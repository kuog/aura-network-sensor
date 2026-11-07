// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Process attribution for TCP connections, plus detection of TCP sockets
 * redirected onto a process's stdin/stdout/stderr (classic reverse shells:
 * `bash -i >& /dev/tcp/...`, `nc -e`, python with os.dup2).
 *
 * Events reach userspace through the `events` ring buffer. Only sockets in
 * the sensor's network namespace are reported: the kernel may be shared with
 * other machines and containers (OrbStack, Docker), whose traffic never
 * shows up on the sensor's interface anyway.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define S_IFMT 00170000
#define S_IFSOCK 0140000

/* Set by userspace before load. */
const volatile __u32 target_netns_ino = 0; /* 0: report every namespace */
const volatile __u64 pidns_dev = 0;
const volatile __u64 pidns_ino = 0;
const volatile __u32 self_tgid = 0; /* the sensor itself, in its pid namespace */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

/* Export the event layout to the Rust skeleton. */
struct mcp_proc_event _mcp_proc_event_btf = {};

/*
 * vmlinux.h generated without CONFIG_NET_NS has an empty `possible_net_t`,
 * which hides `skc_net.net`. Describe the field locally; CO-RE matches it by
 * name against the running kernel's BTF.
 */
struct sock_common___netns {
	struct {
		struct net *net;
	} skc_net;
} __attribute__((preserve_access_index));

static __always_inline __u32 sk_netns_ino(struct sock *sk)
{
	/* __sk_common is the first member of struct sock. */
	struct sock_common___netns *skc = (void *)sk;
	struct net *net = BPF_CORE_READ(skc, skc_net.net);

	return net ? BPF_CORE_READ(net, ns.inum) : 0;
}

static __always_inline void fill_task(struct mcp_proc_event *e)
{
	struct bpf_pidns_info ns = {};
	__u64 id = bpf_get_current_pid_tgid();
	__u64 ugid = bpf_get_current_uid_gid();

	e->pid = id >> 32;
	e->tid = (__u32)id;
	/* /proc lookups in userspace need pids of the sensor's own namespace. */
	if (pidns_ino &&
	    !bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &ns, sizeof(ns))) {
		e->pid = ns.tgid;
		e->tid = ns.pid;
		e->pid_in_ns = 1;
	}
	e->uid = (__u32)ugid;
	e->gid = ugid >> 32;
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->ts_ns = bpf_ktime_get_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline int emit_sock_event(struct sock *sk, __u32 kind, __u8 fd)
{
	if (!sk)
		return 0;
	if (target_netns_ino && sk_netns_ino(sk) != target_netns_ino)
		return 0;

	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	struct mcp_proc_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));

	fill_task(e);
	if (self_tgid && e->pid_in_ns && e->pid == self_tgid) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	e->kind = kind;
	e->fd = fd;
	e->family = family;
	e->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (family == AF_INET) {
		__u32 laddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__u32 raddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

		__builtin_memcpy(e->laddr, &laddr, 4);
		__builtin_memcpy(e->raddr, &raddr, 4);
	} else {
		BPF_CORE_READ_INTO(&e->laddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&e->raddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Runs inside connect(), in the caller's context, once the local port is set. */
SEC("kprobe/tcp_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk)
{
	return emit_sock_event(sk, MCP_EV_CONNECT, 0);
}

/* Returns the accepted connection, in the context of the accepting process. */
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(handle_inet_csk_accept, struct sock *sk)
{
	return emit_sock_event(sk, MCP_EV_ACCEPT, 0);
}

static __always_inline int handle_dup(unsigned int oldfd, unsigned int newfd)
{
	if (newfd > 2 || oldfd == newfd)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	if (!fdt || oldfd >= BPF_CORE_READ(fdt, max_fds))
		return 0;

	struct file **fds = BPF_CORE_READ(fdt, fd);
	struct file *file = NULL;
	if (bpf_probe_read_kernel(&file, sizeof(file), &fds[oldfd]) || !file)
		return 0;

	umode_t mode = BPF_CORE_READ(file, f_inode, i_mode);
	if ((mode & S_IFMT) != S_IFSOCK)
		return 0;

	struct socket *sock = BPF_CORE_READ(file, private_data);
	if (!sock || BPF_CORE_READ(sock, type) != SOCK_STREAM)
		return 0;

	return emit_sock_event(BPF_CORE_READ(sock, sk), MCP_EV_STDIO_SOCKET, newfd);
}

SEC("ksyscall/dup3")
int BPF_KSYSCALL(handle_dup3, unsigned int oldfd, unsigned int newfd, int flags)
{
	return handle_dup(oldfd, newfd);
}

/* dup2(2) is a separate syscall only on some architectures (x86_64 has it,
 * arm64 does not); userspace disables this program where it is missing. */
SEC("ksyscall/dup2")
int BPF_KSYSCALL(handle_dup2, unsigned int oldfd, unsigned int newfd)
{
	return handle_dup(oldfd, newfd);
}
