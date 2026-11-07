/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Types shared by the BPF programs and userspace. The Rust side does not
 * mirror them by hand: each program declares a dummy global of every type it
 * shares, so libbpf-cargo exports the exact layouts into the skeleton.
 */
#ifndef MCP_SENSOR_COMMON_H
#define MCP_SENSOR_COMMON_H

#define COMM_LEN 16

/* ── procmon ─────────────────────────────────────────────────────────── */

enum mcp_proc_event_kind {
	MCP_EV_CONNECT = 1,      /* outbound TCP connect() */
	MCP_EV_ACCEPT = 2,       /* inbound TCP connection accepted */
	MCP_EV_STDIO_SOCKET = 3, /* TCP socket dup'ed onto fd 0, 1 or 2 */
};

struct mcp_proc_event {
	__u64 ts_ns;     /* bpf_ktime_get_ns() */
	__u64 cgroup_id;
	__u32 kind;      /* enum mcp_proc_event_kind */
	__u32 pid;       /* tgid: in the sensor's pid namespace if pid_in_ns, else global */
	__u32 tid;
	__u32 uid;
	__u32 gid;
	__u16 family;    /* AF_INET or AF_INET6 */
	__u16 lport;     /* host byte order */
	__u16 rport;     /* host byte order */
	__u8 pid_in_ns;
	__u8 fd;         /* target fd of MCP_EV_STDIO_SOCKET */
	__u8 laddr[16];  /* IPv4 uses the first 4 bytes */
	__u8 raddr[16];
	char comm[COMM_LEN];
};

/* ── flowfilter ──────────────────────────────────────────────────────── */

/* Directional 5-tuple, hashed byte-wise: keep padding explicit and zeroed. */
struct mcp_flow_key {
	__u8 saddr[16];  /* IPv4 uses the first 4 bytes */
	__u8 daddr[16];
	__u16 sport;     /* host byte order */
	__u16 dport;
	__u8 proto;      /* IPPROTO_TCP or IPPROTO_UDP */
	__u8 family;     /* 4 or 6 */
	__u8 pad[2];
};

struct mcp_flow_stats {
	__u64 first_ns;      /* bpf_ktime_get_ns() of the first frame */
	__u64 last_ns;       /* ... of the latest frame */
	__u64 packets;       /* frames, as the capture socket sees them */
	__u64 bytes;         /* frame bytes */
	__u64 payload_bytes; /* L4 payload bytes */
	__u64 size_sq_sum;   /* sum of squared frame sizes */
	__u64 iat_sum_us;    /* sum of inter-arrival times, microseconds */
	__u64 iat_sq_sum;    /* sum of (iat_us / 16)^2, scaled to avoid overflow */
	__u32 tcp_flags;     /* OR of every TCP flag byte seen */
	__u32 delivered;     /* payload bytes passed up to userspace */
};

#define IAT_SQ_SHIFT 4

#endif /* MCP_SENSOR_COMMON_H */
