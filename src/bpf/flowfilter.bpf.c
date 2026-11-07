// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Flow accounting socket filter, attached to the sensor's pcap socket.
 *
 * Every frame updates per-flow counters in the `flows` LRU map, so flow
 * features stay exact even when userspace cannot keep up. The return value
 * is the snaplen: a flow's frames reach userspace only while the flow is in
 * its DPI window (the first `dpi_limit` payload bytes per direction); after
 * that they are only counted. Non-IP frames (ARP), DNS, TCP SYNs, IP
 * fragments and IPv6 extension chains always pass through whole.
 *
 * A socket filter only decides what this socket captures: it cannot affect
 * the traffic itself, and it goes away with the socket.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04

/* Payload bytes per flow direction passed up to userspace (set at load). */
const volatile __u32 dpi_limit = 16384;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 131072);
	__type(key, struct mcp_flow_key);
	__type(value, struct mcp_flow_stats);
} flows SEC(".maps");

/* Export the key/value layouts to the Rust skeleton. */
struct mcp_flow_key _mcp_flow_key_btf = {};
struct mcp_flow_stats _mcp_flow_stats_btf = {};

static __always_inline int is_dns_port(__u16 port)
{
	return port == 53 || port == 5353;
}

SEC("socket")
int flow_filter(struct __sk_buff *skb)
{
	__u32 len = skb->len;
	__u32 off = ETH_HLEN;
	__u16 eth_proto;

	if (bpf_skb_load_bytes(skb, 12, &eth_proto, sizeof(eth_proto)) < 0)
		return len;
	eth_proto = bpf_ntohs(eth_proto);

	/* Up to two in-band VLAN tags; offloaded tags are not in the data. */
#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (eth_proto != ETH_P_8021Q && eth_proto != ETH_P_8021AD)
			break;
		if (bpf_skb_load_bytes(skb, off + 2, &eth_proto, sizeof(eth_proto)) < 0)
			return len;
		eth_proto = bpf_ntohs(eth_proto);
		off += 4;
	}

	struct mcp_flow_key key = {};
	__u32 l4_off, ip_payload;

	if (eth_proto == ETH_P_IP) {
		struct iphdr iph;

		if (bpf_skb_load_bytes(skb, off, &iph, sizeof(iph)) < 0)
			return len;
		if (iph.ihl < 5)
			return len;
		/* Fragments are reassembled in userspace: deliver, don't account. */
		if (bpf_ntohs(iph.frag_off) & (IP_MF | IP_OFFSET))
			return len;
		if (iph.protocol != IPPROTO_TCP && iph.protocol != IPPROTO_UDP)
			return len;

		__u32 ihl = iph.ihl * 4;
		__u32 tot = bpf_ntohs(iph.tot_len);
		if (tot < ihl)
			return len;

		key.family = 4;
		key.proto = iph.protocol;
		__builtin_memcpy(key.saddr, &iph.saddr, 4);
		__builtin_memcpy(key.daddr, &iph.daddr, 4);
		l4_off = off + ihl;
		/* From the IP length, not skb->len: short frames carry padding. */
		ip_payload = tot - ihl;
	} else if (eth_proto == ETH_P_IPV6) {
		struct ipv6hdr ip6;

		if (bpf_skb_load_bytes(skb, off, &ip6, sizeof(ip6)) < 0)
			return len;
		if (ip6.nexthdr != IPPROTO_TCP && ip6.nexthdr != IPPROTO_UDP)
			return len;

		key.family = 6;
		key.proto = ip6.nexthdr;
		__builtin_memcpy(key.saddr, &ip6.saddr, 16);
		__builtin_memcpy(key.daddr, &ip6.daddr, 16);
		l4_off = off + sizeof(ip6);
		ip_payload = bpf_ntohs(ip6.payload_len);
	} else {
		return len; /* ARP and other non-IP frames */
	}

	__u32 tcp_flags = 0, payload_len;

	if (key.proto == IPPROTO_TCP) {
		struct tcphdr th;

		if (bpf_skb_load_bytes(skb, l4_off, &th, sizeof(th)) < 0)
			return len;
		__u32 doff = th.doff * 4;
		if (doff < sizeof(th) || ip_payload < doff)
			return len;
		payload_len = ip_payload - doff;
		key.sport = bpf_ntohs(th.source);
		key.dport = bpf_ntohs(th.dest);
		tcp_flags = ((__u8 *)&th)[13];
	} else {
		struct udphdr uh;

		if (bpf_skb_load_bytes(skb, l4_off, &uh, sizeof(uh)) < 0)
			return len;
		if (ip_payload < sizeof(uh))
			return len;
		payload_len = ip_payload - sizeof(uh);
		key.sport = bpf_ntohs(uh.source);
		key.dport = bpf_ntohs(uh.dest);
	}

	__u64 now = bpf_ktime_get_ns();
	struct mcp_flow_stats *st = bpf_map_lookup_elem(&flows, &key);

	/* A handshake on a tuple whose previous connection has ended starts a
	 * fresh flow, with a fresh DPI window. */
	if (st && (tcp_flags & TCP_FLAG_SYN) &&
	    (st->tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST))) {
		bpf_map_delete_elem(&flows, &key);
		st = NULL;
	}
	if (!st) {
		struct mcp_flow_stats fresh = {};

		fresh.first_ns = now;
		fresh.last_ns = now;
		bpf_map_update_elem(&flows, &key, &fresh, BPF_NOEXIST);
		st = bpf_map_lookup_elem(&flows, &key);
		if (!st)
			return len;
	}

	/* One inter-arrival sample per frame after the first, clamped at zero
	 * like the userspace tracker does for reordered timestamps. */
	if (st->packets > 0) {
		__u64 last = st->last_ns;
		__u64 iat_us = now > last ? (now - last) / 1000 : 0;
		__u64 scaled = iat_us >> IAT_SQ_SHIFT;

		__sync_fetch_and_add(&st->iat_sum_us, iat_us);
		__sync_fetch_and_add(&st->iat_sq_sum, scaled * scaled);
	}
	if (now > st->last_ns)
		st->last_ns = now;
	__sync_fetch_and_add(&st->packets, 1);
	__sync_fetch_and_add(&st->bytes, len);
	__sync_fetch_and_add(&st->size_sq_sum, (__u64)len * len);
	__sync_fetch_and_add(&st->payload_bytes, payload_len);
	if (tcp_flags)
		st->tcp_flags |= tcp_flags;

	/* Passive DNS and DNS tunneling detection need every message. */
	if (is_dns_port(key.sport) || is_dns_port(key.dport))
		return len;
	/* Connection attempts are cheap and feed the scan detector. */
	if (tcp_flags & TCP_FLAG_SYN)
		return len;
	if (st->delivered < dpi_limit) {
		__sync_fetch_and_add(&st->delivered, payload_len);
		return len;
	}
	return 0;
}
