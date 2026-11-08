//! In-kernel flow accounting (`src/bpf/flowfilter.bpf.c`).
//!
//! The socket filter counts every frame per directional flow in the `flows`
//! LRU map and passes a flow's frames up to userspace only while the flow is
//! inside its DPI window. [`KernelFlowTracker`] turns that map into the same
//! [`FlowMetrics`] the userspace [`FlowTracker`] produces, so the anomaly
//! model sees exact counters even for flows userspace no longer receives.

use std::collections::HashSet;
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Mutex;

use anyhow::{Context, Result};
use dashmap::DashMap;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use log::debug;

use super::skel::flowfilter::{types, FlowfilterSkelBuilder};
use super::{as_bytes, from_bytes, ip_from_bytes, monotonic_now_ns, monotonic_ns_to_epoch};
use crate::anomaly::flow_tracker::{FlowAccounting, FlowTracker};
use crate::anomaly::types::{FlowKey, FlowMetrics, Protocol};
use crate::telemetry::ByteHistogram;

/// Payload bytes per flow direction passed up to userspace (the DPI window).
/// The reassembler inspects at most the first 10 KiB of each direction.
pub const DPI_LIMIT: u32 = 16 * 1024;

/// Payload bytes per flow feeding the entropy feature (as in `FlowTracker`).
const ENTROPY_SAMPLE: usize = 65_536;

/// Idle time after which a flow is complete (as in `FlowTracker`).
const FLOW_TIMEOUT_NS: u64 = 60 * 1_000_000_000;

/// Entries per batched map read.
const LOOKUP_BATCH: u32 = 4096;

const TCP_FIN: u32 = 0x01;
const TCP_RST: u32 = 0x04;

/// Must match `IAT_SQ_SHIFT` in `common.h`.
const IAT_SQ_SHIFT: u32 = 4;

/// The loaded socket filter and the tracker that reads its map.
pub struct FlowFilter {
    /// Program to attach to the capture socket (`SO_ATTACH_BPF`).
    pub program: OwnedFd,
    pub tracker: KernelFlowTracker,
}

/// Load the flow accounting socket filter.
pub fn load() -> Result<FlowFilter> {
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = FlowfilterSkelBuilder::default()
        .open(&mut open_object)
        .context("failed to open the flowfilter BPF object")?;
    if let Some(rodata) = open_skel.maps.rodata_data.as_deref_mut() {
        rodata.dpi_limit = DPI_LIMIT;
    }
    let skel = open_skel.load().context("failed to load flowfilter")?;

    // Owned handles keep the program and the map alive after the skeleton goes.
    let program = skel.progs.flow_filter.as_fd().try_clone_to_owned()?;
    let flows = MapHandle::try_from(&skel.maps.flows)?;
    Ok(FlowFilter { program, tracker: KernelFlowTracker::new(flows) })
}

/// [`FlowAccounting`] backed by the kernel `flows` map.
pub struct KernelFlowTracker {
    flows: MapHandle,
    /// Entropy input: payload delivered to userspace, per directional flow.
    payload: DashMap<FlowKey, ByteHistogram>,
    /// Frames the kernel does not account (non-TCP/UDP, IP fragments) always
    /// reach userspace whole, so the userspace tracker counts them exactly.
    fallback: FlowTracker,
    /// TCP payload totals for the engine's T1041 check.
    tcp_totals: Mutex<TcpTotals>,
}

/// Per-direction TCP payload totals handed to the engine (T1041).
#[derive(Default)]
struct TcpTotals {
    /// Live flows, as of the latest flush.
    live: Vec<(FlowKey, u64)>,
    /// Final totals of flows that ended since the engine last looked. Kept
    /// until taken: a short upload can start and end between two flushes.
    ended: Vec<(FlowKey, u64)>,
    /// A flush happened since the engine last looked.
    fresh: bool,
}

impl KernelFlowTracker {
    fn new(flows: MapHandle) -> Self {
        Self {
            flows,
            payload: DashMap::new(),
            fallback: FlowTracker::new(),
            tcp_totals: Mutex::new(TcpTotals::default()),
        }
    }

    fn read_map(&self) -> Vec<(types::aura_flow_key, types::aura_flow_stats)> {
        let parse = |k: &[u8], v: &[u8]| Some((from_bytes(k)?, from_bytes(v)?));
        match self.flows.lookup_batch(LOOKUP_BATCH, MapFlags::ANY, MapFlags::ANY) {
            Ok(entries) => entries.filter_map(|(k, v)| parse(&k, &v)).collect(),
            Err(e) => {
                debug!("[FlowFilter] batched lookup unavailable ({e}); iterating keys");
                self.flows
                    .keys()
                    .filter_map(|k| {
                        let v = self.flows.lookup(&k, MapFlags::ANY).ok()??;
                        parse(&k, &v)
                    })
                    .collect()
            }
        }
    }

    fn flush(&self, all: bool) -> Vec<FlowMetrics> {
        let now = monotonic_now_ns();
        let mut completed = Vec::new();
        let mut live = HashSet::new();
        let mut live_tcp = Vec::new();
        let mut ended_tcp = Vec::new();

        for (raw_key, stats) in self.read_map() {
            let key = flow_key(&raw_key);
            let idle = now.saturating_sub(stats.last_ns) > FLOW_TIMEOUT_NS;
            let closed = stats.tcp_flags & (TCP_FIN | TCP_RST) != 0;
            let tcp_total = (key.protocol == Protocol::Tcp).then(|| (key.clone(), stats.payload_bytes));

            if all || idle || closed {
                let hist = self.payload.remove(&key).map(|(_, h)| h);
                // Like FlowTracker: single-packet flows are not sessions.
                if stats.packets >= 2 {
                    completed.push(flow_metrics(&key, &stats, hist.as_ref()));
                }
                let _ = self.flows.delete(as_bytes(&raw_key));
                ended_tcp.extend(tcp_total);
            } else {
                live_tcp.extend(tcp_total);
                live.insert(key);
            }
        }

        // Drop entropy samples of flows the kernel LRU evicted on its own.
        self.payload.retain(|key, _| live.contains(key));

        let mut totals = self.tcp_totals.lock().unwrap_or_else(|e| e.into_inner());
        totals.live = live_tcp;
        totals.ended.extend(ended_tcp);
        totals.fresh = true;
        drop(totals);

        completed.extend(if all {
            self.fallback.flush_all()
        } else {
            self.fallback.flush_completed()
        });
        completed
    }
}

impl FlowAccounting for KernelFlowTracker {
    fn record_packet(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
        payload_len: u64,
        payload: Option<&[u8]>,
        timestamp: f64,
        tcp_fin: bool,
        tcp_rst: bool,
    ) -> bool {
        if !matches!(protocol, Protocol::Tcp | Protocol::Udp) {
            return self.fallback.record_packet(
                src_ip, dst_ip, src_port, dst_port, protocol, payload_len, payload, timestamp,
                tcp_fin, tcp_rst,
            );
        }
        // Counters live in the kernel; userspace only samples payload bytes.
        let Some(data) = payload.filter(|d| !d.is_empty()) else {
            return false;
        };
        let key = FlowKey { src_ip, dst_ip, src_port, dst_port, protocol };
        let mut is_new = false;
        self.payload
            .entry(key)
            .or_insert_with(|| {
                is_new = true;
                ByteHistogram::default()
            })
            .add(data, ENTROPY_SAMPLE);
        is_new
    }

    fn peek_metrics(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    ) -> Option<FlowMetrics> {
        let Some(raw_key) = bpf_key(src_ip, dst_ip, src_port, dst_port, protocol) else {
            return self.fallback.peek_metrics(src_ip, dst_ip, src_port, dst_port, protocol);
        };
        let value = self.flows.lookup(as_bytes(&raw_key), MapFlags::ANY).ok()??;
        let stats: types::aura_flow_stats = from_bytes(&value)?;
        let key = FlowKey { src_ip, dst_ip, src_port, dst_port, protocol };
        let hist = self.payload.get(&key);
        Some(flow_metrics(&key, &stats, hist.as_deref()))
    }

    fn flush_completed(&self) -> Vec<FlowMetrics> {
        self.flush(false)
    }

    fn flush_all(&self) -> Vec<FlowMetrics> {
        self.flush(true)
    }

    fn active_count(&self) -> usize {
        // Flows with delivered payload; counting map entries would need a full read.
        self.payload.len() + self.fallback.active_count()
    }

    fn take_tcp_payload_totals(&self) -> Option<Vec<(FlowKey, u64)>> {
        let mut totals = self.tcp_totals.lock().unwrap_or_else(|e| e.into_inner());
        if !totals.fresh {
            return None;
        }
        totals.fresh = false;
        let mut snapshot = totals.live.clone();
        snapshot.append(&mut totals.ended);
        Some(snapshot)
    }
}

/// Kernel map key for a flow, if the kernel accounts this protocol.
fn bpf_key(
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: Protocol,
) -> Option<types::aura_flow_key> {
    let proto = match protocol {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
        _ => return None,
    };
    let mut key = types::aura_flow_key { sport: src_port, dport: dst_port, proto, ..Default::default() };
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            key.family = 4;
            key.saddr[..4].copy_from_slice(&s.octets());
            key.daddr[..4].copy_from_slice(&d.octets());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            key.family = 6;
            key.saddr = s.octets();
            key.daddr = d.octets();
        }
        _ => return None,
    }
    Some(key)
}

fn flow_key(raw: &types::aura_flow_key) -> FlowKey {
    let v4 = raw.family == 4;
    FlowKey {
        src_ip: ip_from_bytes(v4, &raw.saddr),
        dst_ip: ip_from_bytes(v4, &raw.daddr),
        src_port: raw.sport,
        dst_port: raw.dport,
        protocol: Protocol::from_ip_proto(raw.proto),
    }
}

/// Same features as `FlowTracker` computes, from the kernel's running sums.
fn flow_metrics(key: &FlowKey, st: &types::aura_flow_stats, hist: Option<&ByteHistogram>) -> FlowMetrics {
    let packets = st.packets as f64;
    let mean_size = if st.packets > 0 { st.bytes as f64 / packets } else { 0.0 };
    let size_variance = if st.packets >= 2 {
        ((st.size_sq_sum as f64 - packets * mean_size * mean_size) / (packets - 1.0)).max(0.0)
    } else {
        0.0
    };

    // One inter-arrival sample per frame after the first.
    let gaps = st.packets.saturating_sub(1) as f64;
    let iat_mean_us = if gaps > 0.0 { st.iat_sum_us as f64 / gaps } else { 0.0 };
    let iat_std_us = if gaps >= 2.0 {
        let sq_sum_us = st.iat_sq_sum as f64 * f64::from(1u32 << (2 * IAT_SQ_SHIFT));
        ((sq_sum_us - gaps * iat_mean_us * iat_mean_us) / (gaps - 1.0)).max(0.0).sqrt()
    } else {
        0.0
    };

    FlowMetrics {
        timestamp: monotonic_ns_to_epoch(st.first_ns),
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        src_port: key.src_port,
        dst_port: key.dst_port,
        protocol: key.protocol,
        entropy: hist.map_or(0.0, ByteHistogram::entropy),
        duration_ms: (st.last_ns.saturating_sub(st.first_ns) + 500_000) / 1_000_000,
        packet_count: u32::try_from(st.packets).unwrap_or(u32::MAX),
        bytes_count: st.bytes,
        iat_mean: iat_mean_us / 1000.0,
        bytes_per_packet: mean_size,
        pkt_size_variance: size_variance,
        iat_std: iat_std_us / 1000.0,
        payload_ratio: if st.bytes > 0 {
            (st.payload_bytes as f64 / st.bytes as f64).min(1.0)
        } else {
            0.0
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key() -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 40000,
            dst_port: 443,
            protocol: Protocol::Tcp,
        }
    }

    #[test]
    fn metrics_from_kernel_sums_match_the_userspace_definitions() {
        // Frames of 100, 110, 120, 130 bytes, gaps of 10, 20, 30 ms.
        let gaps_us = [10_000u64, 20_000, 30_000];
        let stats = types::aura_flow_stats {
            first_ns: 1_000_000_000,
            last_ns: 1_060_000_000,
            packets: 4,
            bytes: 460,
            payload_bytes: 260,
            size_sq_sum: [100u64, 110, 120, 130].iter().map(|s| s * s).sum(),
            iat_sum_us: gaps_us.iter().sum(),
            iat_sq_sum: gaps_us.iter().map(|g| (g >> IAT_SQ_SHIFT).pow(2)).sum(),
            tcp_flags: 0,
            delivered: 0,
        };
        let m = flow_metrics(&key(), &stats, None);
        assert_eq!(m.packet_count, 4);
        assert_eq!(m.duration_ms, 60);
        assert!((m.bytes_per_packet - 115.0).abs() < 1e-9);
        assert!((m.pkt_size_variance - 500.0 / 3.0).abs() < 1e-9);
        assert!((m.iat_mean - 20.0).abs() < 1e-9);
        assert!((m.iat_std - 10.0).abs() < 1e-9);
        assert!((m.payload_ratio - 260.0 / 460.0).abs() < 1e-12);
    }

    #[test]
    fn keys_round_trip() {
        let k = key();
        let raw = bpf_key(k.src_ip, k.dst_ip, k.src_port, k.dst_port, k.protocol).unwrap();
        assert_eq!(raw.family, 4);
        assert_eq!(as_bytes(&raw).len(), 40);
        assert_eq!(flow_key(&raw), k);
        assert!(bpf_key(k.src_ip, k.dst_ip, 0, 0, Protocol::Icmp).is_none());
    }
}
