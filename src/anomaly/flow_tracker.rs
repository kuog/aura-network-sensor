//! Flow Tracker — Aggregates packets into sessions (flows).
//!
//! Uses [`DashMap`] for lock-free concurrent access from the engine thread.
//! A flow is identified by its 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol).
//! Sessions are considered complete when:
//! - A timeout expires (default: 60 seconds since last packet)
//! - A TCP FIN or RST flag is observed

use dashmap::DashMap;
use log::debug;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::types::{FlowKey, FlowMetrics, Protocol};
use crate::telemetry::ByteHistogram;

/// Default flow timeout in seconds.
const DEFAULT_FLOW_TIMEOUT_SECS: u64 = 60;

/// Running mean/variance (Welford) — constant memory, numerically stable.
#[derive(Debug, Default, Clone, Copy)]
struct RunningStats {
    n: u64,
    mean: f64,
    m2: f64,
}

impl RunningStats {
    fn push(&mut self, x: f64) {
        self.n += 1;
        let delta = x - self.mean;
        self.mean += delta / self.n as f64;
        self.m2 += delta * (x - self.mean);
    }

    fn mean(&self) -> f64 {
        if self.n == 0 { 0.0 } else { self.mean }
    }

    /// Sample variance (n − 1 denominator); 0 with fewer than two samples.
    fn sample_variance(&self) -> f64 {
        if self.n < 2 { 0.0 } else { self.m2 / (self.n - 1) as f64 }
    }
}

/// Internal state for a tracked flow.
#[derive(Debug)]
struct FlowState {
    /// Wall-clock time of the last packet — used only for idle timeouts.
    last_seen: Instant,
    /// Capture timestamp of the first packet (epoch seconds).
    first_timestamp: f64,
    /// Latest capture timestamp seen in this flow (epoch seconds).
    last_timestamp: f64,
    /// Total number of packets.
    packet_count: u32,
    /// Total bytes transferred (including headers).
    bytes_count: u64,
    /// Total payload bytes transferred (excluding headers).
    payload_bytes: u64,
    /// Byte histogram of the first `MAX_PAYLOAD_SAMPLE` payload bytes (entropy).
    payload_hist: ByteHistogram,
    /// Packet sizes (bytes), over every packet of the flow.
    sizes: RunningStats,
    /// Inter-arrival times between consecutive packets (milliseconds).
    iats: RunningStats,
    /// Whether a TCP FIN was observed.
    fin_seen: bool,
    /// Whether a TCP RST was observed.
    rst_seen: bool,
}

/// Payload bytes per flow that feed the entropy feature (64 KB).
const MAX_PAYLOAD_SAMPLE: usize = 65_536;

impl FlowState {
    fn new(timestamp: f64) -> Self {
        Self {
            last_seen: Instant::now(),
            first_timestamp: timestamp,
            last_timestamp: timestamp,
            packet_count: 0,
            bytes_count: 0,
            payload_bytes: 0,
            payload_hist: ByteHistogram::default(),
            sizes: RunningStats::default(),
            iats: RunningStats::default(),
            fin_seen: false,
            rst_seen: false,
        }
    }

    /// Update the flow state with a new packet captured at `timestamp`.
    fn update(&mut self, payload_len: u64, payload: Option<&[u8]>, timestamp: f64) {
        // Inter-arrival time from capture timestamps, not processing time, so
        // queueing inside the pipeline does not distort it. Timestamps from
        // different CPUs can be slightly out of order: never go negative.
        if self.packet_count > 0 {
            let iat_ms = ((timestamp - self.last_timestamp) * 1000.0).max(0.0);
            self.iats.push(iat_ms);
        }
        self.last_timestamp = self.last_timestamp.max(timestamp);
        self.last_seen = Instant::now();

        self.packet_count = self.packet_count.saturating_add(1);
        self.bytes_count += payload_len;
        self.sizes.push(payload_len as f64);

        if let Some(data) = payload {
            self.payload_bytes += data.len() as u64;
            self.payload_hist.add(data, MAX_PAYLOAD_SAMPLE);
        }
    }

    /// Duration of this flow in milliseconds (capture time).
    fn duration_ms(&self) -> u64 {
        ((self.last_timestamp - self.first_timestamp) * 1000.0).max(0.0).round() as u64
    }

    /// Mean inter-arrival time in milliseconds.
    fn iat_mean(&self) -> f64 {
        self.iats.mean()
    }

    /// Standard deviation of inter-arrival times (milliseconds).
    fn iat_std(&self) -> f64 {
        self.iats.sample_variance().sqrt()
    }

    /// Variance of packet sizes (bytes²).
    fn pkt_size_variance(&self) -> f64 {
        self.sizes.sample_variance()
    }

    /// Calculate average bytes per packet.
    fn bytes_per_packet(&self) -> f64 {
        if self.packet_count == 0 {
            return 0.0;
        }
        self.bytes_count as f64 / self.packet_count as f64
    }

    /// Calculate payload-to-total-bytes ratio (0.0–1.0).
    fn payload_ratio(&self) -> f64 {
        if self.bytes_count == 0 {
            return 0.0;
        }
        (self.payload_bytes as f64 / self.bytes_count as f64).min(1.0)
    }

    /// Convert to FlowMetrics for persistence and ML inference.
    fn to_metrics(&self, key: &FlowKey) -> FlowMetrics {
        let entropy = self.payload_hist.entropy();

        FlowMetrics {
            timestamp: self.first_timestamp,
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            src_port: key.src_port,
            dst_port: key.dst_port,
            protocol: key.protocol,
            entropy,
            duration_ms: self.duration_ms(),
            packet_count: self.packet_count,
            bytes_count: self.bytes_count,
            iat_mean: self.iat_mean(),
            bytes_per_packet: self.bytes_per_packet(),
            pkt_size_variance: self.pkt_size_variance(),
            iat_std: self.iat_std(),
            payload_ratio: self.payload_ratio(),
        }
    }
}

/// Per-flow accounting behind the anomaly features.
///
/// The engine records packets and peeks at live flows; the anomaly
/// background task flushes completed ones. Implemented in userspace by
/// [`FlowTracker`] and, on Linux with the `ebpf` feature, by an in-kernel
/// tracker that sees every frame while userspace only receives each flow's
/// DPI window.
pub trait FlowAccounting: Send + Sync {
    /// Record a captured packet. Returns `true` if it opened a new flow.
    #[allow(clippy::too_many_arguments)]
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
    ) -> bool;

    /// Current metrics of a live flow, without removing it.
    fn peek_metrics(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    ) -> Option<FlowMetrics>;

    /// Remove and return flows that ended (idle timeout or TCP FIN/RST).
    fn flush_completed(&self) -> Vec<FlowMetrics>;

    /// Remove and return every flow (shutdown).
    fn flush_all(&self) -> Vec<FlowMetrics>;

    /// Number of flows currently tracked.
    fn active_count(&self) -> usize;

    /// Payload byte totals of live TCP flows, per direction, from the latest
    /// flush; taking a snapshot consumes it. `None` when there is no new
    /// snapshot — always, for trackers fed by the packet path, where the
    /// engine counts exfiltration bytes itself.
    fn take_tcp_payload_totals(&self) -> Option<Vec<(FlowKey, u64)>> {
        None
    }
}

impl FlowAccounting for FlowTracker {
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
        FlowTracker::record_packet(
            self, src_ip, dst_ip, src_port, dst_port, protocol, payload_len, payload, timestamp,
            tcp_fin, tcp_rst,
        )
    }

    fn peek_metrics(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    ) -> Option<FlowMetrics> {
        FlowTracker::peek_metrics(self, src_ip, dst_ip, src_port, dst_port, protocol)
    }

    fn flush_completed(&self) -> Vec<FlowMetrics> {
        FlowTracker::flush_completed(self)
    }

    fn flush_all(&self) -> Vec<FlowMetrics> {
        FlowTracker::flush_all(self)
    }

    fn active_count(&self) -> usize {
        FlowTracker::active_count(self)
    }
}

/// Concurrent flow tracker using DashMap for lock-free access.
///
/// Aggregates individual packets into flow sessions identified by 5-tuple.
/// Completed flows (by timeout or TCP FIN/RST) are flushed and returned
/// as [`FlowMetrics`] for persistence and ML inference.
pub struct FlowTracker {
    /// Active flows indexed by 5-tuple.
    flows: DashMap<FlowKey, FlowState>,
    /// Flow timeout duration.
    timeout: Duration,
}

impl FlowTracker {
    /// Create a new FlowTracker with the default timeout.
    pub fn new() -> Self {
        Self {
            flows: DashMap::new(),
            timeout: Duration::from_secs(DEFAULT_FLOW_TIMEOUT_SECS),
        }
    }

    /// Create a new FlowTracker with a custom timeout.
    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self {
            flows: DashMap::new(),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Create a shared (Arc-wrapped) FlowTracker.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Record a packet belonging to a flow.
    ///
    /// # Arguments
    /// * `src_ip` — Source IP address
    /// * `dst_ip` — Destination IP address
    /// * `src_port` — Source port
    /// * `dst_port` — Destination port
    /// * `protocol` — Transport protocol
    /// * `payload_len` — Total packet length in bytes
    /// * `payload` — Optional payload bytes for entropy calculation
    /// * `timestamp` — Packet timestamp (epoch seconds from pcap)
    /// * `tcp_fin` — Whether TCP FIN flag is set
    /// * `tcp_rst` — Whether TCP RST flag is set
    #[allow(clippy::too_many_arguments)]
    pub fn record_packet(
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
        let key = FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        };

        let mut is_new_flow = false;
        let mut entry = self
            .flows
            .entry(key)
            .or_insert_with(|| {
                is_new_flow = true;
                FlowState::new(timestamp)
            });

        entry.update(payload_len, payload, timestamp);

        if tcp_fin {
            entry.fin_seen = true;
        }
        if tcp_rst {
            entry.rst_seen = true;
        }
        
        is_new_flow
    }

    /// Flush all completed flows (timed out or TCP FIN/RST).
    ///
    /// Returns a vector of [`FlowMetrics`] for the completed flows.
    /// This should be called periodically (e.g., every few seconds).
    pub fn flush_completed(&self) -> Vec<FlowMetrics> {
        let now = Instant::now();
        let mut completed = Vec::new();
        let mut keys_to_remove = Vec::new();

        // Identify completed flows
        for entry in self.flows.iter() {
            let key = entry.key();
            let state = entry.value();

            let is_timed_out = now.duration_since(state.last_seen) > self.timeout;
            let is_tcp_closed = state.fin_seen || state.rst_seen;

            if is_timed_out || is_tcp_closed {
                // Only include flows with at least 2 packets (meaningful sessions)
                if state.packet_count >= 2 {
                    completed.push(state.to_metrics(key));
                }
                keys_to_remove.push(key.clone());
            }
        }

        // Remove completed flows
        for key in &keys_to_remove {
            self.flows.remove(key);
        }

        if !completed.is_empty() {
            debug!(
                "[FlowTracker] Flushed {} completed flows ({} active remaining)",
                completed.len(),
                self.flows.len()
            );
        }

        completed
    }

    /// Force-flush all active flows (used during shutdown).
    pub fn flush_all(&self) -> Vec<FlowMetrics> {
        let mut all = Vec::new();

        // Collect all keys first to avoid holding references during removal
        let keys: Vec<FlowKey> = self.flows.iter().map(|e| e.key().clone()).collect();

        for key in keys {
            if let Some((key, state)) = self.flows.remove(&key) {
                if state.packet_count >= 2 {
                    all.push(state.to_metrics(&key));
                }
            }
        }

        if !all.is_empty() {
            debug!("[FlowTracker] Force-flushed {} flows at shutdown", all.len());
        }

        all
    }

    /// Peek at the current metrics for an active flow without removing it.
    ///
    /// Returns `Some(FlowMetrics)` if the flow exists, `None` otherwise.
    /// This is used by the engine to attach real flow data to alerts.
    pub fn peek_metrics(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    ) -> Option<FlowMetrics> {
        let key = FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        };
        self.flows.get(&key).map(|entry| entry.to_metrics(&key))
    }

    /// Number of currently active flows.
    pub fn active_count(&self) -> usize {
        self.flows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::shannon_entropy;
    use std::net::Ipv4Addr;

    const BASE: f64 = 1_700_000_000.0;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn record(t: &FlowTracker, size: u64, payload: &[u8], ts: f64) {
        t.record_packet(ip(1), ip(2), 40000, 443, Protocol::Tcp, size, Some(payload), ts, false, false);
    }

    fn metrics(t: &FlowTracker) -> FlowMetrics {
        t.peek_metrics(ip(1), ip(2), 40000, 443, Protocol::Tcp).expect("flow exists")
    }

    #[test]
    fn timing_comes_from_capture_timestamps() {
        let t = FlowTracker::new();
        // Gaps of 10, 20 and 30 ms, recorded back-to-back in wall-clock time.
        for (size, offset) in [(100, 0.0), (110, 0.010), (120, 0.030), (130, 0.060)] {
            record(&t, size, b"x", BASE + offset);
        }
        let m = metrics(&t);
        assert_eq!(m.packet_count, 4);
        assert_eq!(m.duration_ms, 60);
        assert!((m.timestamp - BASE).abs() < 1e-9);
        assert!((m.iat_mean - 20.0).abs() < 1e-3, "iat_mean = {}", m.iat_mean);
        assert!((m.iat_std - 10.0).abs() < 1e-3, "iat_std = {}", m.iat_std);
        // Sample variance of 100, 110, 120, 130.
        assert!((m.pkt_size_variance - 500.0 / 3.0).abs() < 1e-6);
    }

    #[test]
    fn out_of_order_timestamps_never_give_negative_gaps() {
        let t = FlowTracker::new();
        record(&t, 100, b"x", BASE + 1.0);
        record(&t, 100, b"x", BASE + 0.5); // reordered: gap clamped to 0
        record(&t, 100, b"x", BASE + 2.0); // 1 s after the latest seen
        let m = metrics(&t);
        assert!((m.iat_mean - 500.0).abs() < 1e-3, "iat_mean = {}", m.iat_mean);
        assert_eq!(m.duration_ms, 1000);
    }

    #[test]
    fn entropy_covers_the_first_64k_of_payload() {
        let t = FlowTracker::new();
        let first: Vec<u8> = (0..60_000u32).map(|i| (i % 251) as u8).collect();
        let second = vec![0u8; 20_000];
        record(&t, 1500, &first, BASE);
        record(&t, 1500, &second, BASE + 0.1);

        let mut sample = first.clone();
        sample.extend_from_slice(&second[..MAX_PAYLOAD_SAMPLE - first.len()]);
        let expected = shannon_entropy(&sample);
        assert!((metrics(&t).entropy - expected).abs() < 1e-12);
    }
}
