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
use crate::telemetry;

/// Default flow timeout in seconds.
const DEFAULT_FLOW_TIMEOUT_SECS: u64 = 60;

/// Internal state for a tracked flow.
#[derive(Debug)]
struct FlowState {
    /// When the first packet of this flow was seen.
    first_seen: Instant,
    /// When the last packet of this flow was seen.
    last_seen: Instant,
    /// Timestamp of the first packet (epoch seconds from pcap).
    first_timestamp: f64,
    /// Total number of packets.
    packet_count: u32,
    /// Total bytes transferred (including headers).
    bytes_count: u64,
    /// Total payload bytes transferred (excluding headers).
    payload_bytes: u64,
    /// Concatenated payload bytes (capped for entropy calculation).
    payload_sample: Vec<u8>,
    /// Individual packet sizes for variance calculation (capped).
    packet_sizes: Vec<u64>,
    /// Inter-arrival times between consecutive packets (milliseconds).
    inter_arrival_times: Vec<f64>,
    /// Whether a TCP FIN was observed.
    fin_seen: bool,
    /// Whether a TCP RST was observed.
    rst_seen: bool,
}

/// Maximum payload sample size for entropy calculation (64 KB).
const MAX_PAYLOAD_SAMPLE: usize = 65_536;

/// Maximum number of individual packet sizes to track for variance calculation.
const MAX_PACKET_SIZES_TRACKED: usize = 1024;

impl FlowState {
    fn new(timestamp: f64) -> Self {
        let now = Instant::now();
        Self {
            first_seen: now,
            last_seen: now,
            first_timestamp: timestamp,
            packet_count: 0,
            bytes_count: 0,
            payload_bytes: 0,
            payload_sample: Vec::with_capacity(4096),
            packet_sizes: Vec::with_capacity(64),
            inter_arrival_times: Vec::with_capacity(64),
            fin_seen: false,
            rst_seen: false,
        }
    }

    /// Update the flow state with a new packet.
    fn update(&mut self, payload_len: u64, payload: Option<&[u8]>) {
        let now = Instant::now();

        // Calculate inter-arrival time
        if self.packet_count > 0 {
            let iat_ms = now.duration_since(self.last_seen).as_secs_f64() * 1000.0;
            self.inter_arrival_times.push(iat_ms);
        }

        self.last_seen = now;
        self.packet_count += 1;
        self.bytes_count += payload_len;

        // Track individual packet sizes for variance calculation
        if self.packet_sizes.len() < MAX_PACKET_SIZES_TRACKED {
            self.packet_sizes.push(payload_len);
        }

        // Collect payload sample for entropy calculation
        if let Some(data) = payload {
            self.payload_bytes += data.len() as u64;
            let remaining = MAX_PAYLOAD_SAMPLE.saturating_sub(self.payload_sample.len());
            if remaining > 0 {
                let take = data.len().min(remaining);
                self.payload_sample.extend_from_slice(&data[..take]);
            }
        }
    }

    /// Calculate the duration of this flow in milliseconds.
    fn duration_ms(&self) -> u64 {
        self.last_seen
            .duration_since(self.first_seen)
            .as_millis() as u64
    }

    /// Calculate the mean inter-arrival time in milliseconds.
    fn iat_mean(&self) -> f64 {
        if self.inter_arrival_times.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.inter_arrival_times.iter().sum();
        sum / self.inter_arrival_times.len() as f64
    }

    /// Calculate the standard deviation of inter-arrival times (milliseconds).
    fn iat_std(&self) -> f64 {
        if self.inter_arrival_times.len() < 2 {
            return 0.0;
        }
        let mean = self.iat_mean();
        let variance: f64 = self
            .inter_arrival_times
            .iter()
            .map(|&t| (t - mean).powi(2))
            .sum::<f64>()
            / (self.inter_arrival_times.len() as f64 - 1.0);
        variance.sqrt()
    }

    /// Calculate the variance of packet sizes (bytes²).
    fn pkt_size_variance(&self) -> f64 {
        if self.packet_sizes.len() < 2 {
            return 0.0;
        }
        let mean = self.packet_sizes.iter().sum::<u64>() as f64 / self.packet_sizes.len() as f64;
        let variance: f64 = self
            .packet_sizes
            .iter()
            .map(|&s| (s as f64 - mean).powi(2))
            .sum::<f64>()
            / (self.packet_sizes.len() as f64 - 1.0);
        variance
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
        let entropy = telemetry::shannon_entropy(&self.payload_sample);

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

        entry.update(payload_len, payload);

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
