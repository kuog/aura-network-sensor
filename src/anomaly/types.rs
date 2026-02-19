//! Shared types for the anomaly detection module.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Unique key identifying a network flow (5-tuple).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl std::fmt::Display for FlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} → {}:{} [{}]",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol
        )
    }
}

/// Transport protocol identifier.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Other(n) => write!(f, "proto_{}", n),
        }
    }
}

impl Protocol {
    /// Convert from IP protocol number.
    pub fn from_ip_proto(proto: u8) -> Self {
        match proto {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            n => Protocol::Other(n),
        }
    }
}

/// Extracted feature metrics for a completed network flow.
///
/// These are the features fed into the Isolation Forest model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowMetrics {
    /// Timestamp when the flow started (seconds since epoch).
    pub timestamp: f64,
    /// Source IP address.
    pub src_ip: IpAddr,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Transport protocol.
    pub protocol: Protocol,
    /// Shannon entropy of the payload bytes (0.0–8.0).
    pub entropy: f64,
    /// Total flow duration in milliseconds.
    pub duration_ms: u64,
    /// Total number of packets in the flow.
    pub packet_count: u32,
    /// Total bytes transferred.
    pub bytes_count: u64,
    /// Mean inter-arrival time between packets (milliseconds).
    pub iat_mean: f64,
}

impl FlowMetrics {
    /// Convert to a feature vector for the Isolation Forest.
    ///
    /// Features (6-dimensional):
    /// 0. entropy
    /// 1. log2(duration_ms + 1)
    /// 2. log2(packet_count)
    /// 3. log2(bytes_count + 1)
    /// 4. log2(iat_mean + 1)
    /// 5. dst_port (normalized: port / 65535)
    pub fn to_feature_vector(&self) -> [f64; 6] {
        [
            self.entropy,
            (self.duration_ms as f64 + 1.0).log2(),
            (self.packet_count as f64).max(1.0).log2(),
            (self.bytes_count as f64 + 1.0).log2(),
            (self.iat_mean + 1.0).log2(),
            self.dst_port as f64 / 65535.0,
        ]
    }

    /// Number of features in the feature vector.
    pub const FEATURE_COUNT: usize = 6;
}

/// Result of anomaly detection for a single flow.
#[derive(Debug, Clone)]
pub struct AnomalyResult {
    /// Anomaly score from the Isolation Forest (0.0 = normal, 1.0 = anomalous).
    /// Values > 0.5 are considered anomalous.
    pub anomaly_score: f64,
    /// Whether this flow is classified as normal (score < threshold).
    pub is_normal: bool,
    /// Confidence that this classification is correct (0.0–1.0).
    pub confidence: f64,
}

/// Current operational phase of the anomaly detection system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorPhase {
    /// Collecting baseline data, not yet making predictions.
    Learning,
    /// Model is being trained (transitional state).
    Training,
    /// Model is trained and actively scoring flows.
    Inference,
}

impl std::fmt::Display for DetectorPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectorPhase::Learning => write!(f, "LEARNING"),
            DetectorPhase::Training => write!(f, "TRAINING"),
            DetectorPhase::Inference => write!(f, "INFERENCE"),
        }
    }
}
