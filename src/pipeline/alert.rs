//! Unified alert type shared across all pipeline stages.
//!
//! [`MitreAlert`] is the canonical output of Stage 2 (Analysis) and the input
//! to Stage 3 (Export). It is JSON-serializable and contains all the context
//! needed for console output, SQLite persistence, and future cloud/Telegram
//! delivery.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single detection event produced by the MITRE analysis engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreAlert {
    /// ISO-8601 timestamp of when the alert was generated.
    pub timestamp: DateTime<Utc>,

    /// MITRE ATT&CK technique ID (e.g. "T1071.004").
    pub technique_id: String,

    /// Human-readable technique name (e.g. "DNS Tunneling").
    pub technique_name: String,

    /// Severity level: "LOW", "MEDIUM", "HIGH", "CRITICAL".
    pub severity: Severity,

    /// Confidence that this is a true positive (0–100).
    pub confidence: u8,

    /// Source IP address (as string to support both v4 and v6).
    pub src_ip: String,

    /// Destination IP address.
    pub dst_ip: String,

    /// Source port (0 for non-TCP/UDP).
    pub src_port: u16,

    /// Destination port (0 for non-TCP/UDP).
    pub dst_port: u16,

    /// Transport protocol: "tcp", "udp", "icmp", "arp", etc.
    pub protocol: String,

    /// The trigger that caused this alert (e.g. "high_entropy", "beaconing").
    pub trigger: String,

    /// Human-readable explanation of the detection logic.
    pub logic: String,

    /// Optional enrichment / telemetry fields.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

/// Alert severity levels, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl MitreAlert {
    /// Create a new alert with the minimum required fields.
    pub fn new(
        technique_id: impl Into<String>,
        technique_name: impl Into<String>,
        severity: Severity,
        confidence: u8,
        src_ip: impl Into<String>,
        dst_ip: impl Into<String>,
        src_port: u16,
        dst_port: u16,
        protocol: impl Into<String>,
        trigger: impl Into<String>,
        logic: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            technique_id: technique_id.into(),
            technique_name: technique_name.into(),
            severity,
            confidence: confidence.min(100),
            src_ip: src_ip.into(),
            dst_ip: dst_ip.into(),
            src_port,
            dst_port,
            protocol: protocol.into(),
            trigger: trigger.into(),
            logic: logic.into(),
            metadata: BTreeMap::new(),
        }
    }

    /// Add a metadata key-value pair (builder pattern).
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Serialize to pretty-printed JSON.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e))
    }
}
