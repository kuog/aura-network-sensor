//! Unified alert type shared across all pipeline stages.
//!
//! [`MitreAlert`] is the canonical output of Stage 2 (Analysis) and the input
//! to Stage 3 (Export). It is JSON-serializable and contains all the context
//! needed for console output, SQLite persistence, and future cloud/Telegram
//! delivery.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Report fields that explain a detection, most specific first.
const REPORT_REASONS: &[&str] = &["trigger_reason", "message", "reason", "anomaly_type"];
/// Report fields the alert already carries elsewhere.
const REPORT_SKIP: &[&str] = &["technique_id", "severity", "confidence_score"];

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
    /// Debug-level: suppressed or near-zero confidence detections.
    /// Used when reputation/protocol checks reduce confidence below 30.
    Debug,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Debug => write!(f, "DEBUG"),
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

    /// The JSON report some detectors (scan, ARP, DNS, SMB) store in `logic`.
    pub fn logic_report(&self) -> Option<Map<String, Value>> {
        match serde_json::from_str(&self.logic) {
            Ok(Value::Object(report)) => Some(report),
            _ => None,
        }
    }

    /// `logic` as readable text: a JSON report becomes its explanation
    /// followed by its scalar fields as `key=value`.
    pub fn logic_text(&self) -> String {
        let Some(report) = self.logic_report() else {
            return self.logic.clone();
        };
        let reason_key = REPORT_REASONS.iter().copied().find(|k| report.get(*k).is_some_and(Value::is_string));
        let reason = reason_key
            .and_then(|k| report[k].as_str())
            .or_else(|| report.get("ai_hints")?.get(0)?.get("logic")?.as_str());

        let mut fields = Vec::new();
        collect_report_fields(&report, reason_key, 0, &mut fields);
        match reason {
            Some(reason) if fields.is_empty() => reason.to_string(),
            Some(reason) => format!("{reason} ({})", fields.join(" ")),
            None => fields.join(" "),
        }
    }
}

/// Scalar fields of a report, nested objects up to two levels deep.
fn collect_report_fields(map: &Map<String, Value>, skip: Option<&str>, depth: usize, out: &mut Vec<String>) {
    for (key, value) in map {
        if Some(key.as_str()) == skip || REPORT_SKIP.contains(&key.as_str()) {
            continue;
        }
        match value {
            Value::Object(inner) if depth < 2 => collect_report_fields(inner, skip, depth + 1, out),
            Value::String(s) if s.contains(char::is_whitespace) => out.push(format!("{key}=\"{s}\"")),
            Value::String(s) if !s.is_empty() => out.push(format!("{key}={s}")),
            Value::Number(n) => out.push(format!("{key}={n}")),
            Value::Bool(b) => out.push(format!("{key}={b}")),
            _ => {} // arrays, nulls, empty strings, deeper objects
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_logic(logic: &str) -> MitreAlert {
        MitreAlert::new("T1046", "Network Service Discovery", Severity::Low, 30,
                        "10.0.0.1", "10.0.0.2", 1, 2, "tcp", "port_scan", logic)
    }

    #[test]
    fn plain_logic_stays_as_is() {
        assert_eq!(with_logic("HTTP anomaly detected").logic_text(), "HTTP anomaly detected");
        assert!(with_logic("HTTP anomaly detected").logic_report().is_none());
    }

    #[test]
    fn json_reports_become_readable() {
        let scan = with_logic(r#"{"scanner_ip":"10.0.0.1","unique_targets_count":1,"unique_ports_count":21,"technique_id":"T1046","trigger_reason":"Vertical Scan: 21 ports on 10.0.0.2"}"#);
        assert_eq!(
            scan.logic_text(),
            "Vertical Scan: 21 ports on 10.0.0.2 (scanner_ip=10.0.0.1 unique_ports_count=21 unique_targets_count=1)"
        );

        let dns = with_logic(r#"{"severity":"LOW","context":{"fields":{"domain":"x7f3.example","protocol":"dns"}},"telemetry":{"entropy":5.3},"ai_hints":[{"trigger":"high_entropy","suspected_techniques":["T1071.004"],"logic":"Domain appears algorithmic"}]}"#);
        assert_eq!(dns.logic_text(), "Domain appears algorithmic (domain=x7f3.example protocol=dns entropy=5.3)");
    }
}
