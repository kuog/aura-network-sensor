use serde::Serialize;
use crate::telemetry::shannon_entropy;

#[derive(Serialize)]
pub struct DnsTunnelReport {
    pub technique: &'static str,
    pub query_sample: String,
    pub entropy: f64,
}

/// Simple detector for DNS Tunneling (T1071.004).
pub fn analyze_dns(payload: &[u8]) -> Option<DnsTunnelReport> {
    if payload.len() < 12 { return None; }
    
    // Naive extraction of DNS Query Name (starts at byte 12)
    let query_bytes = &payload[12..];
    let query_string = String::from_utf8_lossy(query_bytes).to_string();
    let entropy = shannon_entropy(query_string.as_bytes());

    // High entropy in DNS queries is a strong signal for tunneling
    if entropy > 4.2 {
        Some(DnsTunnelReport {
            technique: "T1071.004 (DNS Tunneling)",
            query_sample: query_string.chars().take(50).collect(),
            entropy: (entropy * 100.0).round() / 100.0,
        })
    } else {
        None
    }
}