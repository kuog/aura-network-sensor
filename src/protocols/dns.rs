use serde::Serialize;
use crate::telemetry::shannon_entropy;

#[derive(Serialize)]
pub struct DnsTunnelReport {
    pub technique: &'static str,
    pub domain: String,
    pub entropy: f64,
}

pub fn analyze_dns(payload: &[u8]) -> Option<DnsTunnelReport> {
    if payload.len() < 12 { return None; }

    // DNS wire format: [len]label[len]label...
    let mut domain_parts = Vec::new();
    let mut pos = 12;

    while pos < payload.len() && payload[pos] != 0 {
        let len = payload[pos] as usize;
        pos += 1;
        if pos + len <= payload.len() {
            let part = &payload[pos..pos + len];
            domain_parts.push(String::from_utf8_lossy(part).to_string());
            pos += len;
        } else { break; }
    }

    let full_domain = domain_parts.join(".");
    if full_domain.is_empty() { return None; }

    // Filter out legit noisy traffic
    let whitelist = ["microsoft.com", "office.net", "windows.com", "akamai", "google"];
    if whitelist.iter().any(|&domain| full_domain.contains(domain)) {
        return None;
    }

    let entropy = shannon_entropy(full_domain.as_bytes());

    // Tunneling usually has very high entropy (> 5.0) and weird subdomains
    if entropy > 5.2 { 
        Some(DnsTunnelReport {
            technique: "T1071.004 (DNS Tunneling)",
            domain: full_domain,
            entropy: (entropy * 100.0).round() / 100.0,
        })
    } else {
        None
    }
}