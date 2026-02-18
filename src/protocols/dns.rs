use crate::report::{AiHint, Context, Report, Telemetry};
use crate::telemetry::shannon_entropy;

pub fn analyze_dns(payload: &[u8]) -> Option<Report> {
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
        let mut context = Context::default();
        context.fields.insert("protocol".to_string(), "dns".to_string());
        context.fields.insert("domain".to_string(), full_domain);

        let telemetry = Telemetry {
            entropy: Some((entropy * 100.0).round() / 100.0),
            jitter: None,
            ja3: None,
        };

        let ai_hints = vec![AiHint {
            trigger: "high_entropy".to_string(),
            suspected_techniques: vec!["T1071.004".to_string()],
            logic: "Domain appears algorithmic or encoded (DNS tunneling)".to_string(),
        }];

        Some(Report::new(context, telemetry, ai_hints))
    } else {
        None
    }
}
