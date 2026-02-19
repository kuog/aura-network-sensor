//! Alert Enrichment Module
//!
//! Provides TLS SNI extraction, domain reputation lookup, and confidence scoring
//! to reduce false positives from legitimate traffic (e.g., Exchange/O365 beaconing).

use serde::Serialize;
use tls_parser::{
    parse_tls_plaintext, parse_tls_extensions, TlsMessage, TlsMessageHandshake, TlsExtension,
};

// ---------------------------------------------------------------------------
// SNI Parser
// ---------------------------------------------------------------------------

/// Extract the Server Name Indication (SNI) from a TLS Client Hello payload.
///
/// `data` should be the raw TCP payload starting at the TLS record header.
/// Returns `Some(hostname)` if a valid SNI extension is found.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    // Try the tls-parser crate first
    if let Some(sni) = extract_sni_via_parser(data) {
        return Some(sni);
    }
    // Fallback: manual offset parsing for robustness
    extract_sni_manual(data)
}

/// Use `tls-parser` to walk the Client Hello extensions and pull out the SNI.
fn extract_sni_via_parser(data: &[u8]) -> Option<String> {
    let (_, record) = parse_tls_plaintext(data).ok()?;
    for msg in record.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
            let ext_bytes = ch.ext?;
            let (_, exts) = parse_tls_extensions(ext_bytes).ok()?;
            for ext in exts {
                if let TlsExtension::SNI(sni_list) = ext {
                    for (_, name_bytes) in sni_list {
                        if let Ok(name) = std::str::from_utf8(name_bytes) {
                            if !name.is_empty() {
                                return Some(name.to_lowercase());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Manual offset-based SNI extraction.
///
/// Walks the TLS record → Handshake → Client Hello → Extensions to find
/// extension type 0x0000 (server_name).  This handles edge cases where
/// `tls-parser` may fail on unusual but valid packets.
fn extract_sni_manual(data: &[u8]) -> Option<String> {
    // Minimum TLS record header: 5 bytes (type, version, length)
    if data.len() < 5 {
        return None;
    }
    // Content type 22 = Handshake
    if data[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }
    let hs = &data[5..5 + record_len];

    // Handshake type 1 = Client Hello
    if hs.is_empty() || hs[0] != 0x01 {
        return None;
    }
    let hs_len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
    if hs.len() < 4 + hs_len {
        return None;
    }
    let ch = &hs[4..4 + hs_len];

    // Skip: version(2) + random(32) = 34
    if ch.len() < 34 {
        return None;
    }
    let mut pos = 34;

    // Session ID length (1 byte) + session ID
    if pos >= ch.len() {
        return None;
    }
    let sid_len = ch[pos] as usize;
    pos += 1 + sid_len;

    // Cipher suites length (2 bytes) + cipher suites
    if pos + 2 > ch.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // Compression methods length (1 byte) + methods
    if pos >= ch.len() {
        return None;
    }
    let cm_len = ch[pos] as usize;
    pos += 1 + cm_len;

    // Extensions length (2 bytes)
    if pos + 2 > ch.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_total;
    if ext_end > ch.len() {
        return None;
    }

    // Walk extensions
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let ext_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }

        // Extension type 0 = server_name
        if ext_type == 0x0000 && ext_len >= 5 {
            let sni_data = &ch[pos..pos + ext_len];
            // server_name_list_length (2) + host_name type (1) + host_name_length (2)
            let _list_len = u16::from_be_bytes([sni_data[0], sni_data[1]]);
            let name_type = sni_data[2]; // 0 = host_name
            if name_type == 0 {
                let name_len = u16::from_be_bytes([sni_data[3], sni_data[4]]) as usize;
                if 5 + name_len <= sni_data.len() {
                    if let Ok(name) = std::str::from_utf8(&sni_data[5..5 + name_len]) {
                        if !name.is_empty() {
                            return Some(name.to_lowercase());
                        }
                    }
                }
            }
        }
        pos += ext_len;
    }
    None
}

// ---------------------------------------------------------------------------
// Domain Reputation / Known-Safe List
// ---------------------------------------------------------------------------

/// Known-safe domain suffixes.  Traffic destined for these domains is very
/// likely legitimate and should have its confidence score reduced.
const SAFE_DOMAIN_SUFFIXES: &[&str] = &[
    // Microsoft / Office 365 / Azure
    ".microsoft.com",
    ".office365.com",
    ".office.com",
    ".outlook.com",
    ".live.com",
    ".azure.com",
    ".azure.net",
    ".windows.net",
    ".microsoftonline.com",
    ".sharepoint.com",
    ".onedrive.com",
    ".teams.microsoft.com",
    // Google
    ".google.com",
    ".googleapis.com",
    ".gstatic.com",
    ".youtube.com",
    ".googlevideo.com",
    ".google-analytics.com",
    // Amazon / AWS
    ".amazonaws.com",
    ".amazon.com",
    ".cloudfront.net",
    ".awsstatic.com",
    // Cloudflare
    ".cloudflare.com",
    ".cloudflare-dns.com",
    // Akamai
    ".akamai.net",
    ".akamaized.net",
    ".akamaiedge.net",
    // Fastly
    ".fastly.net",
    ".fastlylb.net",
    // Apple
    ".apple.com",
    ".icloud.com",
    ".cdn-apple.com",
    // GitHub
    ".github.com",
    ".github.io",
    ".githubusercontent.com",
    // Generic CDN / Cloud
    ".azureedge.net",
    ".trafficmanager.net",
    ".edgecastcdn.net",
];

/// CDN / Cloud provider suffixes used specifically for Rule C (beaconing
/// to known infrastructure).
const CDN_CLOUD_SUFFIXES: &[&str] = &[
    ".cloudfront.net",
    ".amazonaws.com",
    ".azure.com",
    ".azure.net",
    ".windows.net",
    ".azureedge.net",
    ".akamai.net",
    ".akamaized.net",
    ".akamaiedge.net",
    ".fastly.net",
    ".fastlylb.net",
    ".cloudflare.com",
    ".cloudflare-dns.com",
    ".googleapis.com",
    ".googlevideo.com",
    ".cdn-apple.com",
    ".edgecastcdn.net",
    ".trafficmanager.net",
    ".office365.com",
    ".office.com",
    ".outlook.com",
    ".microsoftonline.com",
    ".sharepoint.com",
];

/// Returns `true` if `domain` matches any of the known-safe suffixes.
pub fn is_safe_domain(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    SAFE_DOMAIN_SUFFIXES.iter().any(|suffix| {
        lower.ends_with(suffix) || lower == suffix.trim_start_matches('.')
    })
}

/// Returns `true` if `domain` belongs to a known CDN / Cloud provider.
pub fn is_cdn_cloud_provider(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    CDN_CLOUD_SUFFIXES.iter().any(|suffix| {
        lower.ends_with(suffix) || lower == suffix.trim_start_matches('.')
    })
}

/// Try to identify the provider name from the domain for enriched context.
pub fn identify_provider(domain: &str) -> Option<String> {
    let lower = domain.to_lowercase();
    if lower.contains("microsoft") || lower.contains("office365") || lower.contains("office.com")
        || lower.contains("outlook") || lower.contains("azure") || lower.contains("windows.net")
        || lower.contains("sharepoint") || lower.contains("onedrive") || lower.contains("live.com")
        || lower.contains("microsoftonline")
    {
        return Some("Microsoft".to_string());
    }
    if lower.contains("google") || lower.contains("gstatic") || lower.contains("youtube")
        || lower.contains("googlevideo")
    {
        return Some("Google".to_string());
    }
    if lower.contains("amazon") || lower.contains("cloudfront") || lower.contains("awsstatic") {
        return Some("Amazon/AWS".to_string());
    }
    if lower.contains("cloudflare") {
        return Some("Cloudflare".to_string());
    }
    if lower.contains("akamai") {
        return Some("Akamai".to_string());
    }
    if lower.contains("fastly") {
        return Some("Fastly".to_string());
    }
    if lower.contains("apple") || lower.contains("icloud") {
        return Some("Apple".to_string());
    }
    if lower.contains("github") {
        return Some("GitHub".to_string());
    }
    None
}

// ---------------------------------------------------------------------------
// Confidence Scoring
// ---------------------------------------------------------------------------

/// Input parameters for the confidence scoring engine.
pub struct ScoringInput<'a> {
    /// Raw TLS payload (TCP application data) – used for SNI extraction.
    pub tls_payload: &'a [u8],
    /// Destination port of the flow.
    pub dst_port: u16,
    /// Whether the flow was flagged as beaconing (periodic timing).
    pub is_beaconing: bool,
    /// The full session data buffer – used for raw pattern matching.
    pub session_data: &'a [u8],
}

/// Result of the enrichment / scoring pipeline.
#[derive(Debug, Clone, Serialize)]
pub struct EnrichmentResult {
    /// Confidence that the alert is a *true positive* (0 = almost certainly
    /// benign, 100 = very suspicious).
    pub confidence_score: u8,
    /// Enriched context attached to the alert JSON.
    pub enriched_context: EnrichedContext,
    /// Recommended severity string.  `"INFO"` when `confidence_score < 40`.
    pub severity: String,
    /// Human-readable explanation of the scoring decisions.
    pub scoring_notes: Vec<String>,
}

/// Additional context extracted during enrichment.
#[derive(Debug, Clone, Serialize, Default)]
pub struct EnrichedContext {
    /// The SNI hostname extracted from the TLS Client Hello, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Identified cloud / CDN provider, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

/// Run the full enrichment pipeline and return a scoring result.
///
/// This function is designed to be called from the alert dispatcher path
/// (after the main capture loop hands off data) so it does **not** block
/// the packet capture thread.
pub fn enrich(input: &ScoringInput) -> EnrichmentResult {
    let mut score: i32 = 100;
    let mut notes: Vec<String> = Vec::new();
    let mut ctx = EnrichedContext::default();

    // --- Step 1: Extract SNI ---
    if let Some(sni) = extract_sni(input.tls_payload) {
        ctx.sni = Some(sni.clone());
        ctx.provider = identify_provider(&sni);

        // Rule A: Safe domain → -80
        if is_safe_domain(&sni) {
            score -= 80;
            notes.push(format!("Rule A: SNI '{}' matches safe domain list (-80)", sni));
        }

        // Rule C: Beaconing to known CDN/Cloud → -40
        if input.is_beaconing && is_cdn_cloud_provider(&sni) {
            score -= 40;
            notes.push(format!(
                "Rule C: Beaconing to known CDN/Cloud provider '{}' (-40)",
                ctx.provider.as_deref().unwrap_or(&sni)
            ));
        }
    }

    // --- Rule B: port 443 + TLS + no suspicious raw strings → -20 ---
    if input.dst_port == 443 && looks_like_tls(input.tls_payload) {
        let has_suspicious = contains_suspicious_strings(input.session_data);
        if !has_suspicious {
            score -= 20;
            notes.push(
                "Rule B: Port 443 TLS with no suspicious raw strings ('id'/'whoami') (-20)"
                    .to_string(),
            );
        }
    }

    // Clamp to [0, 100]
    let confidence_score = score.clamp(0, 100) as u8;

    let severity = if confidence_score < 40 {
        "INFO".to_string()
    } else if confidence_score < 70 {
        "LOW".to_string()
    } else {
        "HIGH".to_string()
    };

    if notes.is_empty() {
        notes.push("No enrichment rules matched; score unchanged.".to_string());
    }

    EnrichmentResult {
        confidence_score,
        enriched_context: ctx,
        severity,
        scoring_notes: notes,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Quick check: does the buffer start with a TLS record header?
fn looks_like_tls(data: &[u8]) -> bool {
    if data.len() < 3 {
        return false;
    }
    // Content types: 20-25 (ChangeCipherSpec, Alert, Handshake, ApplicationData, …)
    let ct = data[0];
    let major = data[1];
    (20..=25).contains(&ct) && (major == 3)
}

/// Scan the raw session bytes for suspicious command strings.
///
/// We look for `id`, `whoami`, `cmd`, `powershell`, `/bin/sh` as byte
/// patterns.  This is intentionally a simple heuristic – the real value
/// comes from the SNI / reputation checks above.
fn contains_suspicious_strings(data: &[u8]) -> bool {
    const PATTERNS: &[&[u8]] = &[
        b"id\n",
        b"id\r",
        b"whoami",
        b"/bin/sh",
        b"/bin/bash",
        b"cmd.exe",
        b"powershell",
    ];
    let lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
    PATTERNS.iter().any(|pat| {
        let pat_lower: Vec<u8> = pat.iter().map(|b| b.to_ascii_lowercase()).collect();
        lower.windows(pat_lower.len()).any(|w| w == pat_lower.as_slice())
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_domain_matching() {
        assert!(is_safe_domain("outlook.office365.com"));
        assert!(is_safe_domain("login.microsoftonline.com"));
        assert!(is_safe_domain("s3.amazonaws.com"));
        assert!(is_safe_domain("cdn.cloudflare.com"));
        assert!(!is_safe_domain("evil-c2.example.com"));
        assert!(!is_safe_domain("malware.bad-domain.net"));
    }

    #[test]
    fn test_cdn_cloud_matching() {
        assert!(is_cdn_cloud_provider("d1234.cloudfront.net"));
        assert!(is_cdn_cloud_provider("myapp.azureedge.net"));
        assert!(!is_cdn_cloud_provider("evil.example.com"));
    }

    #[test]
    fn test_provider_identification() {
        assert_eq!(identify_provider("outlook.office365.com"), Some("Microsoft".to_string()));
        assert_eq!(identify_provider("maps.googleapis.com"), Some("Google".to_string()));
        assert_eq!(identify_provider("s3.amazonaws.com"), Some("Amazon/AWS".to_string()));
        assert_eq!(identify_provider("evil.example.com"), None);
    }

    #[test]
    fn test_suspicious_strings() {
        assert!(contains_suspicious_strings(b"GET / HTTP/1.1\r\nwhoami\r\n"));
        assert!(contains_suspicious_strings(b"id\n"));
        assert!(!contains_suspicious_strings(b"GET /index.html HTTP/1.1\r\n"));
    }

    #[test]
    fn test_scoring_safe_domain_beaconing() {
        // Simulate: no real TLS payload, but we test the scoring logic directly
        // by calling the individual functions.
        let mut score: i32 = 100;
        let sni = "outlook.office365.com";

        if is_safe_domain(sni) {
            score -= 80;
        }
        if is_cdn_cloud_provider(sni) {
            score -= 40; // beaconing rule
        }
        // Rule B not applicable (no TLS payload in this unit test)
        let final_score = score.clamp(0, 100) as u8;
        assert!(final_score < 40, "Expected score < 40 for Exchange traffic, got {}", final_score);
    }

    #[test]
    fn test_scoring_unknown_domain() {
        let score: i32 = 100;
        let sni = "evil-c2.example.com";
        let mut s = score;
        if is_safe_domain(sni) {
            s -= 80;
        }
        assert_eq!(s, 100, "Unknown domain should not reduce score");
    }
}
