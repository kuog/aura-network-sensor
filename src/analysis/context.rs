//! Network Intelligence & Flow Context Module
//!
//! Provides O(1) IP-range matching for major CDN and Cloud providers using the
//! `ipnetwork` crate, flow classification (TRUSTED_INFRASTRUCTURE), and a
//! confidence-scoring engine with "Relief Factors" to suppress false positives
//! from legitimate TLS traffic.
//!
//! ## MITRE Coverage
//! - **T1001** (Data Obfuscation) — contextual normalization for TLS padding.
//! - **T1573** (Encrypted Channel) — CDN-reputation cross-referencing.
//!
//! ## Suppression Audit
//! Suppressed alerts are logged to `suppressed.log` for SOC audit without
//! polluting the main alert feed.

use ipnetwork::IpNetwork;
use log::{debug, info};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex};

// ---------------------------------------------------------------------------
// Flow Trust Classification
// ---------------------------------------------------------------------------

/// Trust classification for a network flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowTrust {
    /// Destination IP belongs to a known CDN/Cloud provider on an expected port.
    TrustedInfrastructure,
    /// Destination IP is in a known provider range but on a non-standard port.
    KnownProviderNonStandardPort,
    /// No match — treat as untrusted.
    Untrusted,
}

impl std::fmt::Display for FlowTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowTrust::TrustedInfrastructure => write!(f, "TRUSTED_INFRASTRUCTURE"),
            FlowTrust::KnownProviderNonStandardPort => {
                write!(f, "KNOWN_PROVIDER_NON_STANDARD_PORT")
            }
            FlowTrust::Untrusted => write!(f, "UNTRUSTED"),
        }
    }
}

// ---------------------------------------------------------------------------
// CDN / Cloud Provider Registry (ipnetwork-based)
// ---------------------------------------------------------------------------

/// A CDN/Cloud provider with its associated IP ranges.
struct CdnProvider {
    name: &'static str,
    ranges: Vec<IpNetwork>,
}

/// Build the static provider registry.  Each provider's CIDR ranges are parsed
/// once at program start and stored as `IpNetwork` values for O(1) matching.
static CDN_PROVIDERS: LazyLock<Vec<CdnProvider>> = LazyLock::new(|| {
    vec![
        CdnProvider {
            name: "Cloudflare",
            ranges: parse_cidrs(&[
                "1.0.0.0/24",
                "1.1.1.0/24",
                "103.21.244.0/22",
                "103.22.200.0/22",
                "103.31.4.0/22",
                "104.16.0.0/13",
                "104.24.0.0/14",
                "108.162.192.0/18",
                "131.0.72.0/22",
                "141.101.64.0/18",
                "162.158.0.0/15",
                "172.64.0.0/13",
                "173.245.48.0/20",
                "188.114.96.0/20",
                "190.93.240.0/20",
                "197.234.240.0/22",
                "198.41.128.0/17",
                // IPv6
                "2400:cb00::/32",
                "2606:4700::/32",
                "2803:f800::/32",
                "2a06:98c0::/29",
                "2c0f:f248::/32",
            ]),
        },
        CdnProvider {
            name: "Akamai",
            ranges: parse_cidrs(&[
                "23.0.0.0/12",
                "23.32.0.0/11",
                "23.64.0.0/14",
                "23.72.0.0/13",
                "104.64.0.0/10",
                "184.24.0.0/13",
                "184.50.0.0/15",
                "184.84.0.0/14",
                "2.16.0.0/13",
                "95.100.0.0/15",
                // IPv6
                "2600:1400::/24",
                "2600:1480::/24",
            ]),
        },
        CdnProvider {
            name: "Google",
            ranges: parse_cidrs(&[
                "8.8.4.0/24",
                "8.8.8.0/24",
                "34.64.0.0/10",
                "34.128.0.0/10",
                "35.184.0.0/13",
                "35.192.0.0/12",
                "35.208.0.0/12",
                "35.224.0.0/12",
                "35.240.0.0/13",
                "64.233.160.0/19",
                "66.102.0.0/20",
                "72.14.192.0/18",
                "74.125.0.0/16",
                "142.250.0.0/15",
                "172.217.0.0/16",
                "173.194.0.0/16",
                "209.85.128.0/17",
                "216.58.192.0/19",
                // IPv6
                "2001:4860::/32",
                "2404:6800::/32",
                "2607:f8b0::/32",
                "2800:3f0::/32",
                "2a00:1450::/32",
                "2c0f:fb50::/32",
            ]),
        },
        CdnProvider {
            name: "Fastly",
            ranges: parse_cidrs(&[
                "23.235.32.0/20",
                "43.249.72.0/22",
                "103.244.50.0/24",
                "103.245.222.0/23",
                "103.245.224.0/24",
                "104.156.80.0/20",
                "140.248.64.0/18",
                "140.248.128.0/17",
                "146.75.0.0/17",
                "151.101.0.0/16",
                "157.52.64.0/18",
                "167.82.0.0/17",
                "167.82.128.0/20",
                "167.82.160.0/20",
                "167.82.224.0/20",
                "172.111.64.0/18",
                "185.31.16.0/22",
                "199.27.72.0/21",
                "199.232.0.0/16",
                // IPv6
                "2a04:4e40::/32",
                "2a04:4e42::/32",
            ]),
        },
        CdnProvider {
            name: "AWS",
            ranges: parse_cidrs(&[
                "3.0.0.0/15",
                "3.2.0.0/15",
                "3.4.0.0/14",
                "3.8.0.0/13",
                "3.16.0.0/14",
                "13.32.0.0/15",
                "13.224.0.0/14",
                "18.128.0.0/9",
                "34.192.0.0/10",
                "44.192.0.0/11",
                "52.0.0.0/11",
                "52.32.0.0/11",
                "52.64.0.0/11",
                "54.64.0.0/11",
                "54.128.0.0/11",
                "54.160.0.0/11",
                "54.192.0.0/12",
                "54.224.0.0/12",
                "99.77.128.0/18",
                "176.32.96.0/21",
                // IPv6
                "2600:1f00::/24",
                "2600:1ff0::/24",
                "2406:da00::/24",
                "2a05:d000::/25",
                "2600:9000::/28",
            ]),
        },
    ]
});

/// Parse a slice of CIDR strings into `IpNetwork` values.
fn parse_cidrs(cidrs: &[&str]) -> Vec<IpNetwork> {
    cidrs
        .iter()
        .filter_map(|s| s.parse::<IpNetwork>().ok())
        .collect()
}

// ---------------------------------------------------------------------------
// IP → Provider Lookup
// ---------------------------------------------------------------------------

/// Result of a CDN/Cloud provider IP lookup.
#[derive(Debug, Clone)]
pub struct CdnLookupResult {
    /// Provider name (e.g. "Cloudflare") or `None` if no match.
    pub provider: Option<String>,
    /// Whether the IP matched any known CDN/Cloud range.
    pub is_cdn: bool,
}

/// Lookup an IP address against the CDN/Cloud provider registry.
///
/// **Complexity**: O(P × R) where P = number of providers (5) and R = max
/// ranges per provider (~20). Effectively O(1) for the fixed dataset.
pub fn lookup_cdn(ip: &IpAddr) -> CdnLookupResult {
    for provider in CDN_PROVIDERS.iter() {
        for range in &provider.ranges {
            if range.contains(*ip) {
                return CdnLookupResult {
                    provider: Some(provider.name.to_string()),
                    is_cdn: true,
                };
            }
        }
    }
    CdnLookupResult {
        provider: None,
        is_cdn: false,
    }
}

/// Convenience: lookup from a string IP address.
pub fn lookup_cdn_str(ip_str: &str) -> CdnLookupResult {
    match ip_str.parse::<IpAddr>() {
        Ok(ip) => lookup_cdn(&ip),
        Err(_) => CdnLookupResult {
            provider: None,
            is_cdn: false,
        },
    }
}

// ---------------------------------------------------------------------------
// Flow Classification
// ---------------------------------------------------------------------------

/// Standard ports where encrypted traffic is expected.
const STANDARD_ENCRYPTED_PORTS: &[u16] = &[443, 993, 995, 465, 587, 853, 8443];

/// Classify a flow based on destination IP and port.
///
/// Returns `TRUSTED_INFRASTRUCTURE` if the destination IP is in a known
/// CDN/Cloud range **and** the destination port is a standard encrypted port.
pub fn classify_flow(dst_ip: &str, dst_port: u16) -> (FlowTrust, CdnLookupResult) {
    let cdn = lookup_cdn_str(dst_ip);
    let trust = if cdn.is_cdn {
        if STANDARD_ENCRYPTED_PORTS.contains(&dst_port) {
            FlowTrust::TrustedInfrastructure
        } else {
            FlowTrust::KnownProviderNonStandardPort
        }
    } else {
        FlowTrust::Untrusted
    };
    (trust, cdn)
}

// ---------------------------------------------------------------------------
// Confidence Scoring with Relief Factors
// ---------------------------------------------------------------------------

/// Relief factors applied to the base confidence score.
#[derive(Debug, Clone, Default)]
pub struct ReliefFactors {
    /// Matched a trusted CDN/Cloud ASN: −70 points (was −80).
    pub trusted_asn: bool,
    /// Traffic on a standard encrypted port (443/993/…): −10 points.
    pub standard_port: bool,
    /// Valid SNI (Server Name Indication) matching a safe domain: −20 points (was −10).
    pub valid_sni: bool,
}

/// Result of the confidence scoring pipeline.
#[derive(Debug, Clone)]
pub struct ConfidenceResult {
    /// Final confidence score (0–100).
    pub confidence: u8,
    /// Recommended severity string.
    pub severity: &'static str,
    /// Human-readable notes explaining each relief factor applied.
    pub notes: Vec<String>,
    /// The relief factors that were applied.
    pub factors: ReliefFactors,
}

/// Compute the final confidence score starting from `base_confidence = 100`
/// and subtracting relief factors.
///
/// | Factor                          | Points |
/// |---------------------------------|--------|
/// | Trusted CDN/Cloud ASN (AWS/GCP) | −70    |
/// | Standard encrypted port         | −10    |
/// | Safe SNI domain present         | −20    |
///
/// Severity thresholds:
/// - confidence > 75 → HIGH
/// - confidence < 30 → DEBUG (suppress)
/// - confidence < 50 → LOW
/// - confidence < 75 → MEDIUM
pub fn compute_confidence(
    dst_ip: &str,
    dst_port: u16,
    sni: Option<&str>,
) -> ConfidenceResult {
    let mut score: i32 = 100;
    let mut notes = Vec::new();
    let mut factors = ReliefFactors::default();

    // Factor 1: Trusted CDN/Cloud ASN — reduced from −80 to −70
    // Aligns with reputation_engine's contextual scoring
    let cdn = lookup_cdn_str(dst_ip);
    if cdn.is_cdn {
        score -= 70;
        factors.trusted_asn = true;
        notes.push(format!(
            "Matched Trusted ASN '{}' (-70)",
            cdn.provider.as_deref().unwrap_or("Unknown CDN")
        ));
    }

    // Factor 2: Standard encrypted port — reduced from −20 to −10
    if STANDARD_ENCRYPTED_PORTS.contains(&dst_port) {
        score -= 10;
        factors.standard_port = true;
        notes.push(format!("Standard encrypted port {} (-10)", dst_port));
    }

    // Factor 3: Safe SNI domain — increased from −10 to −20
    // Now checks against known safe domain suffixes for stronger reduction
    if let Some(sni_val) = sni {
        if !sni_val.is_empty() {
            if crate::analysis::reputation_engine::is_safe_sni(sni_val) {
                score -= 20;
                factors.valid_sni = true;
                notes.push(format!("Safe SNI '{}' matched known domain (-20)", sni_val));
            } else {
                // SNI present but not a known safe domain — smaller reduction
                score -= 5;
                factors.valid_sni = true;
                notes.push(format!("Valid SNI '{}' present (-5)", sni_val));
            }
        }
    }

    let confidence = score.clamp(0, 100) as u8;

    // Updated severity thresholds:
    // - HIGH only if confidence > 75 (was >= 70)
    // - DEBUG if confidence < 30 (new tier)
    let severity = if confidence < 30 {
        "DEBUG"
    } else if confidence < 50 {
        "LOW"
    } else if confidence <= 75 {
        "MEDIUM"
    } else {
        "HIGH"
    };

    if notes.is_empty() {
        notes.push("No relief factors matched; confidence unchanged.".to_string());
    }

    ConfidenceResult {
        confidence,
        severity,
        notes,
        factors,
    }
}

// ---------------------------------------------------------------------------
// TLS 1.3 Detection Helper
// ---------------------------------------------------------------------------

/// Check if the payload looks like a TLS 1.3 record.
///
/// TLS 1.3 uses record version 0x0303 (TLS 1.2) in the record layer for
/// backward compatibility, but the handshake `supported_versions` extension
/// advertises 0x0304.  For a quick heuristic, we check:
/// 1. Content type 0x16 (Handshake) or 0x17 (Application Data).
/// 2. Record version 0x0303 (the outer record layer).
/// 3. Presence of the `supported_versions` extension (type 0x002B) with
///    value 0x0304 in the Client Hello.
pub fn looks_like_tls_1_3(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }
    let content_type = data[0];
    let major = data[1];
    let minor = data[2];

    // Must be a TLS record (Handshake=0x16 or AppData=0x17)
    if content_type != 0x16 && content_type != 0x17 {
        return false;
    }

    // Record layer version 0x0303 (TLS 1.2 compat) or 0x0301 (TLS 1.0 compat)
    if major != 0x03 || (minor != 0x03 && minor != 0x01) {
        return false;
    }

    // For Application Data records (0x17), if version is 0x0303 on port 443,
    // it's very likely TLS 1.3 (since TLS 1.3 always uses 0x0303 in the
    // record layer).
    if content_type == 0x17 && major == 0x03 && minor == 0x03 {
        return true;
    }

    // For Handshake records, look for supported_versions extension (0x002B)
    // containing TLS 1.3 (0x0304).
    if content_type == 0x16 {
        // Search for the byte pattern 0x002B followed by 0x0304 somewhere
        // in the handshake.  This is a heuristic — not a full TLS parser.
        for i in 0..data.len().saturating_sub(5) {
            if data[i] == 0x00 && data[i + 1] == 0x2B {
                // Found supported_versions extension type
                // Look ahead for 0x0304 within the next ~10 bytes
                let search_end = (i + 12).min(data.len());
                for j in (i + 2)..search_end.saturating_sub(1) {
                    if data[j] == 0x03 && data[j + 1] == 0x04 {
                        return true;
                    }
                }
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Suppression Audit Logger
// ---------------------------------------------------------------------------

/// Global mutex-protected file handle for `suppressed.log`.
static SUPPRESSED_LOG: LazyLock<Mutex<Option<std::fs::File>>> = LazyLock::new(|| {
    match OpenOptions::new()
        .create(true)
        .append(true)
        .open("suppressed.log")
    {
        Ok(f) => {
            info!("[Context] Suppression audit log opened: suppressed.log");
            Mutex::new(Some(f))
        }
        Err(e) => {
            log::warn!("[Context] Failed to open suppressed.log: {}", e);
            Mutex::new(None)
        }
    }
});

/// Log a suppressed alert to `suppressed.log` for audit purposes.
///
/// Format: `[ISO-8601] technique_id | src_ip → dst_ip:dst_port | reason | metadata`
pub fn log_suppressed(
    technique_id: &str,
    src_ip: &str,
    dst_ip: &str,
    dst_port: u16,
    reason: &str,
    cdn_provider: Option<&str>,
    sni: Option<&str>,
) {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let line = format!(
        "[{}] {} | {} → {}:{} | reason={} | cdn={} | sni={}\n",
        timestamp,
        technique_id,
        src_ip,
        dst_ip,
        dst_port,
        reason,
        cdn_provider.unwrap_or("N/A"),
        sni.unwrap_or("N/A"),
    );

    // Also emit at DEBUG level for structured logging
    debug!(
        "[Suppressed] {} {} → {}:{} reason={} cdn={} sni={}",
        technique_id,
        src_ip,
        dst_ip,
        dst_port,
        reason,
        cdn_provider.unwrap_or("N/A"),
        sni.unwrap_or("N/A"),
    );

    if let Ok(mut guard) = SUPPRESSED_LOG.lock() {
        if let Some(ref mut file) = *guard {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
    }
}

// ---------------------------------------------------------------------------
// Integrated T1001 / T1573 Context Evaluation
// ---------------------------------------------------------------------------

/// Full context evaluation result for a flow suspected of T1001/T1573.
#[derive(Debug, Clone)]
pub struct ContextVerdict {
    /// Whether the alert should be suppressed entirely.
    pub suppress: bool,
    /// Whether the alert should be downgraded to INFO/DEBUG.
    pub downgrade_to_info: bool,
    /// Final confidence score after relief factors.
    pub confidence: u8,
    /// Recommended severity string.
    pub severity: &'static str,
    /// CDN provider name if matched.
    pub cdn_provider: Option<String>,
    /// Protocol feature tag (e.g. "TLS_1.3_Padding").
    pub protocol_feature: Option<String>,
    /// Suppression reason for metadata enrichment.
    pub suppression_reason: Option<String>,
    /// Flow trust classification.
    pub flow_trust: FlowTrust,
    /// Human-readable scoring notes.
    pub notes: Vec<String>,
}

/// Evaluate the full context for a T1001 (Data Obfuscation) detection.
///
/// This is the main entry point called from the engine when a T1001 trigger
/// fires (high entropy + null-byte padding on port 443).
///
/// # Logic
/// 1. Check if the protocol is TLS 1.3 (via `looks_like_tls_1_3`).
/// 2. Classify the flow (CDN lookup + port check).
/// 3. Cross-reference SNI with CDN provider.
/// 4. Compute confidence with relief factors.
/// 5. If confidence < 30 and flow is TRUSTED_INFRASTRUCTURE, suppress or
///    downgrade the alert.
pub fn evaluate_t1001_context(
    is_tls_1_3: bool,
    dst_ip: &str,
    dst_port: u16,
    sni: Option<&str>,
    observed_entropy: f64,
) -> ContextVerdict {
    let (flow_trust, cdn_result) = classify_flow(dst_ip, dst_port);
    let conf = compute_confidence(dst_ip, dst_port, sni);

    let mut notes = conf.notes.clone();

    // Determine protocol feature
    let protocol_feature = if is_tls_1_3 && dst_port == 443 {
        notes.push("TLS 1.3 detected on port 443".to_string());
        Some("TLS_1.3_Padding".to_string())
    } else if dst_port == 443 {
        Some("TLS_Padding".to_string())
    } else {
        None
    };

    // Determine suppression
    let (suppress, downgrade_to_info, suppression_reason) =
        if flow_trust == FlowTrust::TrustedInfrastructure && conf.confidence < 30 {
            let reason = format!(
                "Known CDN behavior: {} on port {} (entropy={:.2}, TLS1.3={})",
                cdn_result
                    .provider
                    .as_deref()
                    .unwrap_or("Unknown CDN"),
                dst_port,
                observed_entropy,
                is_tls_1_3,
            );
            notes.push(format!("SUPPRESSED: {}", reason));
            (true, true, Some(reason))
        } else if flow_trust == FlowTrust::TrustedInfrastructure {
            // CDN match but confidence still above 30 — downgrade only
            let reason = format!(
                "CDN traffic from {} — downgraded",
                cdn_result.provider.as_deref().unwrap_or("Unknown CDN"),
            );
            notes.push(format!("DOWNGRADED: {}", reason));
            (false, true, Some(reason))
        } else if conf.confidence < 30 {
            // Low confidence but not CDN — still downgrade to INFO
            let reason = "Low confidence after relief factors".to_string();
            notes.push(format!("DOWNGRADED: {}", reason));
            (false, true, Some(reason))
        } else {
            (false, false, None)
        };

    let severity = if suppress {
        "DEBUG"
    } else if downgrade_to_info {
        "INFO"
    } else {
        conf.severity
    };

    ContextVerdict {
        suppress,
        downgrade_to_info,
        confidence: if suppress { 0 } else { conf.confidence },
        severity,
        cdn_provider: cdn_result.provider,
        protocol_feature,
        suppression_reason,
        flow_trust,
        notes,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_ip_lookup() {
        // 104.16.0.1 is in Cloudflare's 104.16.0.0/13
        let result = lookup_cdn_str("104.16.0.1");
        assert!(result.is_cdn);
        assert_eq!(result.provider.as_deref(), Some("Cloudflare"));
    }

    #[test]
    fn test_cloudflare_172_64_range() {
        // 172.64.0.0/13 — Cloudflare
        let result = lookup_cdn_str("172.64.1.1");
        assert!(result.is_cdn);
        assert_eq!(result.provider.as_deref(), Some("Cloudflare"));
    }

    #[test]
    fn test_akamai_ip_lookup() {
        let result = lookup_cdn_str("23.1.0.1");
        assert!(result.is_cdn);
        assert_eq!(result.provider.as_deref(), Some("Akamai"));
    }

    #[test]
    fn test_google_ip_lookup() {
        let result = lookup_cdn_str("142.250.80.1");
        assert!(result.is_cdn);
        assert_eq!(result.provider.as_deref(), Some("Google"));
    }

    #[test]
    fn test_fastly_ip_lookup() {
        let result = lookup_cdn_str("151.101.1.1");
        assert!(result.is_cdn);
        assert_eq!(result.provider.as_deref(), Some("Fastly"));
    }

    #[test]
    fn test_aws_ip_lookup() {
        let result = lookup_cdn_str("54.192.0.1");
        assert!(result.is_cdn);
        assert_eq!(result.provider.as_deref(), Some("AWS"));
    }

    #[test]
    fn test_unknown_ip() {
        let result = lookup_cdn_str("192.168.1.1");
        assert!(!result.is_cdn);
        assert!(result.provider.is_none());
    }

    #[test]
    fn test_flow_classification_trusted() {
        let (trust, cdn) = classify_flow("104.16.0.1", 443);
        assert_eq!(trust, FlowTrust::TrustedInfrastructure);
        assert!(cdn.is_cdn);
    }

    #[test]
    fn test_flow_classification_non_standard_port() {
        let (trust, cdn) = classify_flow("104.16.0.1", 8080);
        assert_eq!(trust, FlowTrust::KnownProviderNonStandardPort);
        assert!(cdn.is_cdn);
    }

    #[test]
    fn test_flow_classification_untrusted() {
        let (trust, _) = classify_flow("192.168.1.1", 443);
        assert_eq!(trust, FlowTrust::Untrusted);
    }

    #[test]
    fn test_confidence_full_relief() {
        // Cloudflare IP + port 443 + safe SNI → 100 - 70 - 10 - 20 = 0 → DEBUG
        let result = compute_confidence("104.16.0.1", 443, Some("cdn.cloudflare.com"));
        assert!(
            result.confidence < 30,
            "Expected confidence < 30, got {}",
            result.confidence
        );
        assert_eq!(result.severity, "DEBUG");
        assert!(result.factors.trusted_asn);
        assert!(result.factors.standard_port);
        assert!(result.factors.valid_sni);
    }

    #[test]
    fn test_confidence_no_relief() {
        let result = compute_confidence("192.168.1.1", 8080, None);
        assert_eq!(result.confidence, 100);
        assert_eq!(result.severity, "HIGH");
    }

    #[test]
    fn test_confidence_partial_relief() {
        // Standard port only → 100 - 10 = 90
        let result = compute_confidence("192.168.1.1", 443, None);
        assert_eq!(result.confidence, 90);
    }

    #[test]
    fn test_confidence_cdn_port_only() {
        // CDN IP + standard port → 100 - 70 - 10 = 20 → DEBUG
        let result = compute_confidence("104.16.0.1", 443, None);
        assert_eq!(result.confidence, 20);
        assert_eq!(result.severity, "DEBUG");
    }

    #[test]
    fn test_evaluate_t1001_suppressed() {
        // Cloudflare IP + port 443 + SNI + high entropy → should suppress
        let verdict = evaluate_t1001_context(
            false,
            "104.16.0.1",
            443,
            Some("cdn.cloudflare.com"),
            7.95,
        );
        assert!(verdict.suppress || verdict.downgrade_to_info);
        // Suppressed alerts now get "DEBUG" severity
        assert!(verdict.severity == "DEBUG" || verdict.severity == "INFO");
        assert!(verdict.cdn_provider.is_some());
    }

    #[test]
    fn test_evaluate_t1001_not_suppressed() {
        // Unknown IP + non-standard port + no SNI → should NOT suppress
        let verdict = evaluate_t1001_context(false, "192.168.1.1", 8080, None, 7.95);
        assert!(!verdict.suppress);
        assert!(!verdict.downgrade_to_info);
        assert_eq!(verdict.confidence, 100);
    }
}
