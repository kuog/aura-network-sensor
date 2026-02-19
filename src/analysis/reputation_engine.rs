//! Reputation Engine — Contextual Scoring System for T1001 Detection
//!
//! Replaces binary trigger logic with a graduated confidence scoring system
//! that accounts for Cloud Provider infrastructure, TLS 1.3 protocol features,
//! and SNI-based domain trust.
//!
//! ## Key Components
//! - **`Identity`**: Structured IP metadata (provider, category, trust_level).
//! - **`get_ip_metadata()`**: Returns an `Identity` for any IP address.
//! - **`ContextualScore`**: Full scoring result with adjustments applied.
//! - **`compute_contextual_score()`**: Main entry point for the scoring pipeline.
//!
//! ## MITRE Coverage
//! - **T1001** (Data Obfuscation) — contextual normalization for TLS padding.
//! - **T1573** (Encrypted Channel) — cloud provider reputation cross-referencing.

use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Identity — Structured IP Metadata
// ---------------------------------------------------------------------------

/// Structured metadata for an IP address, returned by [`get_ip_metadata`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Cloud/CDN provider name (e.g. "AWS", "Google", "Cloudflare").
    pub provider: &'static str,
    /// Category of the provider (e.g. "Cloud", "CDN", "DNS").
    pub category: &'static str,
    /// Base trust level (0–100). Higher = more trusted.
    /// - 50: Standard cloud provider
    /// - 60: Major CDN (Cloudflare, Akamai)
    /// - 0:  Unknown / untrusted
    pub trust_level: u8,
}

impl Identity {
    /// Unknown / unclassified IP.
    pub const fn unknown() -> Self {
        Self {
            provider: "Unknown",
            category: "Unknown",
            trust_level: 0,
        }
    }

    /// Returns `true` if this identity belongs to a known cloud/CDN provider.
    pub fn is_known_provider(&self) -> bool {
        self.trust_level > 0
    }

    /// Returns `true` if this is a major cloud provider (AWS, Google, Azure).
    pub fn is_cloud(&self) -> bool {
        self.category == "Cloud"
    }

    /// Returns `true` if this is a CDN provider (Cloudflare, Akamai, Fastly).
    pub fn is_cdn(&self) -> bool {
        self.category == "CDN"
    }
}

// ---------------------------------------------------------------------------
// Cloud Provider CIDR Registry
// ---------------------------------------------------------------------------

/// A provider entry with CIDR ranges and metadata.
struct ProviderEntry {
    identity: Identity,
    ranges: Vec<IpNetwork>,
}

/// Parse a slice of CIDR strings into `IpNetwork` values.
fn parse_cidrs(cidrs: &[&str]) -> Vec<IpNetwork> {
    cidrs
        .iter()
        .filter_map(|s| s.parse::<IpNetwork>().ok())
        .collect()
}

/// Static registry of all known cloud/CDN providers with their CIDR ranges.
static PROVIDER_REGISTRY: LazyLock<Vec<ProviderEntry>> = LazyLock::new(|| {
    vec![
        // ── AWS ────────────────────────────────────────────────────────
        ProviderEntry {
            identity: Identity {
                provider: "AWS",
                category: "Cloud",
                trust_level: 50,
            },
            ranges: parse_cidrs(&[
                "3.0.0.0/15",
                "3.2.0.0/15",
                "3.4.0.0/14",
                "3.8.0.0/13",
                "3.16.0.0/14",
                "13.32.0.0/15",
                "13.34.0.0/15",
                "13.224.0.0/14",
                "15.177.0.0/18",
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
                "54.240.0.0/12",
                "99.77.128.0/18",
                "99.150.0.0/21",
                "176.32.96.0/21",
            ]),
        },
        // ── Azure (Microsoft) ──────────────────────────────────────────
        ProviderEntry {
            identity: Identity {
                provider: "Azure",
                category: "Cloud",
                trust_level: 50,
            },
            ranges: parse_cidrs(&[
                "13.64.0.0/11",
                "13.104.0.0/14",
                "20.0.0.0/8",
                "23.96.0.0/13",
                "40.64.0.0/10",
                "40.126.0.0/18",
                "51.104.0.0/15",
                "52.96.0.0/14",
                "52.112.0.0/14",
                "104.40.0.0/13",
                "104.208.0.0/13",
                "131.253.0.0/16",
                "134.170.0.0/16",
                "150.171.0.0/16",
                "157.55.0.0/16",
                "191.232.0.0/13",
                "204.79.180.0/24",
            ]),
        },
        // ── GCP (Google Cloud Platform) ────────────────────────────────
        ProviderEntry {
            identity: Identity {
                provider: "GCP",
                category: "Cloud",
                trust_level: 50,
            },
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
                "66.249.64.0/19",
                "72.14.192.0/18",
                "74.125.0.0/16",
                "108.170.192.0/18",
                "142.250.0.0/15",
                "172.217.0.0/16",
                "173.194.0.0/16",
                "209.85.128.0/17",
                "216.58.192.0/19",
                "216.239.32.0/19",
            ]),
        },
        // ── Cloudflare ─────────────────────────────────────────────────
        ProviderEntry {
            identity: Identity {
                provider: "Cloudflare",
                category: "CDN",
                trust_level: 60,
            },
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
            ]),
        },
        // ── Akamai ─────────────────────────────────────────────────────
        ProviderEntry {
            identity: Identity {
                provider: "Akamai",
                category: "CDN",
                trust_level: 60,
            },
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
            ]),
        },
        // ── Fastly ─────────────────────────────────────────────────────
        ProviderEntry {
            identity: Identity {
                provider: "Fastly",
                category: "CDN",
                trust_level: 55,
            },
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
            ]),
        },
        // ── GitHub ──────────────────────────────────────────────────────
        ProviderEntry {
            identity: Identity {
                provider: "GitHub",
                category: "Cloud",
                trust_level: 55,
            },
            ranges: parse_cidrs(&[
                "140.82.112.0/20",
                "143.55.64.0/20",
                "185.199.108.0/22",
                "192.30.252.0/22",
            ]),
        },
    ]
});

// ---------------------------------------------------------------------------
// IP → Identity Lookup
// ---------------------------------------------------------------------------

/// Look up structured metadata for an IP address.
///
/// Returns an [`Identity`] with provider name, category, and trust level.
/// For unknown IPs, returns `Identity::unknown()` with `trust_level = 0`.
///
/// **Complexity**: O(P × R) where P = number of providers (6) and R = max
/// ranges per provider (~24). Effectively O(1) for the fixed dataset.
pub fn get_ip_metadata(ip: IpAddr) -> Identity {
    for entry in PROVIDER_REGISTRY.iter() {
        for range in &entry.ranges {
            if range.contains(ip) {
                return entry.identity.clone();
            }
        }
    }
    Identity::unknown()
}

/// Convenience: lookup from a string IP address.
pub fn get_ip_metadata_str(ip_str: &str) -> Identity {
    match ip_str.parse::<IpAddr>() {
        Ok(ip) => get_ip_metadata(ip),
        Err(_) => Identity::unknown(),
    }
}

// ---------------------------------------------------------------------------
// Provider Display Name Mapping
// ---------------------------------------------------------------------------

/// Map a short provider code to a full display name for JSON output.
pub fn provider_display_name(provider: &str) -> &'static str {
    match provider {
        "AWS" => "Amazon.com",
        "Azure" => "Microsoft Corporation",
        "GCP" => "Google LLC",
        "Cloudflare" => "Cloudflare Inc.",
        "Akamai" => "Akamai Technologies",
        "Fastly" => "Fastly Inc.",
        "GitHub" => "GitHub Inc.",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Safe Domain Suffixes for SNI-based Trust
// ---------------------------------------------------------------------------

/// Known safe domain suffixes for SNI-based confidence reduction.
/// If an SNI matches one of these, confidence is reduced by an additional 20 points.
const SAFE_SNI_SUFFIXES: &[(&str, &str)] = &[
    // AWS
    (".amazonaws.com", "AWS"),
    (".amazon.com", "AWS"),
    (".cloudfront.net", "AWS"),
    (".elasticbeanstalk.com", "AWS"),
    // Azure / Microsoft
    (".azure.com", "Azure"),
    (".azure.net", "Azure"),
    (".microsoft.com", "Azure"),
    (".microsoftonline.com", "Azure"),
    (".windows.net", "Azure"),
    (".office365.com", "Azure"),
    (".office.com", "Azure"),
    (".outlook.com", "Azure"),
    (".sharepoint.com", "Azure"),
    // GCP / Google
    (".googleapis.com", "GCP"),
    (".google.com", "GCP"),
    (".gstatic.com", "GCP"),
    (".googlevideo.com", "GCP"),
    (".youtube.com", "GCP"),
    // Cloudflare
    (".cloudflare.com", "Cloudflare"),
    (".cloudflare-dns.com", "Cloudflare"),
    (".cloudflareinsights.com", "Cloudflare"),
    // Akamai
    (".akamai.net", "Akamai"),
    (".akamaized.net", "Akamai"),
    (".akamaiedge.net", "Akamai"),
    // Fastly
    (".fastly.net", "Fastly"),
    (".fastlylb.net", "Fastly"),
    // Other trusted infrastructure
    (".github.com", "GitHub"),
    (".githubusercontent.com", "GitHub"),
];

/// Check if an SNI hostname matches a known safe domain suffix.
/// Returns the provider name on match.
pub fn match_safe_sni(sni: &str) -> Option<&'static str> {
    let lower = sni.to_lowercase();
    for &(suffix, provider) in SAFE_SNI_SUFFIXES {
        if lower.ends_with(suffix) || lower == suffix.trim_start_matches('.') {
            return Some(provider);
        }
    }
    None
}

/// Returns `true` if the SNI belongs to a known safe domain.
pub fn is_safe_sni(sni: &str) -> bool {
    match_safe_sni(sni).is_some()
}

// ---------------------------------------------------------------------------
// Contextual Score — Full Scoring Result
// ---------------------------------------------------------------------------

/// Result of the contextual scoring pipeline.
#[derive(Debug, Clone)]
pub struct ContextualScore {
    /// Final confidence score (0–100) after all adjustments.
    pub confidence: u8,
    /// Recommended severity string: "DEBUG", "INFO", "LOW", "MEDIUM", "HIGH".
    pub severity: &'static str,
    /// Whether the alert should be suppressed entirely.
    pub suppress: bool,
    /// Whether the detection is a standard TLS feature (not malicious).
    pub is_standard_tls_feature: bool,
    /// IP identity metadata for the destination.
    pub dst_identity: Identity,
    /// Provider display name (e.g. "Amazon.com").
    pub provider_name: &'static str,
    /// Flow trust classification string.
    pub flow_trust: &'static str,
    /// Human-readable notes explaining each adjustment.
    pub notes: Vec<String>,
}

/// Compute a contextual confidence score for a T1001 detection.
///
/// This replaces the binary trigger with a graduated scoring system:
///
/// | Step | Condition | Adjustment |
/// |------|-----------|------------|
/// | 1 | Protocol: TLS 1.3 on port 443 + "Null byte padding" | Mark as standard TLS feature |
/// | 2 | Reputation: IP in AWS/Google/Cloudflare CIDR | −70 points |
/// | 3 | SNI: Matches known safe domain (*.amazonaws.com) | −20 points |
/// | 4 | If confidence < 30 after adjustments | severity = DEBUG, suppress |
/// | 5 | If confidence > 75 | severity = HIGH |
///
/// # Arguments
/// * `base_confidence` — Starting confidence (typically 100 for raw detections).
/// * `dst_ip` — Destination IP address string.
/// * `dst_port` — Destination port.
/// * `sni` — Optional SNI hostname from TLS Client Hello.
/// * `pattern_type` — Detection pattern (e.g. "Null byte padding").
/// * `is_tls13` — Whether TLS 1.3 was detected in the payload.
pub fn compute_contextual_score(
    base_confidence: u8,
    dst_ip: &str,
    dst_port: u16,
    sni: Option<&str>,
    pattern_type: &str,
    is_tls13: bool,
) -> ContextualScore {
    let mut score: i32 = base_confidence as i32;
    let mut notes = Vec::new();
    let mut is_standard_tls_feature = false;

    // ── Step 1: Protocol Validation ────────────────────────────────────
    // If dst_port == 443 AND TLS 1.3 AND pattern is "Null byte padding",
    // this is a standard protocol feature, not obfuscation.
    if dst_port == 443 && is_tls13 && pattern_type == "Null byte padding" {
        is_standard_tls_feature = true;
        notes.push(
            "TLS 1.3 null-byte padding on port 443 is a standard protocol feature".to_string(),
        );
    }

    // ── Step 2: Reputation Adjustment ──────────────────────────────────
    // Look up the destination IP in the cloud provider registry.
    let dst_identity = get_ip_metadata_str(dst_ip);

    if dst_identity.is_known_provider() {
        // AWS, Google, Cloudflare, etc. → reduce confidence by 70 points
        score -= 70;
        notes.push(format!(
            "Destination IP belongs to {} ({}) — confidence reduced by 70",
            dst_identity.provider, dst_identity.category,
        ));
    }

    // ── Step 3: SNI-based Trust Adjustment ─────────────────────────────
    // If SNI is present and matches a known safe domain, reduce by 20 more.
    if let Some(sni_val) = sni {
        if let Some(sni_provider) = match_safe_sni(sni_val) {
            score -= 20;
            notes.push(format!(
                "SNI '{}' matches safe domain for {} — confidence reduced by 20",
                sni_val, sni_provider,
            ));
        }
    }

    // Clamp to [0, 100]
    let confidence = score.clamp(0, 100) as u8;

    // ── Step 4: Severity Classification ────────────────────────────────
    // New thresholds per task requirements:
    // - confidence > 75 → HIGH
    // - confidence < 30 (due to reputation/protocol) → DEBUG or suppress
    let (severity, suppress) = if confidence < 30 {
        if is_standard_tls_feature || dst_identity.is_known_provider() {
            // Suppress entirely — this is trusted infrastructure + standard TLS
            ("DEBUG", true)
        } else {
            ("DEBUG", false)
        }
    } else if confidence < 50 {
        ("LOW", false)
    } else if confidence <= 75 {
        ("MEDIUM", false)
    } else {
        ("HIGH", false)
    };

    // ── Flow Trust Classification ──────────────────────────────────────
    let flow_trust = if dst_identity.is_known_provider() && dst_port == 443 {
        "TRUSTED_INFRASTRUCTURE"
    } else if dst_identity.is_known_provider() {
        "KNOWN_PROVIDER"
    } else {
        "UNTRUSTED"
    };

    let provider_name = provider_display_name(dst_identity.provider);

    if notes.is_empty() {
        notes.push("No contextual adjustments applied; confidence unchanged.".to_string());
    }

    ContextualScore {
        confidence,
        severity,
        suppress,
        is_standard_tls_feature,
        dst_identity,
        provider_name,
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
    fn test_aws_ip_metadata() {
        let id = get_ip_metadata_str("54.192.0.1");
        assert_eq!(id.provider, "AWS");
        assert_eq!(id.category, "Cloud");
        assert_eq!(id.trust_level, 50);
        assert!(id.is_known_provider());
        assert!(id.is_cloud());
    }

    #[test]
    fn test_gcp_ip_metadata() {
        let id = get_ip_metadata_str("142.250.80.4");
        assert_eq!(id.provider, "GCP");
        assert_eq!(id.category, "Cloud");
        assert_eq!(id.trust_level, 50);
    }

    #[test]
    fn test_azure_ip_metadata() {
        let id = get_ip_metadata_str("20.1.0.1");
        assert_eq!(id.provider, "Azure");
        assert_eq!(id.category, "Cloud");
        assert_eq!(id.trust_level, 50);
    }

    #[test]
    fn test_cloudflare_ip_metadata() {
        let id = get_ip_metadata_str("104.16.0.1");
        assert_eq!(id.provider, "Cloudflare");
        assert_eq!(id.category, "CDN");
        assert_eq!(id.trust_level, 60);
        assert!(id.is_cdn());
    }

    #[test]
    fn test_unknown_ip_metadata() {
        let id = get_ip_metadata_str("192.168.1.1");
        assert_eq!(id.provider, "Unknown");
        assert_eq!(id.trust_level, 0);
        assert!(!id.is_known_provider());
    }

    #[test]
    fn test_safe_sni_match() {
        assert_eq!(match_safe_sni("s3.amazonaws.com"), Some("AWS"));
        assert_eq!(match_safe_sni("cdn.cloudflare.com"), Some("Cloudflare"));
        assert_eq!(match_safe_sni("storage.googleapis.com"), Some("GCP"));
        assert!(match_safe_sni("evil-c2.example.com").is_none());
    }

    #[test]
    fn test_provider_display_name() {
        assert_eq!(provider_display_name("AWS"), "Amazon.com");
        assert_eq!(provider_display_name("GCP"), "Google LLC");
        assert_eq!(provider_display_name("Azure"), "Microsoft Corporation");
    }

    #[test]
    fn test_contextual_score_aws_tls13_null_padding() {
        // AWS IP + TLS 1.3 + port 443 + null byte padding + safe SNI
        // Base 100 - 70 (cloud) - 20 (SNI) = 10 → DEBUG, suppress
        let score = compute_contextual_score(
            100,
            "54.192.0.1",
            443,
            Some("s3.amazonaws.com"),
            "Null byte padding",
            true,
        );
        assert!(score.confidence < 30, "Expected < 30, got {}", score.confidence);
        assert_eq!(score.severity, "DEBUG");
        assert!(score.suppress);
        assert!(score.is_standard_tls_feature);
        assert_eq!(score.provider_name, "Amazon.com");
        assert_eq!(score.flow_trust, "TRUSTED_INFRASTRUCTURE");
    }

    #[test]
    fn test_contextual_score_cloud_no_sni() {
        // Cloud IP + no SNI → 100 - 70 = 30 → LOW (not suppressed)
        let score = compute_contextual_score(
            100,
            "54.192.0.1",
            443,
            None,
            "Null byte padding",
            true,
        );
        assert_eq!(score.confidence, 30);
        assert_eq!(score.severity, "LOW");
        assert!(!score.suppress);
    }

    #[test]
    fn test_contextual_score_unknown_ip() {
        // Unknown IP + no adjustments → 100 → HIGH
        let score = compute_contextual_score(
            100,
            "192.168.1.1",
            443,
            None,
            "Null byte padding",
            false,
        );
        assert_eq!(score.confidence, 100);
        assert_eq!(score.severity, "HIGH");
        assert!(!score.suppress);
        assert!(!score.is_standard_tls_feature);
    }

    #[test]
    fn test_contextual_score_high_threshold() {
        // Confidence must be > 75 for HIGH severity
        let score = compute_contextual_score(
            75,
            "192.168.1.1",
            8080,
            None,
            "Hidden strings in encrypted channel",
            false,
        );
        // 75 is not > 75, so should be MEDIUM
        assert_eq!(score.severity, "MEDIUM");
    }
}
