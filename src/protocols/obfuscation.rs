use crate::analysis::context;
use crate::analysis::reputation_engine::{self, ContextualScore};
use crate::telemetry::shannon_entropy;

pub struct StegResult {
    pub technique_id: String,
    pub reason: String,
    pub observed_entropy: f64,
    pub pattern_type: String,
    /// When `true`, the detection is considered benign (e.g. TLS padding from
    /// a known CDN on port 443 with consistently high entropy).
    pub is_benign: bool,
    /// Optional protocol-level feature tag (e.g. "TLS Padding detected").
    pub protocol_feature: Option<String>,
    /// CDN provider name when the benign heuristic matched.
    pub cdn_provider: Option<String>,
    /// Suppression reason for metadata enrichment.
    pub suppression_reason: Option<String>,
    /// Contextual score from the reputation engine (populated when available).
    pub contextual_score: Option<ContextualScore>,
}

/// Additional context passed into the steganography analyser so it can
/// distinguish legitimate TLS padding from real obfuscation.
pub struct StegContext<'a> {
    /// SNI hostname extracted from the TLS Client Hello, if available.
    pub sni: Option<&'a str>,
    /// Destination IP address (as string) — used for IP-based CDN matching.
    pub dst_ip: &'a str,
}

// ---------------------------------------------------------------------------
// Known CDN SNI suffixes (Cloudflare, Akamai, Fastly)
// ---------------------------------------------------------------------------

const CDN_SNI_SUFFIXES: &[(&str, &str)] = &[
    // Cloudflare
    (".cloudflare.com", "Cloudflare"),
    (".cloudflare-dns.com", "Cloudflare"),
    (".cloudflareinsights.com", "Cloudflare"),
    // Akamai
    (".akamai.net", "Akamai"),
    (".akamaized.net", "Akamai"),
    (".akamaiedge.net", "Akamai"),
    (".akamaitechnologies.com", "Akamai"),
    // Fastly
    (".fastly.net", "Fastly"),
    (".fastlylb.net", "Fastly"),
    (".fastly.com", "Fastly"),
    // Google
    (".google.com", "Google"),
    (".googleapis.com", "Google"),
    (".gstatic.com", "Google"),
    (".googlevideo.com", "Google"),
    // AWS / CloudFront
    (".cloudfront.net", "AWS"),
    (".amazonaws.com", "AWS"),
];

/// Check if the SNI belongs to a known CDN (Cloudflare, Akamai, Fastly, etc.).
/// Returns the provider name on match.
fn match_cdn_sni(sni: &str) -> Option<&'static str> {
    let lower = sni.to_lowercase();
    for &(suffix, provider) in CDN_SNI_SUFFIXES {
        if lower.ends_with(suffix) || lower == suffix.trim_start_matches('.') {
            return Some(provider);
        }
    }
    None
}

/// Try to identify CDN provider via IP-based lookup (using the context module).
/// Falls back to SNI-based matching if IP lookup fails.
fn resolve_cdn_provider(ctx: Option<&StegContext>) -> Option<String> {
    if let Some(c) = ctx {
        // First: try IP-based CDN lookup (O(1) via ipnetwork)
        let cdn_lookup = context::lookup_cdn_str(c.dst_ip);
        if cdn_lookup.is_cdn {
            return cdn_lookup.provider;
        }
        // Fallback: SNI-based CDN matching
        if let Some(sni) = c.sni {
            if let Some(provider) = match_cdn_sni(sni) {
                return Some(provider.to_string());
            }
        }
    }
    None
}

pub fn analyze_steganography(payload: &[u8], port: u16) -> Option<StegResult> {
    analyze_steganography_with_context(payload, port, None)
}

pub fn analyze_steganography_with_context(
    payload: &[u8],
    port: u16,
    ctx: Option<&StegContext>,
) -> Option<StegResult> {
    if payload.is_empty() {
        return None;
    }

    let entropy = shannon_entropy(payload);

    // ── Step 1: TLS 1.3 Protocol Validation ─────────────────────────────
    // Before triggering T1001, check if the protocol is TLS 1.3.
    // TLS 1.3 traffic on port 443 with high entropy is expected behavior.
    let is_tls_1_3 = context::looks_like_tls_1_3(payload);
    let protocol_feature_tag = if is_tls_1_3 && port == 443 {
        Some("TLS_1.3_Padding".to_string())
    } else if port == 443 {
        Some("TLS_Padding".to_string())
    } else {
        None
    };

    // Trigger 1: Magic Byte Mismatch
    if let Some(format) = check_magic_bytes(payload) {
        // Expected entropy for compressed images is usually high (> 7.0)
        // User specified < 5.0 as a threshold for "significantly lower"
        if entropy < 5.0 {
            return Some(StegResult {
                technique_id: "T1001".to_string(),
                reason: "Entropy dilution detected".to_string(),
                observed_entropy: entropy,
                pattern_type: format!("Low entropy {} file", format),
                is_benign: false,
                protocol_feature: None,
                cdn_provider: None,
                suppression_reason: None,
                contextual_score: None,
            });
        }
    }

    // Trigger 3: Null Byte Padding
    // Detect large blocks of null bytes (0x00) used as padding
    if has_null_block(payload, 32) {
        // ── Step 2: Signature Filtering ─────────────────────────────────
        // If pattern_type == "Null byte padding" AND is_tls13 == true on
        // port 443, this is a standard TLS 1.3 protocol feature.
        //
        // ── Step 3: Reputation Adjustment ───────────────────────────────
        // Use the reputation engine to compute contextual confidence score.
        // Cloud provider IPs get −70, safe SNI gets −20.
        if let Some(c) = ctx {
            let contextual = reputation_engine::compute_contextual_score(
                100,
                c.dst_ip,
                port,
                c.sni,
                "Null byte padding",
                is_tls_1_3,
            );

            // If the contextual score says suppress (confidence < 30 + known provider),
            // mark as benign with full metadata.
            if contextual.suppress || contextual.is_standard_tls_feature {
                let cdn_provider = resolve_cdn_provider(ctx)
                    .or_else(|| {
                        if contextual.dst_identity.is_known_provider() {
                            Some(contextual.dst_identity.provider.to_string())
                        } else {
                            None
                        }
                    });

                let suppression_reason = if contextual.is_standard_tls_feature {
                    format!(
                        "Standard TLS 1.3 feature: null-byte padding on port {} to {} (confidence={}, entropy={:.2})",
                        port,
                        contextual.provider_name,
                        contextual.confidence,
                        entropy,
                    )
                } else {
                    format!(
                        "Known cloud provider: {} on port {} (confidence={}, entropy={:.2})",
                        contextual.provider_name,
                        port,
                        contextual.confidence,
                        entropy,
                    )
                };

                return Some(StegResult {
                    technique_id: "T1001".to_string(),
                    reason: format!(
                        "TLS null-byte padding on port {} to '{}' (entropy={:.2}) — contextual score: {}",
                        port,
                        contextual.provider_name,
                        entropy,
                        contextual.confidence,
                    ),
                    observed_entropy: entropy,
                    pattern_type: "Null byte padding".to_string(),
                    is_benign: true,
                    protocol_feature: protocol_feature_tag.clone().or(Some("TLS Padding detected".to_string())),
                    cdn_provider,
                    suppression_reason: Some(suppression_reason),
                    contextual_score: Some(contextual),
                });
            }

            // Even if not suppressed, if confidence is reduced, still attach
            // the contextual score for downstream processing.
            if contextual.confidence < 100 {
                // Check legacy CDN heuristic as well
                if port == 443 && entropy > 7.9 {
                    if let Some(cdn_provider) = resolve_cdn_provider(ctx) {
                        let suppression_reason = if is_tls_1_3 {
                            format!(
                                "Known CDN behavior: TLS 1.3 padding from '{}' on port 443 (entropy={:.2})",
                                cdn_provider, entropy,
                            )
                        } else {
                            format!(
                                "Known CDN behavior: TLS padding from '{}' on port 443 (entropy={:.2})",
                                cdn_provider, entropy,
                            )
                        };

                        return Some(StegResult {
                            technique_id: "T1001".to_string(),
                            reason: format!(
                                "TLS null-byte padding on port 443 to known CDN '{}' with high entropy ({:.2}) — benign",
                                cdn_provider, entropy,
                            ),
                            observed_entropy: entropy,
                            pattern_type: "Null byte padding".to_string(),
                            is_benign: true,
                            protocol_feature: protocol_feature_tag.clone().or(Some("TLS Padding detected".to_string())),
                            cdn_provider: Some(cdn_provider),
                            suppression_reason: Some(suppression_reason),
                            contextual_score: Some(contextual),
                        });
                    }
                }

                // Non-benign but with reduced confidence — attach score
                return Some(StegResult {
                    technique_id: "T1001".to_string(),
                    reason: "Entropy dilution detected".to_string(),
                    observed_entropy: entropy,
                    pattern_type: "Null byte padding".to_string(),
                    is_benign: false,
                    protocol_feature: protocol_feature_tag,
                    cdn_provider: None,
                    suppression_reason: None,
                    contextual_score: Some(contextual),
                });
            }
        } else {
            // No context available — fall back to legacy CDN heuristic
            if port == 443 && entropy > 7.9 {
                if let Some(cdn_provider) = resolve_cdn_provider(ctx) {
                    let suppression_reason = if is_tls_1_3 {
                        format!(
                            "Known CDN behavior: TLS 1.3 padding from '{}' on port 443 (entropy={:.2})",
                            cdn_provider, entropy,
                        )
                    } else {
                        format!(
                            "Known CDN behavior: TLS padding from '{}' on port 443 (entropy={:.2})",
                            cdn_provider, entropy,
                        )
                    };

                    return Some(StegResult {
                        technique_id: "T1001".to_string(),
                        reason: format!(
                            "TLS null-byte padding on port 443 to known CDN '{}' with high entropy ({:.2}) — benign",
                            cdn_provider, entropy,
                        ),
                        observed_entropy: entropy,
                        pattern_type: "Null byte padding".to_string(),
                        is_benign: true,
                        protocol_feature: protocol_feature_tag.clone().or(Some("TLS Padding detected".to_string())),
                        cdn_provider: Some(cdn_provider),
                        suppression_reason: Some(suppression_reason),
                        contextual_score: None,
                    });
                }

                // Even without CDN match, if TLS 1.3 is detected on port 443,
                // cross-reference with the context module's flow classification
                if is_tls_1_3 {
                    if let Some(c) = ctx {
                        let (flow_trust, cdn_result) = context::classify_flow(c.dst_ip, port);
                        if flow_trust == context::FlowTrust::TrustedInfrastructure {
                            let provider = cdn_result.provider.unwrap_or_else(|| "Unknown CDN".to_string());
                            return Some(StegResult {
                                technique_id: "T1001".to_string(),
                                reason: format!(
                                    "TLS 1.3 null-byte padding on port 443 to trusted infrastructure '{}' (entropy={:.2}) — benign",
                                    provider, entropy,
                                ),
                                observed_entropy: entropy,
                                pattern_type: "Null byte padding".to_string(),
                                is_benign: true,
                                protocol_feature: Some("TLS_1.3_Padding".to_string()),
                                cdn_provider: Some(provider),
                                suppression_reason: Some("Known CDN behavior".to_string()),
                                contextual_score: None,
                            });
                        }
                    }
                }
            }
        }

        return Some(StegResult {
            technique_id: "T1001".to_string(),
            reason: "Entropy dilution detected".to_string(),
            observed_entropy: entropy,
            pattern_type: "Null byte padding".to_string(),
            is_benign: false,
            protocol_feature: protocol_feature_tag,
            cdn_provider: None,
            suppression_reason: None,
            contextual_score: None,
        });
    }

    // Trigger 2: Hidden Strings
    // Detect high density of ASCII/UTF-8 strings inside what should be purely binary encrypted traffic
    let encrypted_ports = [443, 8443, 22, 993, 995, 465];
    if encrypted_ports.contains(&port) {
        let string_density = calculate_string_density(payload);
        // If > 30% of bytes are printable strings (min length 4), and it's supposed to be encrypted.
        if string_density > 0.3 {
             return Some(StegResult {
                technique_id: "T1001".to_string(),
                reason: "Entropy dilution detected".to_string(),
                observed_entropy: entropy,
                pattern_type: "Hidden strings in encrypted channel".to_string(),
                is_benign: false,
                protocol_feature: None,
                cdn_provider: None,
                suppression_reason: None,
                contextual_score: None,
            });
        }
    }

    None
}

fn check_magic_bytes(payload: &[u8]) -> Option<&'static str> {
    if payload.len() < 4 { return None; }
    
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if payload.starts_with(&[0x89, 0x50, 0x4E, 0x47]) { return Some("PNG"); }
    
    // GIF: 47 49 46 38
    if payload.starts_with(&[0x47, 0x49, 0x46, 0x38]) { return Some("GIF"); }
    
    // JPEG/JFIF: FF D8 FF
    if payload.starts_with(&[0xFF, 0xD8, 0xFF]) { return Some("JFIF"); }
    
    None
}

fn has_null_block(payload: &[u8], min_len: usize) -> bool {
    let mut count = 0;
    for &b in payload {
        if b == 0x00 {
            count += 1;
            if count >= min_len {
                return true;
            }
        } else {
            count = 0;
        }
    }
    false
}

fn calculate_string_density(payload: &[u8]) -> f64 {
    let mut current_string_len = 0;
    let mut total_string_bytes = 0;

    for &b in payload {
        // Check for printable ASCII (0x20 - 0x7E)
        if b >= 0x20 && b <= 0x7E {
            current_string_len += 1;
        } else {
            if current_string_len >= 4 {
                total_string_bytes += current_string_len;
            }
            current_string_len = 0;
        }
    }
    // Check last segment
    if current_string_len >= 4 {
        total_string_bytes += current_string_len;
    }

    total_string_bytes as f64 / payload.len() as f64
}
