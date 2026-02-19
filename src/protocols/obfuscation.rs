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
];

/// Check if the SNI belongs to a known CDN (Cloudflare, Akamai, Fastly).
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
            });
        }
    }

    // Trigger 3: Null Byte Padding
    // Detect large blocks of null bytes (0x00) used as padding
    if has_null_block(payload, 32) {
        // ── TLS Padding CDN heuristic (T1001 benign) ───────────────────
        // If null-byte padding is detected on port 443 while communicating
        // with a known CDN (Cloudflare, Akamai, Fastly) AND entropy is
        // consistently high (> 7.9), this is legitimate TLS record padding
        // and should be marked BENIGN.
        if port == 443 && entropy > 7.9 {
            if let Some(cdn_provider) = ctx.and_then(|c| c.sni).and_then(match_cdn_sni) {
                return Some(StegResult {
                    technique_id: "T1001".to_string(),
                    reason: format!(
                        "TLS null-byte padding on port 443 to known CDN '{}' with high entropy ({:.2}) — benign",
                        cdn_provider, entropy,
                    ),
                    observed_entropy: entropy,
                    pattern_type: "Null byte padding".to_string(),
                    is_benign: true,
                    protocol_feature: Some("TLS Padding detected".to_string()),
                    cdn_provider: Some(cdn_provider.to_string()),
                });
            }
        }

        return Some(StegResult {
            technique_id: "T1001".to_string(),
            reason: "Entropy dilution detected".to_string(),
            observed_entropy: entropy,
            pattern_type: "Null byte padding".to_string(),
            is_benign: false,
            protocol_feature: None,
            cdn_provider: None,
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
