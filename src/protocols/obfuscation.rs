use crate::telemetry::shannon_entropy;

pub struct StegResult {
    pub technique_id: String,
    pub reason: String,
    pub observed_entropy: f64,
    pub pattern_type: String,
}

pub fn analyze_steganography(payload: &[u8], port: u16) -> Option<StegResult> {
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
            });
        }
    }

    // Trigger 3: Null Byte Padding
    // Detect large blocks of null bytes (0x00) used as padding
    if has_null_block(payload, 32) {
         return Some(StegResult {
                technique_id: "T1001".to_string(),
                reason: "Entropy dilution detected".to_string(),
                observed_entropy: entropy,
                pattern_type: "Null byte padding".to_string(),
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
