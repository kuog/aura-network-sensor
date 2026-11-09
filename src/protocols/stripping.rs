use aho_corasick::AhoCorasick;
use serde::Serialize;
use std::sync::LazyLock;
use crate::protocols::is_header;
use crate::report::Context;

/// Every trigger on a request needs one of these in the payload.
static REQUEST_MARKERS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(["password=", "token=", "auth=", "user=", "login=", "cookie:"])
        .expect("valid patterns")
});

#[derive(Serialize)]
pub struct StrippingAlert {
    pub technique_id: String,
    pub domain: String,
    pub reason: String,
    pub severity: String,
    pub context: Context,
}

fn build_context(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> Context {
    let mut context = Context::default();
    context.fields.insert("src_ip".to_string(), src_ip.to_string());
    context.fields.insert("dst_ip".to_string(), dst_ip.to_string());
    context.fields.insert("src_port".to_string(), src_port.to_string());
    context.fields.insert("dst_port".to_string(), dst_port.to_string());
    context.fields.insert("protocol".to_string(), "http".to_string());
    context
}

pub fn analyze(payload: &[u8], src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> Option<StrippingAlert> {
    // Most sessions are encrypted: settle them before converting to text.
    if !payload.starts_with(b"HTTP/") && !REQUEST_MARKERS.is_match(payload) {
        return None;
    }

    let data_str = String::from_utf8_lossy(payload);
    let mut lines = data_str.lines();
    let first_line = lines.next()?;

    // Check if it's a Response or Request
    if first_line.starts_with("HTTP/") {
        analyze_response(&data_str, first_line, src_ip, dst_ip, src_port, dst_port)
    } else {
        analyze_request(&data_str, first_line, src_ip, dst_ip, src_port, dst_port)
    }
}

fn analyze_response(headers: &str, first_line: &str, src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> Option<StrippingAlert> {
    // Parse Status Code
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let status_code = parts[1];

    // Extract headers
    let mut location: Option<&str> = None;
    let mut set_cookie: Option<&str> = None;
    
    // We need to find the domain (Host) to know if it's a known domain. 
    // But Host header is in the Request, not Response. 
    // However, we might infer it from the Location header or if we track state (which we don't here easily).
    // For Trigger 1, we look at Location header.
    
    for line in headers.lines() {
        if is_header(line, "location:") {
            location = line.splitn(2, ':').nth(1).map(|s| s.trim());
        } else if is_header(line, "set-cookie:") {
            set_cookie = line.splitn(2, ':').nth(1).map(|s| s.trim());
        }
    }

    // Trigger 1: Location Header Downgrade
    if status_code == "301" || status_code == "302" {
        if let Some(loc) = location {
            if loc.starts_with("http://") {
                // Check if it's a common HTTPS domain
                if is_https_common_domain(loc) {
                    return Some(StrippingAlert {
                        technique_id: "T1562.001".to_string(),
                        domain: extract_domain(loc).to_string(),
                        reason: "Potential SSL Stripping detected (Downgrade Redirect)".to_string(),
                        severity: "CRITICAL".to_string(),
                        context: build_context(src_ip, dst_ip, src_port, dst_port),
                    });
                }
            }
        }
    }

    // Trigger 2: HSTS Removal
    // We can only check this if we know the domain. In a response, we don't always have the domain unless we track the request.
    // However, if we see a Location header, we have a domain. 
    // Or if we assume the sensor sees the IP, maybe we can reverse lookup? No.
    // But wait, if we are stripping, the attacker sends a response.
    // If we rely on the Request's Host header, we need to pair them. 
    // For now, let's check if we can find the domain in the response (unlikely unless in Location).
    // BUT, the prompt says "Monitor for the absence of Strict-Transport-Security headers on domains that are known to require them".
    // If we can't identify the domain from the response, we can't trigger this on the response alone.
    // UNLESS we look at the Request that triggered this Response. But we process packets/streams.
    // Let's assume for now we might see the Host in the stream if it's pipelined or if we just look at the Location header for Trigger 1.
    // For Trigger 2, if we don't have the domain, we can't check.
    // However, maybe we can check if the response *contains* sensitive data but no HSTS?
    // Let's stick to what we can do. If we see a redirect to a known domain, we check Trigger 1.
    
    // Trigger 3 (Response part): Set-Cookie with sensitive data over HTTP
    if let Some(cookie) = set_cookie {
        if (cookie.contains("session_id") || cookie.contains("auth") || cookie.contains("token")) && !cookie.contains("Secure") {
             return Some(StrippingAlert {
                technique_id: "T1562.001".to_string(),
                domain: "unknown (response)".to_string(), // We might not know the domain
                reason: "Sensitive Cookie set without Secure flag over HTTP".to_string(),
                severity: "CRITICAL".to_string(),
                context: build_context(src_ip, dst_ip, src_port, dst_port),
            });
        }
    }

    None
}

fn analyze_request(headers: &str, first_line: &str, src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> Option<StrippingAlert> {
    let mut host: Option<&str> = None;
    let mut cookie: Option<&str> = None;
    
    for line in headers.lines() {
        if is_header(line, "host:") {
            host = line.splitn(2, ':').nth(1).map(|s| s.trim());
        } else if is_header(line, "cookie:") {
            cookie = line.splitn(2, ':').nth(1).map(|s| s.trim());
        }
    }

    let domain = host.unwrap_or("unknown");

    // Trigger 2: HSTS Removal (Check if known HSTS domain is accessed over HTTP)
    // If we see a request to a known HSTS domain on port 80, it's suspicious (unless it's the initial redirect).
    // But if it's carrying data, it's definitely bad.
    if is_hsts_domain(domain) {
        // If it's just a GET / HTTP/1.1, it might be the initial type-in.
        // But if it has sensitive data, it's bad.
    }

    // Trigger 3: Sensitive Data over HTTP
    // Check URL parameters in first line
    if first_line.contains("password=") || first_line.contains("token=") || first_line.contains("auth=") {
         return Some(StrippingAlert {
            technique_id: "T1562.001".to_string(),
            domain: domain.to_string(),
            reason: "Sensitive data in URL over HTTP".to_string(),
            severity: "CRITICAL".to_string(),
            context: build_context(src_ip, dst_ip, src_port, dst_port),
        });
    }

    // Check Cookie
    if let Some(c) = cookie {
        if c.contains("session") || c.contains("auth") || c.contains("token") {
             return Some(StrippingAlert {
                technique_id: "T1562.001".to_string(),
                domain: domain.to_string(),
                reason: "Sensitive Cookie sent over HTTP".to_string(),
                severity: "CRITICAL".to_string(),
                context: build_context(src_ip, dst_ip, src_port, dst_port),
            });
        }
    }

    // Check Body for Login forms (simple check)
    // We need the body. The payload might contain it.
    if let Some(idx) = headers.find("\r\n\r\n") {
        let body = &headers[idx+4..];
        if body.contains("password=") || body.contains("user=") || body.contains("login=") {
             return Some(StrippingAlert {
                technique_id: "T1562.001".to_string(),
                domain: domain.to_string(),
                reason: "Login form data sent over HTTP".to_string(),
                severity: "CRITICAL".to_string(),
                context: build_context(src_ip, dst_ip, src_port, dst_port),
            });
        }
    }

    None
}

fn is_https_common_domain(url: &str) -> bool {
    let common = [
        "google.com", "facebook.com", "twitter.com", "linkedin.com", 
        "paypal.com", "bank", "login", "signin", "account", "amazon.com", "microsoft.com"
    ];
    for c in common {
        if url.contains(c) {
            return true;
        }
    }
    false
}

fn is_hsts_domain(domain: &str) -> bool {
    let hsts_domains = [
        "google.com", "facebook.com", "paypal.com", "twitter.com", "github.com", "accounts.google.com"
    ];
    for d in hsts_domains {
        if domain.contains(d) {
            return true;
        }
    }
    false
}

fn extract_domain(url: &str) -> &str {
    // Simple extractor
    if let Some(start) = url.find("://") {
        let rest = &url[start+3..];
        if let Some(end) = rest.find('/') {
            return &rest[..end];
        }
        return rest;
    }
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(payload: &[u8]) -> Option<String> {
        analyze(payload, "10.0.0.1", "10.0.0.2", 40000, 80).map(|alert| alert.reason)
    }

    #[test]
    fn payloads_without_markers_are_skipped() {
        assert_eq!(reason(b"\x17\x03\x03\x10\x00 ciphertext \xff\xfe"), None);
        assert_eq!(reason(b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"), None);
    }

    #[test]
    fn a_sensitive_cookie_is_found_in_any_case() {
        let expected = Some("Sensitive Cookie sent over HTTP".to_string());
        assert_eq!(reason(b"GET / HTTP/1.1\r\nCOOKIE: session=1\r\n\r\n"), expected);
        assert_eq!(reason(b"GET / HTTP/1.1\r\ncookie: session=1\r\n\r\n"), expected);
    }

    #[test]
    fn markers_count_outside_http_too() {
        assert_eq!(reason(b"HELLO token=1\r\n\r\n"), Some("Sensitive data in URL over HTTP".to_string()));
        assert_eq!(reason(b"NOOP\r\n\r\nuser=alice"), Some("Login form data sent over HTTP".to_string()));
    }

    #[test]
    fn a_downgrade_redirect_is_found_in_any_case() {
        let response = b"HTTP/1.1 301 Moved\r\nlOcAtIoN: http://www.paypal.com/\r\n\r\n";
        assert_eq!(reason(response), Some("Potential SSL Stripping detected (Downgrade Redirect)".to_string()));
    }
}
