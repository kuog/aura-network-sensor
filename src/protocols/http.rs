// src/protocols/http.rs
use serde::Serialize;
use crate::protocols::is_header;
use crate::report::Context;

#[derive(Serialize)]
pub struct HttpAnomalyReport {
    pub context: Context,
    pub technique: &'static str,
    pub suspicious_header: String,
    pub reason: &'static str,
}

fn build_context(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> Context {
    let mut context = Context::default();
    context.fields.insert("src_ip".to_string(), src_ip.to_string());
    context.fields.insert("dst_ip".to_string(), dst_ip.to_string());
    context.fields.insert("src_port".to_string(), src_port.to_string());
    context.fields.insert("dst_port".to_string(), dst_port.to_string());
    context
}

fn is_whitelisted(host: &str) -> bool {
    let whitelist = ["google.com", "apple.com", "microsoft.com"];
    for domain in whitelist {
        if host.contains(domain) {
            return true;
        }
    }
    false
}

/// Whether `payload` can start with an HTTP method. Checked before converting
/// the payload to text: most sessions are encrypted and fail on the first byte.
/// The method may follow whitespace, Unicode whitespace included.
fn may_start_with_http_method(payload: &[u8]) -> bool {
    payload.first().is_some_and(|byte| {
        matches!(
            byte,
            b'G' | b'P' | b'D' | b'H' | b'O' | b'C' | b'T' | b'\t'..=b'\r' | b' ' | 0xC2 | 0xE1 | 0xE2 | 0xE3
        )
    })
}

pub fn analyze_http(payload: &[u8], src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> Option<HttpAnomalyReport> {
    if !may_start_with_http_method(payload) {
        return None;
    }

    let headers_str = String::from_utf8_lossy(payload);
    let mut lines = headers_str.lines();
    
    // 1. Parse Method from first line
    let first_line = lines.next()?;
    let method = first_line.split_whitespace().next().unwrap_or("");
    
    // Validate Method to avoid False Positives on non-HTTP traffic (e.g., encrypted HTTPS)
    let valid_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE", "PATCH"];
    if !valid_methods.contains(&method) {
        return None;
    }
    
    // 2. Check Host header for whitelist
    let host_line = headers_str.lines().find(|l| is_header(l, "host:"));
    if let Some(line) = host_line {
        let host = line.splitn(2, ':').nth(1).unwrap_or("").trim();
        if is_whitelisted(host) {
            return None;
        }
    }
    
    // 3. User-Agent check
    let ua_line = headers_str.lines().find(|l| is_header(l, "user-agent:"));

    match ua_line {
        Some(line) => {
            // Extract the value part
            let agent = line.splitn(2, ':').nth(1).unwrap_or("").trim();
            
            // 1. Check for empty User-Agent (T1071.001)
            if agent.is_empty() {
                 return Some(HttpAnomalyReport {
                    context: build_context(src_ip, dst_ip, src_port, dst_port),
                    technique: "T1071.001",
                    suspicious_header: "User-Agent: <EMPTY>".to_string(),
                    reason: "Empty User-Agent header (highly suspicious)",
                });
            }

            // 2. Check against known suspicious patterns (Top 100)
            if let Some((technique, suspicious_header, reason)) = analyze_http_agent(agent) {
                return Some(HttpAnomalyReport {
                    context: build_context(src_ip, dst_ip, src_port, dst_port),
                    technique,
                    suspicious_header,
                    reason,
                });
            }

            // 3. Check for very short/weird User-Agent (Evasion technique)
            if agent.len() < 10 {
                 return Some(HttpAnomalyReport {
                    context: build_context(src_ip, dst_ip, src_port, dst_port),
                    technique: "T1071.001",
                    suspicious_header: format!("User-Agent: {}", agent),
                    reason: "Unusually short User-Agent header (often used by malware)",
                });
            }
        },
        None => {
            // If method is CONNECT, suppress missing UA alert
            if method == "CONNECT" {
                return None;
            }

            // Missing User-Agent is also suspicious for HTTP clients, 
            // but might be common for some API calls. However, for malware detection, it's a good signal.
             return Some(HttpAnomalyReport {
                context: build_context(src_ip, dst_ip, src_port, dst_port),
                technique: "T1071.001",
                suspicious_header: "User-Agent: <MISSING>".to_string(),
                reason: "Missing User-Agent header (common in malware)",
            });
        }
    }

    None
}

fn analyze_http_agent(user_agent: &str) -> Option<(&'static str, String, &'static str)> {
    // Top suspicious patterns categorized
    let patterns = [
        // 1. Offensive Security Tools
        ("sqlmap", "T1505: SQL Injection tool"),
        ("nmap", "T1595: Active Scanning"),
        ("Nikto", "T1595: Vulnerability Scanning"),
        ("DirBuster", "T1595: Directory Brute Force"),
        ("Gobuster", "T1595: Directory Brute Force"),
        ("Wfuzz", "T1595: Web Fuzzing"),
        ("ZAP", "T1595: OWASP ZAP Scanner"),
        ("BurpSuite", "T1595: Web Proxy/Scanner"),
        ("Metasploit", "T1071.001: Metasploit Framework"),
        ("Empire", "T1071.001: Empire C2"),
        ("Havoc", "T1071.001: Havoc C2"),
        ("CobaltStrike", "T1071.001: Cobalt Strike C2"),
        ("Sliver", "T1071.001: Sliver C2"),
        ("Merlin", "T1071.001: Merlin C2"),
        
        // 2. Common Library Agents
        ("python-requests", "T1071: Scripted communication (Python)"),
        ("Python-urllib", "T1071: Scripted communication (Python)"),
        ("aiohttp", "T1071: Scripted communication (Python)"),
        ("Go-http-client", "T1071: Scripted communication (Go)"),
        ("Resty", "T1071: Scripted communication (Go)"),
        ("Java/1.8.0", "T1071: Scripted communication (Java)"),
        ("Apache-HttpClient", "T1071: Scripted communication (Java)"),
        ("WebClient", "T1071: Scripted communication (.NET)"), 
        
        // 3. Suspiciously Short or Generic
        ("Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) WindowsPowerShell/5.1", "T1059.001: PowerShell Web Client"),
        
        // 4. Admin & Cloud Tools
        ("rclone", "T1567.002: Exfiltration to Cloud Storage"),
        ("aws-cli", "T1071: Cloud CLI Tool"),
        ("azcopy", "T1567.002: Azure Copy Tool"),
        ("gsutil", "T1567.002: Google Cloud Storage Util"),
        ("Wget", "T1105: Ingress Tool Transfer"),
        ("curl", "T1105: Ingress Tool Transfer"),
        ("Powershell", "T1059.001: PowerShell Execution"),
        ("WinHttp.WinHttpRequest", "T1071: Windows HTTP Services (often used by malware)"),
    ];

    for (pattern, reason) in patterns {
        if user_agent.contains(pattern) {
            return Some((
                "T1071.001",
                format!("User-Agent: {}", user_agent),
                reason,
            ));
        }
    }
    
    // Special check for "Mozilla/5.0" exact match (common C2 evasion)
    if user_agent == "Mozilla/5.0" {
         return Some((
            "T1071.001",
            format!("User-Agent: {}", user_agent),
            "Generic User-Agent (often used by C2)",
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(payload: &[u8]) -> Option<HttpAnomalyReport> {
        analyze_http(payload, "10.0.0.1", "10.0.0.2", 40000, 80)
    }

    #[test]
    fn encrypted_payloads_are_not_http() {
        assert!(analyze(b"").is_none());
        assert!(analyze(b"\x16\x03\x01\x02\x00\x01 record").is_none());
    }

    #[test]
    fn a_method_after_whitespace_is_still_a_request() {
        for prefix in ["\t", " ", "\u{0b}", "\u{85}", "\u{a0}", "\u{1680}", "\u{2003}", "\u{205f}", "\u{3000}"] {
            let request = format!("{prefix}GET / HTTP/1.1\r\nHost: example.org\r\n\r\n");
            assert!(analyze(request.as_bytes()).is_some(), "prefix {prefix:?}");
        }
    }

    #[test]
    fn header_names_are_case_insensitive() {
        assert!(analyze(b"GET / HTTP/1.1\r\nHOST: www.google.com\r\n\r\n").is_none());
        let report = analyze(b"GET / HTTP/1.1\r\nuSeR-aGeNt: sqlmap/1.7\r\n\r\n").expect("suspicious agent");
        assert_eq!(report.reason, "T1505: SQL Injection tool");
    }
}
