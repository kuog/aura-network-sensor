use serde::Serialize;

#[derive(Serialize)]
pub struct PortAnomaly {
    pub technique: &'static str,
    pub port: u16,
    pub observation: String,
    pub severity: &'static str,
}

pub fn check_port_misuse(port: u16, entropy: f64, app_data: &[u8]) -> Option<PortAnomaly> {
    // 1. Encrypted traffic on cleartext ports (T1571)
    if (port == 80 || port == 8080 || port == 21) && entropy > 6.5 {
        return Some(PortAnomaly {
            technique: "T1571: Non-Standard Port",
            port,
            observation: "High entropy (encrypted) data on a typically plaintext port".to_string(),
            severity: "HIGH",
        });
    }

    // 2. Protocol Mismatch (T1071)
    // If it's port 80 but doesn't start with HTTP methods
    if port == 80 && !app_data.is_empty() {
        let methods: &[&[u8]] = &[b"GET", b"POST", b"PUT", b"DELETE", b"CONNECT", b"HEAD", b"OPTIONS", b"PATCH"];
        // Check if it starts with any known HTTP method
        // We need to be careful about partial packets, but usually the first packet has the method.
        // Let's check if any method matches the start of app_data
        let is_http_req = methods.iter().any(|&m| app_data.starts_with(m));
        
        if !is_http_req {
             // It might be a response (HTTP/1.1 200 OK), so check for "HTTP/"
            if !app_data.starts_with(b"HTTP/") {
                return Some(PortAnomaly {
                    technique: "T1071: Protocol Mismatch",
                    port,
                    observation: "Traffic on port 80 does not look like HTTP".to_string(),
                    severity: "MEDIUM",
                });
            }
        }
    }

    None
}
