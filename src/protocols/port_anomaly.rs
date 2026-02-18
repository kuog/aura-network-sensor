use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PortProfile {
    pub port: u16,
    pub min_entropy: f64,
    pub max_entropy: f64,
    pub allowed_prefixes: Vec<Vec<u8>>,
}

#[derive(Serialize, Debug)]
pub struct PortAnomaly {
    pub technique: String,
    pub port: u16,
    pub observation: String,
    pub severity: String,
}

pub struct ExpectationMatrix {
    profiles: HashMap<u16, PortProfile>,
}

impl ExpectationMatrix {
    pub fn new() -> Self {
        let mut profiles = HashMap::new();

        // Port 80: HTTP
        // Max entropy 6.0, must start with HTTP methods
        profiles.insert(80, PortProfile {
            port: 80,
            min_entropy: 0.0,
            max_entropy: 6.0,
            allowed_prefixes: vec![
                b"GET".to_vec(), b"POST".to_vec(), b"PUT".to_vec(), 
                b"DELETE".to_vec(), b"HEAD".to_vec(), b"OPTIONS".to_vec(), 
                b"CONNECT".to_vec(), b"PATCH".to_vec(), b"HTTP/".to_vec()
            ],
        });

        // Port 443: HTTPS
        // Min entropy 7.0 (should be encrypted)
        profiles.insert(443, PortProfile {
            port: 443,
            min_entropy: 7.0,
            max_entropy: 8.0, // Theoretical max for bytes is 8.0
            allowed_prefixes: vec![],
        });

        // Port 53: DNS
        // Max entropy 5.5 (DNS is usually readable)
        profiles.insert(53, PortProfile {
            port: 53,
            min_entropy: 0.0,
            max_entropy: 5.5,
            allowed_prefixes: vec![],
        });

        // Port 22: SSH
        // Min entropy 7.0, must start with SSH-
        profiles.insert(22, PortProfile {
            port: 22,
            min_entropy: 7.0,
            max_entropy: 8.0,
            allowed_prefixes: vec![b"SSH-".to_vec()],
        });

        Self { profiles }
    }

    pub fn check(&self, port: u16, entropy: f64, payload: &[u8]) -> Option<PortAnomaly> {
        if let Some(profile) = self.profiles.get(&port) {
            // 1. Check Entropy
            if entropy < profile.min_entropy {
                return Some(PortAnomaly {
                    technique: "T1571: Non-Standard Port".to_string(),
                    port,
                    observation: format!("Entropy {:.2} is lower than expected min {:.2} for port {}", entropy, profile.min_entropy, port),
                    severity: "HIGH".to_string(),
                });
            }

            if entropy > profile.max_entropy {
                return Some(PortAnomaly {
                    technique: "T1571: Non-Standard Port".to_string(),
                    port,
                    observation: format!("Entropy {:.2} is higher than expected max {:.2} for port {}", entropy, profile.max_entropy, port),
                    severity: "HIGH".to_string(),
                });
            }

            // 2. Check Prefix (if defined and payload is not empty)
            if !profile.allowed_prefixes.is_empty() && !payload.is_empty() {
                let mut match_found = false;
                for prefix in &profile.allowed_prefixes {
                    if payload.starts_with(prefix) {
                        match_found = true;
                        break;
                    }
                }

                if !match_found {
                    return Some(PortAnomaly {
                        technique: "T1071: Protocol Mismatch".to_string(),
                        port,
                        observation: format!("Payload on port {} does not start with expected protocol signature", port),
                        severity: "MEDIUM".to_string(),
                    });
                }
            }
        }
        
        // Default "Neutral" policy for ports not in matrix
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_80_valid() {
        let matrix = ExpectationMatrix::new();
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let entropy = 4.5; // Typical text entropy
        assert!(matrix.check(80, entropy, payload).is_none());
    }

    #[test]
    fn test_port_80_high_entropy() {
        let matrix = ExpectationMatrix::new();
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let entropy = 7.5; // Too high for HTTP
        let anomaly = matrix.check(80, entropy, payload);
        assert!(anomaly.is_some());
        assert_eq!(anomaly.unwrap().technique, "T1571: Non-Standard Port");
    }

    #[test]
    fn test_port_80_bad_prefix() {
        let matrix = ExpectationMatrix::new();
        let payload = b"\x00\x01\x02\x03"; // Binary data
        let entropy = 4.5;
        let anomaly = matrix.check(80, entropy, payload);
        assert!(anomaly.is_some());
        assert_eq!(anomaly.unwrap().technique, "T1071: Protocol Mismatch");
    }

    #[test]
    fn test_port_443_valid() {
        let matrix = ExpectationMatrix::new();
        let payload = b"\x16\x03\x01..."; // TLS Handshake start
        let entropy = 7.5; // Encrypted
        assert!(matrix.check(443, entropy, payload).is_none());
    }

    #[test]
    fn test_port_443_low_entropy() {
        let matrix = ExpectationMatrix::new();
        let payload = b"GET / HTTP/1.1..."; // Cleartext HTTP on 443
        let entropy = 4.5;
        let anomaly = matrix.check(443, entropy, payload);
        assert!(anomaly.is_some());
        assert_eq!(anomaly.unwrap().technique, "T1571: Non-Standard Port");
    }

    #[test]
    fn test_unknown_port() {
        let matrix = ExpectationMatrix::new();
        let payload = b"whatever";
        let entropy = 5.0;
        assert!(matrix.check(9999, entropy, payload).is_none());
    }
}

