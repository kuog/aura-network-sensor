use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::Serialize;
use crate::report::Context;

#[derive(Serialize, Debug)]
pub struct SmbAnomaly {
    pub technique_id: String,
    pub accessed_path: String,
    pub anomaly_type: String,
    pub severity: String,
    pub context: Context,
}

pub struct SmbTracker {
    // Tracking for enumeration: IP -> (Count, WindowStart)
    enum_tracker: HashMap<String, (u32, Instant)>,
    // Tracking for volume: IP -> (Bytes, WindowStart)
    volume_tracker: HashMap<String, (u64, Instant)>,
}

impl SmbTracker {
    pub fn new() -> Self {
        Self {
            enum_tracker: HashMap::new(),
            volume_tracker: HashMap::new(),
        }
    }

    pub fn analyze_smb(
        &mut self,
        payload: &[u8],
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<SmbAnomaly> {
        let mut anomalies = Vec::new();

        // Check for NetBIOS header (4 bytes) + SMB2 Header
        let smb_start = if payload.len() > 4 && &payload[4..8] == b"\xFESMB" {
            4
        } else if payload.len() >= 4 && &payload[0..4] == b"\xFESMB" {
            0
        } else {
            return anomalies;
        };

        let smb_payload = &payload[smb_start..];

        // Parse Header
        if smb_payload.len() < 64 {
            return anomalies;
        }

        let command = u16::from_le_bytes([smb_payload[12], smb_payload[13]]);
        let flags = u32::from_le_bytes([
            smb_payload[16],
            smb_payload[17],
            smb_payload[18],
            smb_payload[19],
        ]);

        // Check if Request (Bit 0 of Flags is 0 for Request in SMB2? 
        // Actually: 0x00000001 is SMB2_FLAGS_SERVER_TO_REDIR. 
        // So if bit 0 is set, it's a response. We want requests (bit 0 clear).
        if (flags & 0x00000001) != 0 {
            // It's a response
        } else {
            // It is a Request
            
            // Trigger 1: Share Enumeration (Tree Connect 0x0003 or Query Directory 0x000E)
            if command == 0x0003 || command == 0x000E {
                self.check_enumeration(src_ip, &mut anomalies, src_ip, dst_ip, src_port, dst_port);
            }

            // Trigger 2: Sensitive File Access (Create 0x0005)
            if command == 0x0005 {
                self.check_sensitive_file(smb_payload, &mut anomalies, src_ip, dst_ip, src_port, dst_port);
            }

            // Trigger 3: Large File Transfers (Read 0x0008)
            if command == 0x0008 {
                self.check_large_transfer(smb_payload, &mut anomalies, src_ip, dst_ip, src_port, dst_port);
            }
        }

        anomalies
    }

    fn check_enumeration(
        &mut self,
        key: &str,
        anomalies: &mut Vec<SmbAnomaly>,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
    ) {
        let now = Instant::now();
        let entry = self.enum_tracker.entry(key.to_string()).or_insert((0, now));

        // Reset if window passed (e.g., 5 seconds)
        if now.duration_since(entry.1) > Duration::from_secs(5) {
            entry.0 = 0;
            entry.1 = now;
        }

        entry.0 += 1;

        // Threshold: e.g., 10 requests in 5 seconds
        if entry.0 == 10 {
            anomalies.push(SmbAnomaly {
                technique_id: "T1039".to_string(),
                accessed_path: "MULTIPLE".to_string(),
                anomaly_type: "Mass Enumeration (Share Crawling)".to_string(),
                severity: "HIGH".to_string(),
                context: build_context(src_ip, dst_ip, src_port, dst_port),
            });
        }
    }

    fn check_sensitive_file(
        &self,
        payload: &[u8],
        anomalies: &mut Vec<SmbAnomaly>,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
    ) {
        // Parse SMB2 Create Request to get filename
        // Header is 64 bytes.
        // StructureSize (2 bytes) at offset 64.
        // NameOffset (2 bytes) at offset 64 + 4 = 68.
        // NameLength (2 bytes) at offset 64 + 6 = 70.
        
        if payload.len() < 72 {
            return;
        }

        let name_offset = u16::from_le_bytes([payload[68], payload[69]]) as usize;
        let name_len = u16::from_le_bytes([payload[70], payload[71]]) as usize;

        if name_offset + name_len > payload.len() {
            return;
        }

        let name_bytes = &payload[name_offset..name_offset + name_len];
        // SMB2 names are UTF-16LE
        let name_string = String::from_utf16_lossy(
            &name_bytes
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<u16>>(),
        );

        let lower_name = name_string.to_lowercase();
        let keywords = ["password", "config", "wallet", "backup", "secret", ".kdbx"];

        for keyword in keywords.iter() {
            if lower_name.contains(keyword) {
                anomalies.push(SmbAnomaly {
                    technique_id: "T1039".to_string(),
                    accessed_path: name_string.clone(),
                    anomaly_type: "Sensitive File Access".to_string(),
                    severity: "HIGH".to_string(),
                    context: build_context(src_ip, dst_ip, src_port, dst_port),
                });
                break; 
            }
        }
    }

    fn check_large_transfer(
        &mut self,
        payload: &[u8],
        anomalies: &mut Vec<SmbAnomaly>,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
    ) {
        // SMB2 Read Request
        // Header 64 bytes.
        // StructureSize (2 bytes) at 64.
        // Padding (1 byte).
        // Flags (1 byte).
        // Length (4 bytes) at offset 68.
        
        if payload.len() < 72 {
            return;
        }

        let length = u32::from_le_bytes([
            payload[68],
            payload[69],
            payload[70],
            payload[71],
        ]) as u64;

        let now = Instant::now();
        let entry = self.volume_tracker.entry(src_ip.to_string()).or_insert((0, now));

        // Reset if window passed (e.g., 60 seconds)
        if now.duration_since(entry.1) > Duration::from_secs(60) {
            entry.0 = 0;
            entry.1 = now;
        }

        entry.0 += length;

        // Threshold: e.g., 100 MB in 60 seconds
        // 100 MB = 100 * 1024 * 1024 = 104,857,600 bytes
        if entry.0 > 104_857_600 {
             // Only trigger once per window reset to avoid spam? 
             // Or we can just let it trigger.
             // To avoid spam, we could check if it was already above threshold before adding.
             if entry.0 - length <= 104_857_600 {
                anomalies.push(SmbAnomaly {
                    technique_id: "T1039".to_string(),
                    accessed_path: "High Volume Data".to_string(),
                    anomaly_type: "Large File Transfer (Potential Exfiltration)".to_string(),
                    severity: "HIGH".to_string(),
                    context: build_context(src_ip, dst_ip, src_port, dst_port),
                });
             }
        }
    }
}

fn build_context(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> Context {
    let mut context = Context::default();
    context.fields.insert("src_ip".to_string(), src_ip.to_string());
    context.fields.insert("dst_ip".to_string(), dst_ip.to_string());
    context.fields.insert("src_port".to_string(), src_port.to_string());
    context.fields.insert("dst_port".to_string(), dst_port.to_string());
    context.fields.insert("protocol".to_string(), "smb".to_string());
    context
}
