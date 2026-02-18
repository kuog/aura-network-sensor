use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ArpAlert {
    pub victim_ip: IpAddr,
    pub attacker_mac: String,
    pub real_mac: String,
    pub technique_id: String,
    pub message: String,
    pub alert_type: String,
}

pub struct ArpTracker {
    // IP -> MAC (Authoritative)
    ip_mac_map: HashMap<IpAddr, [u8; 6]>,
    // IP -> Timestamp of last request (to detect unsolicited replies)
    pending_requests: HashMap<IpAddr, Instant>,
}

impl ArpTracker {
    pub fn new() -> Self {
        ArpTracker {
            ip_mac_map: HashMap::new(),
            pending_requests: HashMap::new(),
        }
    }

    pub fn handle_packet(&mut self, 
                         sender_mac: [u8; 6], 
                         sender_ip: IpAddr, 
                         _target_mac: [u8; 6], 
                         target_ip: IpAddr, 
                         opcode: u16) -> Option<ArpAlert> {
        
        // Opcode 1: Request
        if opcode == 1 {
            // Record that we saw a request for target_ip
            self.pending_requests.insert(target_ip, Instant::now());
            
            // TOFU for sender
            self.update_mapping(sender_ip, sender_mac);
            return None;
        }
        
        // Opcode 2: Reply
        if opcode == 2 {
            let mut alert = None;

            // Trigger 1: Conflict
            if let Some(known_mac) = self.ip_mac_map.get(&sender_ip) {
                if *known_mac != sender_mac {
                    return Some(ArpAlert {
                        victim_ip: sender_ip,
                        attacker_mac: mac_to_string(sender_mac),
                        real_mac: mac_to_string(*known_mac),
                        technique_id: "T1557".to_string(),
                        message: format!("ARP Spoofing detected: IP {} is claimed by {} but known as {}", sender_ip, mac_to_string(sender_mac), mac_to_string(*known_mac)),
                        alert_type: "Conflict".to_string(),
                    });
                }
            } else {
                // TOFU: Trust on First Use
                self.ip_mac_map.insert(sender_ip, sender_mac);
            }

            // Trigger 2: Gratuitous ARP (Unsolicited Reply)
            // Check if we saw a request for this IP recently
            let is_unsolicited = match self.pending_requests.get(&sender_ip) {
                Some(timestamp) => {
                    if timestamp.elapsed() > Duration::from_secs(5) {
                        true // Request too old
                    } else {
                        false // Found recent request
                    }
                },
                None => true,
            };

            if is_unsolicited {
                 // If we haven't alerted yet
                 if alert.is_none() {
                     let real_mac = self.ip_mac_map.get(&sender_ip).map(|m| mac_to_string(*m)).unwrap_or_else(|| "Unknown".to_string());
                     alert = Some(ArpAlert {
                        victim_ip: sender_ip,
                        attacker_mac: mac_to_string(sender_mac),
                        real_mac,
                        technique_id: "T1557".to_string(),
                        message: format!("Gratuitous ARP Reply detected for IP {}", sender_ip),
                        alert_type: "Gratuitous".to_string(),
                     });
                 }
            }
            
            // Remove the pending request since it's answered
            self.pending_requests.remove(&sender_ip);
            
            return alert;
        }

        None
    }

    fn update_mapping(&mut self, ip: IpAddr, mac: [u8; 6]) {
        self.ip_mac_map.entry(ip).or_insert(mac);
    }
}

pub fn mac_to_string(mac: [u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

pub fn parse_arp(payload: &[u8]) -> Option<(u16, [u8; 6], IpAddr, [u8; 6], IpAddr)> {
    // Basic ARP parsing for IPv4 over Ethernet
    // HW Type (2), Proto (2), HW Len (1), Proto Len (1), Opcode (2), Sender MAC (6), Sender IP (4), Target MAC (6), Target IP (4)
    if payload.len() < 28 {
        return None;
    }

    let hw_type = u16::from_be_bytes([payload[0], payload[1]]);
    let proto_type = u16::from_be_bytes([payload[2], payload[3]]);
    let hw_len = payload[4];
    let proto_len = payload[5];
    let opcode = u16::from_be_bytes([payload[6], payload[7]]);

    // Ethernet (1) and IPv4 (0x0800)
    if hw_type != 1 || proto_type != 0x0800 || hw_len != 6 || proto_len != 4 {
        return None;
    }

    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&payload[8..14]);

    let sender_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]));

    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&payload[18..24]);

    let target_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]));

    Some((opcode, sender_mac, sender_ip, target_mac, target_ip))
}
