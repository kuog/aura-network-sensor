pub mod l3_defrag;
pub mod l4_reassembly;
pub mod telemetry;
pub mod protocols;
pub mod report;

use pcap::Capture;
use etherparse::{PacketHeaders, NetHeaders, TransportHeader, LinkHeader, VlanHeader};
use l3_defrag::Defragmenter;
use l4_reassembly::Reassembler;
use crate::protocols::dns;
use crate::protocols::scan::ScannerTracker;
use crate::protocols::arp::{ArpTracker, parse_arp};
use crate::protocols::shell;
use std::time::Duration;
use crate::report::{AiHint, Context, Report, Telemetry};

fn is_local_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12
            (octets[0] == 10) ||
            (octets[0] == 192 && octets[1] == 168) ||
            (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
        },
        _ => false, 
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: cargo run -- <path_to_pcap>");
        return;
    }

    let mut defrag = Defragmenter::new();
    // Increase capacity for real-world traffic
    let mut tcp_reassembler = Reassembler::new(10000); 
    let matrix = protocols::port_anomaly::ExpectationMatrix::new();
    let mut scanner_tracker = ScannerTracker::new(Duration::from_secs(60));
    let mut arp_tracker = ArpTracker::new();
    let mut smb_tracker = protocols::smb::SmbTracker::new();
    
    let mut cap = Capture::from_file(&args[1]).expect("Failed to open PCAP file");

    println!("--- AI Sensor Analysis Started ---");

    while let Ok(packet) = cap.next_packet() {
        // Extract timestamp from pcap header
        let ts = packet.header.ts.tv_sec as f64 + (packet.header.ts.tv_usec as f64 / 1_000_000.0);

        if let Ok(headers) = PacketHeaders::from_ethernet_slice(packet.data) {
            
            let mut is_arp = false;
            
            if let Some(LinkHeader::Ethernet2(ether)) = &headers.link {
                if ether.ether_type.0 == 0x0806 {
                    is_arp = true;
                }
            }

            if let Some(vlan) = headers.vlan() {
                match vlan {
                    VlanHeader::Single(single) => {
                        if single.ether_type.0 == 0x0806 {
                            is_arp = true;
                        }
                    },
                    VlanHeader::Double(double) => {
                        if double.inner.ether_type.0 == 0x0806 {
                            is_arp = true;
                        }
                    }
                }
            }

            if is_arp {
                // Calculate offset manually as fallback if payload is empty
                let payload = if headers.payload.slice().len() > 0 {
                    headers.payload.slice()
                } else {
                    let mut offset = 14; // Ethernet header
                    if let Some(vlan) = headers.vlan() {
                        match vlan {
                            VlanHeader::Single(_) => offset += 4,
                            VlanHeader::Double(_) => offset += 8,
                        }
                    }
                    if packet.data.len() > offset {
                        &packet.data[offset..]
                    } else {
                        &[]
                    }
                };

                if let Some((opcode, sender_mac, sender_ip, target_mac, target_ip)) = parse_arp(payload) {
                    if let Some(alert) = arp_tracker.handle_packet(sender_mac, sender_ip, target_mac, target_ip, opcode) {
                        println!("{}", serde_json::to_string_pretty(&alert).unwrap());
                    }
                }
            }

            if let Some(NetHeaders::Ipv4(ip_hdr, _)) = headers.net {
                // T1046 Scanning Detection
                let scan_src = std::net::IpAddr::V4(ip_hdr.source.into());
                let scan_dst = std::net::IpAddr::V4(ip_hdr.destination.into());
                
                if is_local_ip(&scan_src) {
                     match &headers.transport {
                        Some(TransportHeader::Tcp(tcp)) => {
                            if tcp.syn && !tcp.ack {
                                if let Some(alert) = scanner_tracker.update(scan_src, scan_dst, tcp.destination_port) {
                                    println!("{}", serde_json::to_string_pretty(&alert).unwrap());
                                }
                            }
                        },
                        Some(TransportHeader::Udp(udp)) => {
                            if let Some(alert) = scanner_tracker.update(scan_src, scan_dst, udp.destination_port) {
                                println!("{}", serde_json::to_string_pretty(&alert).unwrap());
                            }
                        },
                        _ => {}
                    }
                }

                // Determine the L4 payload (the data after IP header)
                // Etherparse headers.payload is the raw slice after IP
                let ip_payload_bytes = headers.payload.slice();

                if let Some(full_ip_payload) = defrag.process(&ip_hdr, ip_payload_bytes) {
                    
                    let src_ip = std::net::IpAddr::V4(ip_hdr.source.into());
                    let dst_ip = std::net::IpAddr::V4(ip_hdr.destination.into());

                    match headers.transport {
                        Some(TransportHeader::Tcp(tcp)) => {
                            // SKIP analysis for standard HTTPS to avoid False Positives
                            // if tcp.destination_port == 443 || tcp.source_port == 443 {
                            //    continue;
                            // }

                            // Determine direction for stats
                            let is_upload = is_local_ip(&src_ip);
                            let packet_len = full_ip_payload.len() as u64;

                            // Update stats and check for Exfiltration
                            if let Some((up, down, ratio)) = tcp_reassembler.update_stats(src_ip, dst_ip, tcp.source_port, tcp.destination_port, packet_len, is_upload) {
                                let mut context = Context::default();
                                context.fields.insert("src_ip".to_string(), src_ip.to_string());
                                context.fields.insert("dst_ip".to_string(), dst_ip.to_string());
                                context.fields.insert("src_port".to_string(), tcp.source_port.to_string());
                                context.fields.insert("dst_port".to_string(), tcp.destination_port.to_string());
                                context.fields.insert("protocol".to_string(), "tcp".to_string());
                                context.fields.insert("total_uploaded_mb".to_string(), format!("{:.2}", up as f64 / 1_000_000.0));
                                context.fields.insert("total_downloaded_mb".to_string(), format!("{:.2}", down as f64 / 1_000_000.0));
                                context.fields.insert("ratio".to_string(), format!("{:.2}", ratio));

                                let telemetry = Telemetry {
                                    entropy: None,
                                    jitter: None,
                                    ja3: None,
                                };

                                let ai_hint = AiHint {
                                    trigger: "exfiltration".to_string(),
                                    suspected_techniques: vec!["T1041".to_string()],
                                    logic: "Asymmetric outbound flow detected".to_string(),
                                };

                                let report = Report::new(context, telemetry, vec![ai_hint]);
                                println!("{}", serde_json::to_string_pretty(&report).unwrap());
                            }

                            // We need to strip the TCP header from the reassembled IP payload
                            // before adding it to the stream buffer
                            let tcp_data_offset = tcp.header_len() as usize;
                            if full_ip_payload.len() > tcp_data_offset {
                                let app_data = &full_ip_payload[tcp_data_offset..];
                                
                                if let Some((session_data, b_score)) = tcp_reassembler.add_segment(src_ip, dst_ip, tcp.source_port, tcp.destination_port, app_data, ts) {
                                    
                                    let entropy = telemetry::shannon_entropy(&session_data);
                                    let port = tcp.destination_port;

                                    // T1059 Interactive Shell Detection
                                    if let Some(shell_alert) = shell::detect_interactive_shell(&session_data) {
                                        println!("{}", serde_json::to_string_pretty(&shell_alert).unwrap());
                                    }

                                    // Check for Port Misuse (T1571) using the Matrix
                                    if let Some(anomaly) = matrix.check(port, entropy, &session_data) {
                                        let mut context = Context::default();
                                        context.fields.insert("src_ip".to_string(), src_ip.to_string());
                                        context.fields.insert("dst_ip".to_string(), dst_ip.to_string());
                                        context.fields.insert("src_port".to_string(), tcp.source_port.to_string());
                                        context.fields.insert("dst_port".to_string(), tcp.destination_port.to_string());
                                        context.fields.insert("protocol".to_string(), "tcp".to_string());

                                        let telemetry = Telemetry {
                                            entropy: Some((entropy * 100.0).round() / 100.0),
                                            jitter: Some((b_score * 100.0).round() / 100.0),
                                            ja3: None,
                                        };

                                        let ai_hint = AiHint {
                                            trigger: "port_anomaly".to_string(),
                                            suspected_techniques: vec![anomaly.technique.clone()],
                                            logic: anomaly.observation,
                                        };

                                        let report = Report::new(context, telemetry, vec![ai_hint]);
                                        println!("{}", serde_json::to_string_pretty(&report).unwrap());
                                    }

                                    // T1001 Obfuscation / Steganography Check
                                    if let Some(steg) = protocols::obfuscation::analyze_steganography(&session_data, port) {
                                        let mut context = Context::default();
                                        context.fields.insert("src_ip".to_string(), src_ip.to_string());
                                        context.fields.insert("dst_ip".to_string(), dst_ip.to_string());
                                        context.fields.insert("src_port".to_string(), tcp.source_port.to_string());
                                        context.fields.insert("dst_port".to_string(), tcp.destination_port.to_string());
                                        context.fields.insert("protocol".to_string(), "tcp".to_string());
                                        context.fields.insert("pattern_type".to_string(), steg.pattern_type);

                                        let telemetry = Telemetry {
                                            entropy: Some((steg.observed_entropy * 100.0).round() / 100.0),
                                            jitter: Some((b_score * 100.0).round() / 100.0),
                                            ja3: None,
                                        };

                                        let ai_hint = AiHint {
                                            trigger: "obfuscation_detected".to_string(),
                                            suspected_techniques: vec![steg.technique_id],
                                            logic: steg.reason,
                                        };

                                        let report = Report::new(context, telemetry, vec![ai_hint]);
                                        println!("{}", serde_json::to_string_pretty(&report).unwrap());
                                    }

                                    // T1039 SMB/RPC Anomaly Detection
                                    if tcp.source_port == 445 || tcp.destination_port == 445 {
                                        let anomalies = smb_tracker.analyze_smb(&session_data, &src_ip.to_string(), &dst_ip.to_string(), tcp.source_port, tcp.destination_port);
                                        for anomaly in anomalies {
                                            println!("{}", serde_json::to_string_pretty(&anomaly).unwrap());
                                        }
                                    }

                                    // 1. Analyze for HTTP anomalies
                                    if let Some(http_report) = protocols::http::analyze_http(&session_data, &src_ip.to_string(), &dst_ip.to_string(), tcp.source_port, tcp.destination_port) {
                                         println!("{}", serde_json::to_string_pretty(&http_report).unwrap());
                                    }

                                    // 2. Analyze for SSL Stripping (T1562.001)
                                    if let Some(stripping_alert) = protocols::stripping::analyze(&session_data, &src_ip.to_string(), &dst_ip.to_string(), tcp.source_port, tcp.destination_port) {
                                         println!("{}", serde_json::to_string_pretty(&stripping_alert).unwrap());
                                    }

                                    // 3. Beaconing check (Timing)
                                    if b_score < 0.15 {
                                        println!("BEACON DETECTED: T1011 | Score: {:.2}", b_score);
                                    }
                                    
                                    // Check for TLS JA3
                                    let mut ja3_hash_str = None;
                                    if let Some(ja3_hash) = protocols::tls::calculate_ja3(&session_data) {
                                        println!("TLS FINGERPRINT (JA3): {}", ja3_hash);
                                        
                                        // MITRE T1011 Hint:
                                        // Many C2 agents have fixed JA3 hashes. 
                                        // e.g., "a0e9f5d64349fb12a91c..." is a known Meterpreter hash.
                                        if ja3_hash == "a0e9f5d64349fb12a91c13d332612953" {
                                            println!("ALERT: Known Malware JA3 detected! (T1573.002)");
                                        }
                                        ja3_hash_str = Some(ja3_hash);
                                    }

                                    let ent = entropy;
                                     
                                    let is_standard_tls = [443, 8443, 465].contains(&tcp.source_port) || [443, 8443, 465].contains(&tcp.destination_port);
                                    let high_entropy_trigger = ent > 7.5 && !is_standard_tls;

                                    // Threshold for non-standard encrypted tunnels
                                    if high_entropy_trigger || ja3_hash_str.is_some() || b_score < 0.15 {
                                        let mut context = Context::default();
                                        context.fields.insert("src_ip".to_string(), src_ip.to_string());
                                        context.fields.insert("dst_ip".to_string(), dst_ip.to_string());
                                        context.fields.insert("src_port".to_string(), tcp.source_port.to_string());
                                        context.fields.insert("dst_port".to_string(), tcp.destination_port.to_string());
                                        context.fields.insert("protocol".to_string(), "tcp".to_string());

                                        let telemetry = Telemetry {
                                            entropy: Some((ent * 100.0).round() / 100.0),
                                            jitter: Some((b_score * 100.0).round() / 100.0),
                                            ja3: ja3_hash_str,
                                        };

                                        let mut ai_hints = Vec::new();
                                        if high_entropy_trigger {
                                            ai_hints.push(AiHint {
                                                trigger: "high_entropy".to_string(),
                                                suspected_techniques: vec!["T1573".to_string()],
                                                logic: "Encrypted payload on non-standard port".to_string(),
                                            });
                                        }
                                        
                                        if b_score < 0.15 {
                                            ai_hints.push(AiHint {
                                                trigger: "beaconing".to_string(),
                                                suspected_techniques: vec!["T1011".to_string()],
                                                logic: "Periodic communication detected".to_string(),
                                            });
                                        }

                                        let report = Report::new(context, telemetry, ai_hints);
                                        println!("{}", serde_json::to_string_pretty(&report).unwrap());
                                    }
                                }
                            }
                        }
                        Some(TransportHeader::Udp(udp)) => {
                            if udp.destination_port == 53 || udp.source_port == 53 {
                                let udp_data_offset = 8; // UDP header is always 8 bytes
                                if full_ip_payload.len() > udp_data_offset {
                                    let dns_data = &full_ip_payload[udp_data_offset..];
                                    if let Some(report) = dns::analyze_dns(dns_data) {
                                        println!("{}", serde_json::to_string_pretty(&report).unwrap());
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
