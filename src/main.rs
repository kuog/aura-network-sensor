pub mod l3_defrag;
pub mod l4_reassembly;
pub mod telemetry;
pub mod protocols;
pub mod report;

use pcap::Capture;
use etherparse::{PacketHeaders, NetHeaders, TransportHeader};
use l3_defrag::Defragmenter;
use l4_reassembly::{Reassembler, FlowKey};
use crate::protocols::dns;
use crate::report::{AiHint, Context, Report, Telemetry};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: cargo run -- <path_to_pcap>");
        return;
    }

    let mut defrag = Defragmenter::new();
    // Increase capacity for real-world traffic
    let mut tcp_reassembler = Reassembler::new(10000); 
    
    let mut cap = Capture::from_file(&args[1]).expect("Failed to open PCAP file");

    println!("--- AI Sensor Analysis Started ---");

    while let Ok(packet) = cap.next_packet() {
        // Extract timestamp from pcap header
        let ts = packet.header.ts.tv_sec as f64 + (packet.header.ts.tv_usec as f64 / 1_000_000.0);

        if let Ok(headers) = PacketHeaders::from_ethernet_slice(packet.data) {
            
            if let Some(NetHeaders::Ipv4(ip_hdr, _)) = headers.net {
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

                            let key = FlowKey {
                                src: src_ip, dst: dst_ip,
                                src_port: tcp.source_port, dst_port: tcp.destination_port,
                            };

                            // We need to strip the TCP header from the reassembled IP payload
                            // before adding it to the stream buffer
                            let tcp_data_offset = tcp.header_len() as usize;
                            if full_ip_payload.len() > tcp_data_offset {
                                let app_data = &full_ip_payload[tcp_data_offset..];
                                
                                if let Some((session_data, b_score)) = tcp_reassembler.add_segment(key, app_data, ts) {
                                    
                                    // 1. Analyze for HTTP anomalies
                                    if let Some(http_report) = protocols::http::analyze_http(&session_data, &src_ip.to_string(), &dst_ip.to_string(), tcp.source_port, tcp.destination_port) {
                                         println!("{}", serde_json::to_string_pretty(&http_report).unwrap());
                                    }

                                    // 2. Beaconing check (Timing)
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

                                    let ent = telemetry::shannon_entropy(&session_data);
                                     
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
