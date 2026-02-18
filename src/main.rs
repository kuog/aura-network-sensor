pub mod l3_defrag;
pub mod l4_reassembly;
pub mod telemetry;
pub mod protocols;
pub mod report;

use pcap::Capture;
use etherparse::{PacketHeaders, NetHeaders, TransportHeader};
use l3_defrag::Defragmenter;
use l4_reassembly::{Reassembler, FlowKey, TcpStream};
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
                            if tcp.destination_port == 443 || tcp.source_port == 443 {
                                continue;
                            }

                            let key = FlowKey {
                                src: src_ip, dst: dst_ip,
                                src_port: tcp.source_port, dst_port: tcp.destination_port,
                            };

                            // Beaconing Detection Logic
                            {
                                let stream = tcp_reassembler.streams.get_or_insert_mut(key.clone(), || TcpStream {
                                    bytes: Vec::with_capacity(4096),
                                    analyzed: false,
                                    last_seen_ts: Some(ts),
                                    intervals: Vec::new(),
                                });

                                if let Some(last_ts) = stream.last_seen_ts {
                                    let delta = ts - last_ts;
                                    if delta > 0.001 { // Ignore simultaneous packets
                                        stream.intervals.push(delta);
                                    }
                                }
                                stream.last_seen_ts = Some(ts);

                                // Periodic rhythm check (e.g., every 10 packets)
                                if stream.intervals.len() >= 10 {
                                    let score = telemetry::calculate_beacon_score(&stream.intervals);
                                    if score < 0.15 {
                                        println!("BEACONING DETECTED: T1011 | Score: {:.2} | Flow: {} -> {}", 
                                                 score, src_ip, dst_ip);
                                        
                                        let mut context = Context::default();
                                        context.fields.insert("src_ip".to_string(), src_ip.to_string());
                                        context.fields.insert("dst_ip".to_string(), dst_ip.to_string());
                                        context.fields.insert("src_port".to_string(), tcp.source_port.to_string());
                                        context.fields.insert("dst_port".to_string(), tcp.destination_port.to_string());
                                        context.fields.insert("protocol".to_string(), "tcp".to_string());

                                        let telemetry = Telemetry {
                                            entropy: None,
                                            jitter: Some((score * 100.0).round() / 100.0),
                                        };

                                        let ai_hints = vec![AiHint {
                                            trigger: "beaconing".to_string(),
                                            suspected_techniques: vec!["T1011".to_string()],
                                            logic: "Periodic communication detected".to_string(),
                                        }];

                                        let report = Report::new(context, telemetry, ai_hints);
                                        println!("{}", serde_json::to_string_pretty(&report).unwrap());

                                        stream.intervals.clear(); // Reset to avoid double alerts
                                    }
                                }
                            }

                            // We need to strip the TCP header from the reassembled IP payload
                            // before adding it to the stream buffer
                            let tcp_data_offset = tcp.header_len() as usize;
                            if full_ip_payload.len() > tcp_data_offset {
                                let app_data = &full_ip_payload[tcp_data_offset..];
                                
                                if let Some(session_data) = tcp_reassembler.add_segment(key, app_data) {
                                    let ent = telemetry::shannon_entropy(&session_data);
                                     
                                    // Threshold for non-standard encrypted tunnels
                                    if ent > 6.0 {
                                        let mut context = Context::default();
                                        context.fields.insert("src_ip".to_string(), src_ip.to_string());
                                        context.fields.insert("dst_ip".to_string(), dst_ip.to_string());
                                        context.fields.insert("src_port".to_string(), tcp.source_port.to_string());
                                        context.fields.insert("dst_port".to_string(), tcp.destination_port.to_string());
                                        context.fields.insert("protocol".to_string(), "tcp".to_string());

                                        let telemetry = Telemetry {
                                            entropy: Some((ent * 100.0).round() / 100.0),
                                            jitter: None,
                                        };

                                        let ai_hints = vec![AiHint {
                                            trigger: "high_entropy".to_string(),
                                            suspected_techniques: vec!["T1573".to_string(), "T1041".to_string()],
                                            logic: "Payload appears encrypted or obfuscated".to_string(),
                                        }];

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
