pub mod l3_defrag;
pub mod l4_reassembly;
pub mod telemetry;
pub mod protocols;

use pcap::Capture;
use etherparse::{PacketHeaders, NetHeaders, TransportHeader};
use l3_defrag::Defragmenter;
use l4_reassembly::{Reassembler, FlowKey};
use crate::protocols::dns;

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

                            // We need to strip the TCP header from the reassembled IP payload
                            // before adding it to the stream buffer
                            let tcp_data_offset = tcp.header_len() as usize;
                            if full_ip_payload.len() > tcp_data_offset {
                                let app_data = &full_ip_payload[tcp_data_offset..];
                                
                                if let Some(session_data) = tcp_reassembler.add_segment(key, app_data) {
                                    let ent = telemetry::shannon_entropy(&session_data);
                                    
                                    // Threshold for non-standard encrypted tunnels
                                    if ent > 6.0 {
                                        println!("SUSPICIOUS TCP: From {} to {}, Port: {}, Entropy: {:.2}", 
                                            src_ip, dst_ip, tcp.destination_port, ent);
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