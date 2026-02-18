pub mod l3_defrag;
pub mod l4_reassembly;
pub mod telemetry;
pub mod protocols;

use pcap::Capture;
use etherparse::{PacketHeaders, NetHeaders, TransportHeader, PayloadSlice};
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
    let mut tcp_reassembler = Reassembler::new(5000); // Track 5000 concurrent flows
    
    let mut cap = Capture::from_file(&args[1]).expect("Failed to open PCAP file");

    println!("--- AI Sensor Analysis Started ---");

    while let Ok(packet) = cap.next_packet() {
        if let Ok(headers) = PacketHeaders::from_ethernet_slice(packet.data) {
            
            // Step 1: L3 Defragmentation
            if let Some(NetHeaders::Ipv4(ip_hdr, _)) = headers.net {
                // Convert the typed payload into a raw byte slice for defragmentation
                let ip_payload_bytes: &[u8] = match headers.payload.clone() {
                    PayloadSlice::Empty => &[],
                    PayloadSlice::Ether(ep) => ep.payload,
                    PayloadSlice::MacsecMod(b) => b,
                    PayloadSlice::Ip(ip) => ip.payload,
                    PayloadSlice::Udp(b)
                    | PayloadSlice::Tcp(b)
                    | PayloadSlice::Icmpv4(b)
                    | PayloadSlice::Icmpv6(b) => b,
                };

                if let Some(full_ip_payload) = defrag.process(&ip_hdr, ip_payload_bytes) {
                    
                    let src_ip = std::net::IpAddr::V4(ip_hdr.source.into());
                    let dst_ip = std::net::IpAddr::V4(ip_hdr.destination.into());

                    match headers.transport {
                        // Step 2a: TCP Reassembly (e.g., for HTTP T1071.001)
                        Some(TransportHeader::Tcp(tcp)) => {
                            let key = FlowKey {
                                src: src_ip, dst: dst_ip,
                                src_port: tcp.source_port, dst_port: tcp.destination_port,
                            };
                            if let Some(session_data) = tcp_reassembler.add_segment(key, &full_ip_payload) {
                                let ent = telemetry::shannon_entropy(&session_data);
                                if ent > 5.0 {
                                    println!("SUSPICIOUS TCP: From {} to {}, Entropy: {}", src_ip, dst_ip, ent);
                                }
                            }
                        }
                        // Step 2b: UDP Stateless Analysis (e.g., for DNS T1071.004)
                        Some(TransportHeader::Udp(udp)) => {
                            if udp.destination_port == 53 || udp.source_port == 53 {
                                if let Some(report) = dns::analyze_dns(&full_ip_payload) {
                                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
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