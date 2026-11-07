//! Minimal standalone capture demo: prints the network headers of every frame
//! seen on an interface. Uses libpcap on both Linux and macOS.

use anyhow::{Context, Result};
use etherparse::PacketHeaders;
use log::info;

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let interface = std::env::args()
        .nth(1)
        .context("usage: cross_platform_capture <interface>")?;

    let mut cap = pcap::Capture::from_device(interface.as_str())?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .immediate_mode(true)
        .open()?;

    loop {
        let packet = match cap.next_packet() {
            Ok(pkt) => pkt,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(err) => return Err(err.into()),
        };

        match PacketHeaders::from_ethernet_slice(packet.data) {
            Ok(parsed) => {
                if let Some(net) = parsed.net {
                    info!("Captured network packet: {:?}", net);
                }
            }
            Err(err) => {
                info!("Failed to parse packet: {}", err);
            }
        }
    }
}
