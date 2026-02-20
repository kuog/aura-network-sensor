use anyhow::{Context, Result};
use crossbeam_channel::Sender;
use etherparse::PacketHeaders;
use log::info;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PacketSourceError {
    #[error("interface '{0}' not found")]
    InterfaceNotFound(String),
    #[error("packet channel disconnected")]
    ChannelDisconnected,
    #[cfg(target_os = "linux")]
    #[error("pnet error: {0}")]
    Pnet(#[from] std::io::Error),
    #[cfg(target_os = "macos")]
    #[error("pcap error: {0}")]
    Pcap(#[from] pcap::Error),
}

pub trait PacketSource {
    fn run(&mut self, sender: Sender<Vec<u8>>) -> Result<()>;
}

#[cfg(target_os = "linux")]
pub struct LinuxScanner {
    interface: String,
}

#[cfg(target_os = "linux")]
impl LinuxScanner {
    pub fn new(interface: String) -> Result<Self> {
        Ok(Self { interface })
    }
}

#[cfg(target_os = "linux")]
impl PacketSource for LinuxScanner {
    fn run(&mut self, sender: Sender<Vec<u8>>) -> Result<()> {
        use pnet::datalink::{self, Channel, ChannelType, Config};

        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == self.interface)
            .ok_or_else(|| PacketSourceError::InterfaceNotFound(self.interface.clone()))?;

        let mut config = Config::default();
        config.channel_type = ChannelType::Layer2;

        let (_, mut rx) = match datalink::channel(&interface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(PacketSourceError::InterfaceNotFound(self.interface.clone()).into());
            }
            Err(err) => return Err(PacketSourceError::Pnet(err).into()),
        };

        loop {
            let packet = rx.next().map_err(PacketSourceError::Pnet)?;
            if sender.send(packet.to_vec()).is_err() {
                return Err(PacketSourceError::ChannelDisconnected.into());
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub struct MacScanner {
    interface: String,
}

#[cfg(target_os = "macos")]
impl MacScanner {
    pub fn new(interface: String) -> Result<Self> {
        Ok(Self { interface })
    }
}

#[cfg(target_os = "macos")]
impl PacketSource for MacScanner {
    fn run(&mut self, sender: Sender<Vec<u8>>) -> Result<()> {
        let mut cap = pcap::Capture::from_device(self.interface.as_str())?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .immediate_mode(true)
            .open()?;

        loop {
            let packet = match cap.next_packet() {
                Ok(pkt) => pkt,
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(err) => return Err(PacketSourceError::Pcap(err).into()),
            };

            if sender.send(packet.data.to_vec()).is_err() {
                return Err(PacketSourceError::ChannelDisconnected.into());
            }
        }
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let interface = std::env::args()
        .nth(1)
        .context("usage: cross_platform_capture <interface>")?;

    let (tx, rx) = crossbeam_channel::bounded::<Vec<u8>>(4096);

    #[cfg(target_os = "linux")]
    let mut scanner = LinuxScanner::new(interface)?;

    #[cfg(target_os = "macos")]
    let mut scanner = MacScanner::new(interface)?;

    std::thread::spawn(move || {
        let _ = scanner.run(tx);
    });

    for packet in rx.iter() {
        match PacketHeaders::from_ethernet_slice(&packet) {
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

    Ok(())
}
