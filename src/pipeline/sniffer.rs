//! Stage 1: Sniffer Thread — High-speed packet capture with core pinning.
//!
//! This thread is pinned to Core 0 and runs a tight capture loop using libpcap.
//! Captured raw packets are pushed into a bounded [`crossbeam_channel`] acting as
//! a ring buffer. When the buffer is full, packets are dropped (not blocked) and
//! the drop count is tracked via an atomic counter.

use crossbeam_channel::Sender;
use log::{debug, info, warn};
use pcap::{Active, Capture, Offline};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use super::pin_to_core;

/// An owned copy of a captured packet (pcap data is borrowed, so we must copy).
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// Packet timestamp (seconds since epoch, with microsecond fraction).
    pub timestamp: f64,
    /// Raw Ethernet frame bytes.
    pub data: Vec<u8>,
}

/// Capture source abstraction: live interface or pcap file.
pub enum CaptureSource {
    Live(Capture<Active>),
    File(Capture<Offline>),
}

impl CaptureSource {
    /// Open a live capture on the given interface name.
    pub fn live(interface: &str) -> Result<Self, pcap::Error> {
        let cap = Capture::from_device(interface)?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000) // 1 s timeout so we can check the shutdown flag
            .open()?;
        Ok(CaptureSource::Live(cap))
    }

    /// Open a pcap file for offline analysis.
    pub fn file(path: &str) -> Result<Self, pcap::Error> {
        let cap = Capture::from_file(path)?;
        Ok(CaptureSource::File(cap))
    }

    /// Read the next packet. Returns `Err` on EOF or fatal error.
    fn next_packet(&mut self) -> Result<pcap::Packet<'_>, pcap::Error> {
        match self {
            CaptureSource::Live(cap) => cap.next_packet(),
            CaptureSource::File(cap) => cap.next_packet(),
        }
    }
}

/// Shared counters for observability (read by telemetry / main thread).
pub struct SnifferStats {
    /// Total packets captured.
    pub captured: AtomicU64,
    /// Packets dropped because the ring buffer was full.
    pub dropped: AtomicU64,
}

impl SnifferStats {
    pub fn new() -> Self {
        Self {
            captured: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }
}

/// Run the sniffer loop. This function is intended to be called inside a
/// dedicated `std::thread::spawn` closure.
///
/// # Arguments
/// * `source`   – The pcap capture source (live or file).
/// * `tx`       – Bounded crossbeam sender (ring buffer).
/// * `running`  – Shared shutdown flag (set to `false` on Ctrl+C).
/// * `stats`    – Shared atomic counters for captured/dropped packets.
/// * `core_id`  – Which physical core to pin this thread to (typically 0).
pub fn run(
    mut source: CaptureSource,
    tx: Sender<RawPacket>,
    running: Arc<AtomicBool>,
    stats: Arc<SnifferStats>,
    core_id: usize,
) {
    // ── Core pinning ──────────────────────────────────────────────────
    pin_to_core("Sniffer", core_id);

    info!("[Sniffer] Capture loop started");

    // ── Main capture loop ─────────────────────────────────────────────
    while running.load(Ordering::Relaxed) {
        let pkt = match source.next_packet() {
            Ok(p) => p,
            Err(pcap::Error::TimeoutExpired) => continue, // live capture timeout
            Err(e) => {
                // EOF for file captures, or a fatal error
                debug!("[Sniffer] Capture ended: {}", e);
                break;
            }
        };

        // Build an owned copy of the packet data
        let ts =
            pkt.header.ts.tv_sec as f64 + (pkt.header.ts.tv_usec as f64 / 1_000_000.0);
        let raw = RawPacket {
            timestamp: ts,
            data: pkt.data.to_vec(),
        };

        stats.captured.fetch_add(1, Ordering::Relaxed);

        // Non-blocking send: drop the packet if the channel is full
        if let Err(_) = tx.try_send(raw) {
            let drops = stats.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            // Log every 1000 drops to avoid flooding
            if drops % 1000 == 0 {
                warn!("[Sniffer] Ring buffer full — {} packets dropped so far", drops);
            }
        }
    }

    // Signal downstream that no more packets are coming by dropping the sender
    drop(tx);
    let total_captured = stats.captured.load(Ordering::Relaxed);
    let total_dropped = stats.dropped.load(Ordering::Relaxed);
    info!(
        "[Sniffer] Stopped. Captured: {}, Dropped: {} ({:.2}% loss)",
        total_captured,
        total_dropped,
        if total_captured > 0 {
            (total_dropped as f64 / total_captured as f64) * 100.0
        } else {
            0.0
        }
    );
}
