//! Stage 1: Sniffer Thread — High-speed packet capture with core pinning.
//!
//! This thread is pinned to Core 0 and runs the capture loop directly on top
//! of libpcap on both platforms (Linux: PACKET_MMAP ring, macOS: BPF device).
//! Captured packets are pushed into a bounded [`crossbeam_channel`] acting as
//! a ring buffer. When the buffer is full, packets are dropped (not blocked)
//! and the drop count is tracked via an atomic counter. Packets the kernel had
//! to drop before we could read them are reported separately (`pcap_stats`).

use anyhow::{Context, Result};
use crossbeam_channel::{Sender, TrySendError};
use log::{error, info, warn};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::pin_to_core;

/// Bytes captured per packet. GRO/TSO super-frames can reach 64 KiB, and the
/// engine's strict parser rejects truncated frames, so capture them whole.
const SNAPLEN: i32 = 65_535;

/// Read timeout, so the loop notices shutdown on an idle interface.
const READ_TIMEOUT_MS: i32 = 100;

/// Size of the kernel capture ring (Linux).
#[cfg(target_os = "linux")]
const KERNEL_BUFFER_BYTES: i32 = 64 * 1024 * 1024;

/// How often kernel drop counters are refreshed.
const STATS_INTERVAL: Duration = Duration::from_secs(1);

/// An owned copy of a captured packet (pcap data is borrowed, so we must copy).
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// Kernel capture timestamp (seconds since epoch, microsecond precision).
    pub timestamp: f64,
    /// Raw Ethernet frame bytes.
    pub data: Vec<u8>,
}

/// A live packet source driven by the sniffer thread.
pub trait PacketSource {
    /// Capture until `running` is cleared, the consumer goes away or an
    /// unrecoverable capture error occurs.
    fn run(&mut self, tx: &Sender<RawPacket>, running: &AtomicBool, stats: &SnifferStats) -> Result<()>;
}

/// libpcap-backed capture source, used on both Linux and macOS.
pub struct PcapSource {
    cap: pcap::Capture<pcap::Active>,
}

impl PcapSource {
    /// Open `interface` for live capture (promiscuous, full snaplen).
    pub fn open(interface: &str) -> Result<Self> {
        let inactive = pcap::Capture::from_device(interface)
            .with_context(|| format!("cannot use interface '{interface}'"))?
            .promisc(true)
            .snaplen(SNAPLEN)
            .timeout(READ_TIMEOUT_MS);

        // Linux: without immediate mode libpcap uses TPACKET_V3 (block-based
        // mmap ring), the fastest mode; the read timeout bounds the latency.
        #[cfg(target_os = "linux")]
        let inactive = inactive.immediate_mode(false).buffer_size(KERNEL_BUFFER_BYTES);
        #[cfg(not(target_os = "linux"))]
        let inactive = inactive.immediate_mode(true);

        let cap = inactive
            .open()
            .with_context(|| format!("failed to open capture on '{interface}'"))?;

        // With TPACKET_V3 libpcap polls without a timeout and relies on the
        // kernel's block timer, which never retires an empty block: on an
        // idle interface a blocking read would never return, and shutdown
        // would hang. Read non-blocking and wait with our own poll timeout.
        #[cfg(target_os = "linux")]
        let cap = cap
            .setnonblock()
            .context("failed to make the capture non-blocking")?;

        Ok(Self { cap })
    }

    /// Attach an eBPF socket filter to the capture socket. The kernel runs it
    /// for every frame before the frame enters the capture ring; its return
    /// value is the snaplen (0 = do not capture).
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub fn attach_socket_filter(&self, program: std::os::fd::OwnedFd) -> Result<()> {
        use std::os::fd::AsRawFd;

        let prog_fd: libc::c_int = program.as_raw_fd();
        // SAFETY: valid socket fd; the option value is an int-sized program fd.
        let rc = unsafe {
            libc::setsockopt(
                self.cap.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_BPF,
                (&prog_fd as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("SO_ATTACH_BPF on the capture socket");
        }
        // The socket now holds its own reference to the program.
        drop(program);
        Ok(())
    }

    /// Wait until the capture ring has data, at most `READ_TIMEOUT_MS`.
    #[cfg(target_os = "linux")]
    fn wait_readable(&self) {
        use std::os::fd::AsRawFd;

        let mut pfd = libc::pollfd {
            fd: self.cap.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Errors (EINTR) just mean another loop iteration.
        unsafe { libc::poll(&mut pfd, 1, READ_TIMEOUT_MS) };
    }

    fn refresh_kernel_stats(&mut self, stats: &SnifferStats) {
        if let Ok(s) = self.cap.stats() {
            stats.kernel_dropped.store(u64::from(s.dropped), Ordering::Relaxed);
            stats.if_dropped.store(u64::from(s.if_dropped), Ordering::Relaxed);
        }
    }
}

impl PacketSource for PcapSource {
    fn run(&mut self, tx: &Sender<RawPacket>, running: &AtomicBool, stats: &SnifferStats) -> Result<()> {
        let mut last_stats = Instant::now();

        while running.load(Ordering::Relaxed) {
            match self.cap.next_packet() {
                Ok(packet) => {
                    let raw = RawPacket {
                        timestamp: timeval_to_secs(&packet.header.ts),
                        data: packet.data.to_vec(),
                    };
                    stats.captured.fetch_add(1, Ordering::Relaxed);

                    match tx.try_send(raw) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => {
                            let drops = stats.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                            if drops % 1000 == 0 {
                                warn!("[Sniffer] Ring buffer full — {} packets dropped so far", drops);
                            }
                        }
                        Err(TrySendError::Disconnected(_)) => break,
                    }
                }
                // Nothing ready: blocking read timed out (macOS), or the
                // non-blocking ring is empty (Linux) and we wait for it here.
                Err(pcap::Error::TimeoutExpired) => {
                    #[cfg(target_os = "linux")]
                    self.wait_readable();
                }
                Err(e) => return Err(e).context("packet capture failed"),
            }

            if last_stats.elapsed() >= STATS_INTERVAL {
                self.refresh_kernel_stats(stats);
                last_stats = Instant::now();
            }
        }

        self.refresh_kernel_stats(stats);
        Ok(())
    }
}

fn timeval_to_secs(tv: &libc::timeval) -> f64 {
    tv.tv_sec as f64 + tv.tv_usec as f64 / 1_000_000.0
}

/// Shared counters for observability (read by telemetry / main thread).
pub struct SnifferStats {
    /// Total packets captured.
    pub captured: AtomicU64,
    /// Packets dropped because the ring buffer was full.
    pub dropped: AtomicU64,
    /// Packets the kernel dropped before userspace could read them.
    pub kernel_dropped: AtomicU64,
    /// Packets dropped by the network interface or its driver.
    pub if_dropped: AtomicU64,
}

impl SnifferStats {
    pub fn new() -> Self {
        Self {
            captured: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            kernel_dropped: AtomicU64::new(0),
            if_dropped: AtomicU64::new(0),
        }
    }
}

/// Run the sniffer loop for live capture on the pinned sniffer thread.
pub fn run_live(
    mut source: Box<dyn PacketSource + Send>,
    tx: Sender<RawPacket>,
    running: Arc<AtomicBool>,
    stats: Arc<SnifferStats>,
    core_id: usize,
) {
    // ── Core pinning ──────────────────────────────────────────────────
    pin_to_core("Sniffer", core_id);

    info!("[Sniffer] Live capture loop started");

    if let Err(e) = source.run(&tx, &running, &stats) {
        error!("[Sniffer] {:#}", e);
        // Without packets the pipeline has nothing to do: shut everything down.
        running.store(false, Ordering::SeqCst);
    }

    drop(tx);
    let total_captured = stats.captured.load(Ordering::Relaxed);
    let total_dropped = stats.dropped.load(Ordering::Relaxed);
    info!(
        "[Sniffer] Stopped. Captured: {}, Dropped: {} ({:.2}% loss), Kernel drops: {}",
        total_captured,
        total_dropped,
        if total_captured > 0 {
            (total_dropped as f64 / total_captured as f64) * 100.0
        } else {
            0.0
        },
        stats.kernel_dropped.load(Ordering::Relaxed),
    );
}
