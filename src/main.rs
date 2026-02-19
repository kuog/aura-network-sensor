//! # MCP Network Sensor — High-Performance NDR Pipeline
//!
//! A three-stage pipeline architecture for network detection and response:
//!
//! ```text
//! Stage 1 (Core 0)          Stage 2 (Core 1)          Stage 3 (Tokio, Cores 2-N)
//! ┌─────────────┐  ring buf ┌─────────────┐  mpsc     ┌─────────────┐
//! │   Sniffer   │──────────▶│   Engine    │──────────▶│  Exporter   │
//! │   (pcap)    │ crossbeam │  (MITRE)    │  tokio    │ Console+DB  │
//! └─────────────┘           └─────────────┘           └─────────────┘
//! ```
//!
//! Graceful shutdown via `Arc<AtomicBool>` + Ctrl+C handler.

pub mod l3_defrag;
pub mod l4_reassembly;
pub mod telemetry;
pub mod protocols;
pub mod report;
pub mod analysis;
pub mod pipeline;

use log::{error, info};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use analysis::dns_resolver::DnsCache;
use analysis::dns_tracker::DnsTracker;
use pipeline::engine::EngineStats;
use pipeline::exporter::ExporterStats;
use pipeline::sniffer::{CaptureSource, SnifferStats};

// ── Ring buffer capacity (packets) ────────────────────────────────────────
const RING_BUFFER_CAPACITY: usize = 10_000;

// ── Default core assignments ──────────────────────────────────────────────
const SNIFFER_CORE: usize = 0;
const ENGINE_CORE: usize = 1;

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  Live capture (default):  mcp-network-sensor -i <interface>");
    eprintln!("  Read pcap file:          mcp-network-sensor -f <path_to_pcap>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -i <interface>   Capture live traffic from the specified network interface");
    eprintln!("  -f <file>        Analyze traffic from a pcap file");
    eprintln!("  -d <db_path>     SQLite database path (default: alerts.db)");
    eprintln!("  -l               List available network interfaces");
    eprintln!("  -h, --help       Show this help message");
}

fn list_interfaces() {
    match pcap::Device::list() {
        Ok(devices) => {
            println!("Available network interfaces:");
            for dev in &devices {
                let desc = dev.desc.as_deref().unwrap_or("");
                let addrs: Vec<String> =
                    dev.addresses.iter().map(|a| format!("{}", a.addr)).collect();
                let addr_str = if addrs.is_empty() {
                    String::from("no addresses")
                } else {
                    addrs.join(", ")
                };
                println!("  {} - {} [{}]", dev.name, desc, addr_str);
            }
        }
        Err(e) => {
            eprintln!("Error listing interfaces: {}", e);
        }
    }
}

fn main() {
    // ── Initialize logging ────────────────────────────────────────────
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    // ── Parse CLI arguments ───────────────────────────────────────────
    let args: Vec<String> = std::env::args().collect();
    let mut interface: Option<String> = None;
    let mut pcap_file: Option<String> = None;
    let mut db_path: Option<String> = None;
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "-i" => {
                if i + 1 < args.len() {
                    interface = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: -i requires an interface name");
                    print_usage();
                    return;
                }
            }
            "-f" => {
                if i + 1 < args.len() {
                    pcap_file = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: -f requires a file path");
                    print_usage();
                    return;
                }
            }
            "-d" => {
                if i + 1 < args.len() {
                    db_path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: -d requires a database path");
                    print_usage();
                    return;
                }
            }
            "-l" => {
                list_interfaces();
                return;
            }
            "-h" | "--help" => {
                print_usage();
                return;
            }
            other => {
                // Backward compatibility: treat bare argument as pcap file
                pcap_file = Some(other.to_string());
                i += 1;
            }
        }
    }

    // ── Determine capture source ──────────────────────────────────────
    let source = if let Some(file) = pcap_file {
        match CaptureSource::file(&file) {
            Ok(s) => {
                info!("Reading from pcap file: {}", file);
                s
            }
            Err(e) => {
                error!("Failed to open PCAP file '{}': {}", file, e);
                return;
            }
        }
    } else if let Some(iface) = interface {
        match CaptureSource::live(&iface) {
            Ok(s) => {
                info!("Capturing live traffic on interface: {}", iface);
                s
            }
            Err(e) => {
                error!("Failed to open capture device '{}': {}", iface, e);
                return;
            }
        }
    } else {
        eprintln!("Error: no capture source specified.");
        eprintln!();
        print_usage();
        return;
    };

    // ── Shared shutdown flag ──────────────────────────────────────────
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        eprintln!("\n--- Ctrl+C received, initiating graceful shutdown ---");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    // ── Shared stats ──────────────────────────────────────────────────
    let sniffer_stats = Arc::new(SnifferStats::new());
    let engine_stats = Arc::new(EngineStats::new());
    let exporter_stats = Arc::new(ExporterStats::new());

    // ── Shared DNS tracker (passive DNS cache) ─────────────────────────
    let dns_tracker = DnsTracker::shared();

    // ── Shared DNS resolver cache (active, hickory-resolver) ────────────
    let dns_cache = DnsCache::shared();

    // ── Channel: Sniffer → Engine (bounded crossbeam ring buffer) ─────
    let (pkt_tx, pkt_rx) = crossbeam_channel::bounded(RING_BUFFER_CAPACITY);

    // ── Channel: Engine → Exporter (tokio unbounded mpsc) ─────────────
    let (alert_tx, alert_rx) = tokio::sync::mpsc::unbounded_channel();

    info!("=== MCP Network Sensor — 3-Stage Pipeline ===");
    info!(
        "Ring buffer capacity: {} packets | Sniffer→Core {} | Engine→Core {}",
        RING_BUFFER_CAPACITY, SNIFFER_CORE, ENGINE_CORE
    );

    // ── Stage 3: Async Exporter (Tokio runtime on remaining cores) ────
    //
    // We build the Tokio runtime first so we can spawn the exporter task,
    // then launch the synchronous threads for Stages 1 and 2.
    let exporter_stats_clone = exporter_stats.clone();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2) // Use 2 threads (cores 2-3 on a 4-core system)
        .enable_all()
        .thread_name("exporter")
        .build()
        .expect("Failed to build Tokio runtime");

    // Spawn the exporter task inside the runtime
    let dns_tracker_exporter = dns_tracker.clone();
    let dns_cache_exporter = dns_cache.clone();
    let exporter_handle = rt.spawn(pipeline::exporter::run(
        alert_rx,
        exporter_stats_clone,
        db_path,
        dns_tracker_exporter,
        dns_cache_exporter,
    ));

    // ── Stage 2: MITRE Analysis Engine (Core 1) ───────────────────────
    let engine_running = running.clone();
    let engine_stats_clone = engine_stats.clone();
    let dns_tracker_engine = dns_tracker.clone();
    let engine_thread = std::thread::Builder::new()
        .name("engine".to_string())
        .spawn(move || {
            pipeline::engine::run(pkt_rx, alert_tx, engine_running, engine_stats_clone, ENGINE_CORE, dns_tracker_engine);
        })
        .expect("Failed to spawn engine thread");

    // ── Stage 1: Sniffer (Core 0) ─────────────────────────────────────
    let sniffer_running = running.clone();
    let sniffer_stats_clone = sniffer_stats.clone();
    let sniffer_thread = std::thread::Builder::new()
        .name("sniffer".to_string())
        .spawn(move || {
            pipeline::sniffer::run(source, pkt_tx, sniffer_running, sniffer_stats_clone, SNIFFER_CORE);
        })
        .expect("Failed to spawn sniffer thread");

    // ── Wait for all stages to complete ───────────────────────────────
    info!("All pipeline stages running. Press Ctrl+C to stop.");

    // Stage 1 finishes first (EOF or Ctrl+C)
    if let Err(e) = sniffer_thread.join() {
        error!("Sniffer thread panicked: {:?}", e);
    }
    info!("Sniffer thread finished");

    // Stage 2 finishes when the crossbeam channel is drained + disconnected
    if let Err(e) = engine_thread.join() {
        error!("Engine thread panicked: {:?}", e);
    }
    info!("Engine thread finished");

    // Stage 3 finishes when the tokio mpsc channel is drained
    // (the Engine dropped alert_tx when it exited)
    rt.block_on(async {
        if let Err(e) = exporter_handle.await {
            error!("Exporter task panicked: {:?}", e);
        }
    });
    info!("Exporter task finished");

    // ── Final summary ─────────────────────────────────────────────────
    info!("=== Pipeline Shutdown Summary ===");
    info!(
        "Sniffer  — Captured: {}, Dropped: {}",
        sniffer_stats.captured.load(Ordering::Relaxed),
        sniffer_stats.dropped.load(Ordering::Relaxed),
    );
    info!(
        "Engine   — Analyzed: {}, Alerts: {}",
        engine_stats.analyzed.load(Ordering::Relaxed),
        engine_stats.alerts.load(Ordering::Relaxed),
    );
    info!(
        "Exporter — Console: {}, DB writes: {}, DB errors: {}",
        exporter_stats.console_writes.load(Ordering::Relaxed),
        exporter_stats.db_writes.load(Ordering::Relaxed),
        exporter_stats.db_errors.load(Ordering::Relaxed),
    );
    info!(
        "DNS      — Cache entries: {}",
        dns_tracker.len(),
    );
    info!("=== MCP Network Sensor stopped ===");
}
