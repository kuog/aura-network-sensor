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
//!                                 │
//!                                 ▼
//!                           ┌─────────────┐  background  ┌─────────────┐
//!                           │ FlowTracker │─────────────▶│  Isolation  │
//!                           │  (DashMap)  │   flush      │  Forest ML  │
//!                           └─────────────┘              └─────────────┘
//! ```
//!
//! Graceful shutdown via `Arc<AtomicBool>` + Ctrl+C handler.

pub mod l3_defrag;
pub mod l4_reassembly;
pub mod telemetry;
pub mod protocols;
pub mod report;
pub mod analysis;
pub mod anomaly;
pub mod pipeline;

use log::{error, info, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use analysis::arp_provider::ArpGuardian;
use analysis::dns_resolver::DnsCache;
use analysis::dns_tracker::DnsTracker;
use anomaly::detector::AnomalyDetector;
use anomaly::flow_tracker::FlowTracker;
use pipeline::engine::EngineStats;
use pipeline::exporter::ExporterStats;
use pipeline::sniffer::{CaptureSource, PacketSource, SnifferStats};

// ── Ring buffer capacity (packets) ────────────────────────────────────────
const RING_BUFFER_CAPACITY: usize = 10_000;

// ── Default core assignments ──────────────────────────────────────────────
const SNIFFER_CORE: usize = 0;
const ENGINE_CORE: usize = 1;

// ── Default learning time (minutes) ───────────────────────────────────────
const DEFAULT_LEARNING_TIME_MINUTES: u64 = 10;

// ── Default flow flush interval (seconds) ─────────────────────────────────
const FLOW_FLUSH_INTERVAL_SECS: u64 = 5;

fn print_usage() {
    pipeline::console_fmt::print_usage();
}

fn list_interfaces() {
    match pcap::Device::list() {
        Ok(devices) => {
            pipeline::console_fmt::print_interfaces(&devices);
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
    let mut learning_time: u64 = DEFAULT_LEARNING_TIME_MINUTES;
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
            "--learning-time" => {
                if i + 1 < args.len() {
                    match args[i + 1].parse::<u64>() {
                        Ok(minutes) => {
                            learning_time = minutes;
                            i += 2;
                        }
                        Err(_) => {
                            eprintln!("Error: --learning-time requires a number (minutes)");
                            print_usage();
                            return;
                        }
                    }
                } else {
                    eprintln!("Error: --learning-time requires a value in minutes");
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
    enum SnifferMode {
        Live(Box<dyn PacketSource + Send>),
        File(CaptureSource),
    }

    let (source, source_type, source_name) = if let Some(file) = pcap_file {
        match CaptureSource::file(&file) {
            Ok(s) => {
                info!("Reading from pcap file: {}", file);
                (SnifferMode::File(s), "PCAP file", file)
            }
            Err(e) => {
                error!("Failed to open PCAP file '{}': {}", file, e);
                return;
            }
        }
    } else if let Some(iface) = interface {
        #[cfg(target_os = "linux")]
        let source = match pipeline::sniffer::LinuxScanner::new(iface.clone()) {
            Ok(scanner) => SnifferMode::Live(Box::new(scanner)),
            Err(e) => {
                error!("Failed to open capture device '{}': {}", iface, e);
                return;
            }
        };

        #[cfg(target_os = "macos")]
        let source = match pipeline::sniffer::MacScanner::new(iface.clone()) {
            Ok(scanner) => SnifferMode::Live(Box::new(scanner)),
            Err(e) => {
                error!("Failed to open capture device '{}': {}", iface, e);
                return;
            }
        };

        info!("Capturing live traffic on interface: {}", iface);
        (source, "Live capture", iface)
    } else {
        use colored::Colorize;
        eprintln!("{} {}", "Error:".red().bold(), "no capture source specified.".white());
        eprintln!();
        print_usage();
        return;
    };

    // ── Shared shutdown flag ──────────────────────────────────────────
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        use colored::Colorize;
        eprintln!("\n  {} {}", "[STOP]".yellow().bold(), "Ctrl+C received, initiating graceful shutdown...".yellow());
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

    // ── Anomaly Detection: FlowTracker + AnomalyDetector ───────────────
    let flow_tracker = FlowTracker::shared();
    let anomaly_detector = AnomalyDetector::shared(learning_time, None);

    // Try to load a previously trained model
    if anomaly_detector.try_load_model() {
        info!(
            "Loaded pre-trained anomaly model — skipping learning phase"
        );
    } else {
        info!(
            "Anomaly detection: learning phase = {} minutes",
            learning_time
        );
    }

    // ── Shared ARP Guardian (persisted across restarts) ─────────────────
    let arp_guardian = Arc::new(ArpGuardian::new());

    // ── Restore persisted state from database ───────────────────────────
    {
        let state_db_path = db_path.as_deref().unwrap_or("alerts.db");
        match rusqlite::Connection::open(state_db_path) {
            Ok(conn) => {
                // Restore ARP bindings (known devices)
                match arp_guardian.load_from_db(&conn) {
                    Ok(count) if count > 0 => {
                        info!("Restored {} known devices from previous session", count);
                    }
                    Ok(_) => {}
                    Err(e) => warn!("Failed to restore ARP bindings: {}", e),
                }
            }
            Err(e) => {
                warn!("Failed to open state database for restore: {}", e);
            }
        }
    }

    // ── Channel: Sniffer → Engine (bounded crossbeam ring buffer) ─────
    let (pkt_tx, pkt_rx) = crossbeam_channel::bounded(RING_BUFFER_CAPACITY);

    // ── Channel: Engine → Exporter (tokio unbounded mpsc) ─────────────
    let (alert_tx, alert_rx) = tokio::sync::mpsc::unbounded_channel();

    pipeline::console_fmt::print_banner();
    pipeline::console_fmt::print_source_info(&source_type, &source_name);
    pipeline::console_fmt::print_pipeline_config(RING_BUFFER_CAPACITY, SNIFFER_CORE, ENGINE_CORE);

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
    let anomaly_detector_exporter = anomaly_detector.clone();
    let exporter_handle = rt.spawn(pipeline::exporter::run(
        alert_rx,
        exporter_stats_clone,
        db_path.clone(),
        dns_tracker_exporter,
        dns_cache_exporter,
        anomaly_detector_exporter,
    ));

    // Spawn the anomaly detection background flush task
    let features_db_path = anomaly::db::ensure_db_path(
        db_path.as_deref().unwrap_or("alerts.db"),
    );
    let anomaly_detector_bg = anomaly_detector.clone();
    let flow_tracker_bg = flow_tracker.clone();
    let running_bg = running.clone();
    let _anomaly_handle = rt.spawn(anomaly::detector::background_flush_task(
        anomaly_detector_bg,
        flow_tracker_bg,
        features_db_path,
        running_bg,
        FLOW_FLUSH_INTERVAL_SECS,
    ));

    // ── Stage 2: MITRE Analysis Engine (Core 1) ───────────────────────
    let engine_running = running.clone();
    let engine_stats_clone = engine_stats.clone();
    let dns_tracker_engine = dns_tracker.clone();
    let flow_tracker_engine = flow_tracker.clone();
    let anomaly_detector_engine = anomaly_detector.clone();
    let arp_guardian_engine = arp_guardian.clone();
    let engine_thread = std::thread::Builder::new()
        .name("engine".to_string())
        .spawn(move || {
            pipeline::engine::run(
                pkt_rx,
                alert_tx,
                engine_running,
                engine_stats_clone,
                ENGINE_CORE,
                dns_tracker_engine,
                flow_tracker_engine,
                anomaly_detector_engine,
                arp_guardian_engine,
            );
        })
        .expect("Failed to spawn engine thread");

    // ── Stage 1: Sniffer (Core 0) ─────────────────────────────────────
    let sniffer_running = running.clone();
    let sniffer_stats_clone = sniffer_stats.clone();
    let sniffer_thread = std::thread::Builder::new()
        .name("sniffer".to_string())
        .spawn(move || {
            match source {
                SnifferMode::File(file_source) => {
                    pipeline::sniffer::run(
                        file_source,
                        pkt_tx,
                        sniffer_running,
                        sniffer_stats_clone,
                        SNIFFER_CORE,
                    );
                }
                SnifferMode::Live(live_source) => {
                    pipeline::sniffer::run_live(
                        live_source,
                        pkt_tx,
                        sniffer_running,
                        sniffer_stats_clone,
                        SNIFFER_CORE,
                    );
                }
            }
        })
        .expect("Failed to spawn sniffer thread");

    // ── Wait for all stages to complete ───────────────────────────────
    pipeline::console_fmt::print_ready();

    // Stage 1 finishes first (EOF or Ctrl+C)
    if let Err(e) = sniffer_thread.join() {
        error!("Sniffer thread panicked: {:?}", e);
    }
    pipeline::console_fmt::print_stage_done("Sniffer thread");

    // Stage 2 finishes when the crossbeam channel is drained + disconnected
    if let Err(e) = engine_thread.join() {
        error!("Engine thread panicked: {:?}", e);
    }
    pipeline::console_fmt::print_stage_done("Engine thread");

    // Stage 3 finishes when the tokio mpsc channel is drained
    // (the Engine dropped alert_tx when it exited)
    rt.block_on(async {
        if let Err(e) = exporter_handle.await {
            error!("Exporter task panicked: {:?}", e);
        }
    });
    pipeline::console_fmt::print_stage_done("Exporter task");

    // ── Persist state to database for next startup ──────────────────────
    {
        let state_db_path = db_path.as_deref().unwrap_or("alerts.db");
        match rusqlite::Connection::open(state_db_path) {
            Ok(conn) => {
                match arp_guardian.save_to_db(&conn) {
                    Ok(count) => {
                        info!("Saved {} ARP bindings for next session", count);
                    }
                    Err(e) => warn!("Failed to save ARP bindings: {}", e),
                }
            }
            Err(e) => {
                warn!("Failed to open state database for save: {}", e);
            }
        }
    }

    // ── Final summary ─────────────────────────────────────────────────
    pipeline::console_fmt::print_shutdown_summary(
        sniffer_stats.captured.load(Ordering::Relaxed),
        sniffer_stats.dropped.load(Ordering::Relaxed),
        engine_stats.analyzed.load(Ordering::Relaxed),
        engine_stats.alerts.load(Ordering::Relaxed),
        exporter_stats.console_writes.load(Ordering::Relaxed),
        exporter_stats.db_writes.load(Ordering::Relaxed),
        exporter_stats.db_errors.load(Ordering::Relaxed),
        dns_tracker.len(),
    );
}
