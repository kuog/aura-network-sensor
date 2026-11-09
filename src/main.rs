//! # Aura Network Sensor — High-Performance NDR Pipeline
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
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod ebpf;

use log::{error, info, warn};
use mimalloc::MiMalloc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use clap::Parser;

use analysis::arp_provider::ArpGuardian;
use analysis::dns_resolver::DnsCache;
use analysis::dns_tracker::DnsTracker;
use analysis::process::ProcessLookup;
use anomaly::detector::AnomalyDetector;
use anomaly::flow_tracker::{FlowAccounting, FlowTracker};
use pipeline::engine::EngineStats;
use pipeline::exporter::ExporterStats;
use pipeline::sniffer::{PcapSource, SnifferStats};

// Every packet is allocated on the sniffer thread and freed on the engine
// thread, the pattern the system allocators handle worst.
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

// ── Ring buffer capacity (packets) ────────────────────────────────────────
const RING_BUFFER_CAPACITY: usize = 10_000;

// ── Default core assignments ──────────────────────────────────────────────
const SNIFFER_CORE: usize = 0;
const ENGINE_CORE: usize = 1;

// ── Default learning time (minutes) ───────────────────────────────────────
const DEFAULT_LEARNING_TIME_MINUTES: u64 = 10;

// ── Default flow flush interval (seconds) ─────────────────────────────────
const FLOW_FLUSH_INTERVAL_SECS: u64 = 5;

#[derive(Debug, Parser)]
#[command(name = "aura-network-sensor")]
#[command(about = "High-Performance NDR Pipeline", long_about = None)]
struct Args {
    /// Interface name to capture from
    #[arg(short = 'i', value_name = "interface")]
    interface: Option<String>,

    /// SQLite database path (default: alerts.db)
    #[arg(short = 'd', value_name = "db_path")]
    db_path: Option<String>,

    /// Learning time in minutes
    #[arg(long = "learning-time", value_name = "minutes", default_value_t = DEFAULT_LEARNING_TIME_MINUTES)]
    learning_time: u64,

    /// List available interfaces
    #[arg(short = 'l', long = "list")]
    list_interfaces: bool,

    /// Also append alerts as OCSF Detection Finding JSON lines to this file
    #[arg(long = "ocsf-file", value_name = "path")]
    ocsf_file: Option<std::path::PathBuf>,

    /// Also send alerts to syslog: local, udp://host[:port] or tcp://host[:port]
    #[arg(long = "syslog", value_name = "target")]
    syslog: Option<pipeline::syslog::Target>,

    /// Disable eBPF sensing (process attribution, kernel flow accounting)
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[arg(long = "no-ebpf")]
    no_ebpf: bool,
}

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
    let args = Args::parse();
    if args.list_interfaces {
        list_interfaces();
        return;
    }

    let interface = args.interface;
    let db_path = args.db_path;
    let learning_time = args.learning_time;
    let ocsf_file = args.ocsf_file;
    let syslog_target = args.syslog;

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    let use_ebpf = if args.no_ebpf {
        info!("[eBPF] Disabled (--no-ebpf)");
        false
    } else if !ebpf::kernel_btf_available() {
        warn!("[eBPF] Kernel has no BTF (/sys/kernel/btf/vmlinux) — running without eBPF");
        false
    } else {
        true
    };

    // ── Determine capture source ──────────────────────────────────────
    let (source, source_name): (PcapSource, String) = if let Some(iface) = interface {
        let source = match PcapSource::open(&iface) {
            Ok(source) => source,
            Err(e) => {
                error!("Failed to open capture device '{}': {:#}", iface, e);
                return;
            }
        };

        info!("Capturing live traffic on interface: {}", iface);
        (source, iface)
    } else {
        use colored::Colorize;
        eprintln!("{} {}", "Error:".red().bold(), "no interface specified. Use -i <interface>.".white());
        eprintln!();
        print_usage();
        return;
    };

    // ── Optional exports: OCSF file, syslog (own thread) ──────────────
    let (events, export_thread) = if ocsf_file.is_some() || syslog_target.is_some() {
        let config = pipeline::event_export::ExportConfig {
            ocsf_file: ocsf_file.clone(),
            syslog: syslog_target.clone(),
        };
        match pipeline::event_export::start(config) {
            Ok((events, handle)) => (Some(events), Some(handle)),
            Err(e) => {
                error!("{:#}", e);
                return;
            }
        }
    } else {
        (None, None)
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

    // ── Anomaly Detection: flow accounting + AnomalyDetector ───────────
    // In-kernel accounting (eBPF socket filter on the capture socket) when
    // available; otherwise every packet is accounted in userspace.
    #[allow(unused_mut)]
    let mut flow_tracker: Arc<dyn FlowAccounting> = FlowTracker::shared();
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    if use_ebpf {
        match ebpf::flow::load() {
            Ok(filter) => match source.attach_socket_filter(filter.program) {
                Ok(()) => {
                    info!(
                        "[eBPF] Flow accounting in the kernel; userspace gets the first {} KiB of each flow direction",
                        ebpf::flow::DPI_LIMIT / 1024
                    );
                    flow_tracker = Arc::new(filter.tracker);
                }
                Err(e) => warn!("[eBPF] Flow filter not attached: {:#}", e),
            },
            Err(e) => warn!("[eBPF] Flow filter unavailable: {:#}", e),
        }
    }
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

    // ── Process attribution + reverse-shell detection (eBPF) ──────────
    #[allow(unused_mut)]
    let mut process_lookup: Option<Arc<dyn ProcessLookup>> = None;
    #[allow(unused_mut)]
    let mut procmon_thread: Option<std::thread::JoinHandle<()>> = None;
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    if use_ebpf {
        match ebpf::procmon::spawn(alert_tx.clone(), running.clone()) {
            Ok((cache, handle, probes)) => {
                info!("[eBPF] Process attribution on: {}", probes.join(", "));
                process_lookup = Some(cache);
                procmon_thread = Some(handle);
            }
            Err(e) => warn!("[eBPF] Process attribution unavailable: {:#}", e),
        }
    }

    pipeline::console_fmt::print_banner();
    pipeline::console_fmt::print_setting("live capture", &source_name);
    pipeline::console_fmt::print_pipeline_config(RING_BUFFER_CAPACITY, SNIFFER_CORE, ENGINE_CORE);
    if let Some(path) = &ocsf_file {
        pipeline::console_fmt::print_setting("OCSF file", &path.display().to_string());
    }
    if let Some(target) = &syslog_target {
        pipeline::console_fmt::print_setting("syslog", &target.to_string());
    }

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
        process_lookup,
        events,
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
            pipeline::sniffer::run_live(
                Box::new(source),
                pkt_tx,
                sniffer_running,
                sniffer_stats_clone,
                SNIFFER_CORE,
            );
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

    // The procmon thread holds an alert sender too; it stops on the shutdown flag.
    if let Some(handle) = procmon_thread {
        if let Err(e) = handle.join() {
            error!("Procmon thread panicked: {:?}", e);
        }
    }

    // Stage 3 finishes when the tokio mpsc channel is drained
    // (the Engine and procmon dropped their alert senders when they exited)
    rt.block_on(async {
        if let Err(e) = exporter_handle.await {
            error!("Exporter task panicked: {:?}", e);
        }
    });
    pipeline::console_fmt::print_stage_done("Exporter task");

    // The export thread drains its queue once the exporter has dropped its sender.
    if let Some(handle) = export_thread {
        if let Err(e) = handle.join() {
            error!("Export thread panicked: {:?}", e);
        }
    }

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
        sniffer_stats.kernel_dropped.load(Ordering::Relaxed),
        sniffer_stats.if_dropped.load(Ordering::Relaxed),
        engine_stats.analyzed.load(Ordering::Relaxed),
        engine_stats.parse_errors.load(Ordering::Relaxed),
        engine_stats.alerts.load(Ordering::Relaxed),
        exporter_stats.console_writes.load(Ordering::Relaxed),
        exporter_stats.db_writes.load(Ordering::Relaxed),
        exporter_stats.db_errors.load(Ordering::Relaxed),
        dns_tracker.len(),
    );
}
