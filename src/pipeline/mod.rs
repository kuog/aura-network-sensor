//! Three-stage high-performance NDR pipeline.
//!
//! ```text
//! ┌──────────────┐   crossbeam-channel   ┌──────────────┐   tokio::mpsc   ┌──────────────┐
//! │  Stage 1     │   (bounded ring buf)  │  Stage 2     │   (unbounded)   │  Stage 3     │
//! │  Sniffer     │ ───────────────────▶  │  MITRE       │ ──────────────▶ │  Exporter    │
//! │  (Core 0)    │   RawPacket           │  Engine      │   MitreAlert    │  (Tokio)     │
//! │  libpcap     │                       │  (Core 1)    │                 │  Console+DB  │
//! └──────────────┘                       └──────────────┘                 └──────────────┘
//! ```
//!
//! - **Stage 1** captures packets at wire speed, pinned to Core 0.
//! - **Stage 2** runs all detection logic, pinned to Core 1.
//! - **Stage 3** handles all I/O (console, SQLite, cloud) on the Tokio runtime.
//!
//! Graceful shutdown is coordinated via `Arc<AtomicBool>`.

pub mod alert;
pub mod engine;
pub mod exporter;
pub mod sniffer;

use log::{info, warn};

/// Pin the current thread to a specific physical core.
///
/// On **Linux** this uses `sched_setaffinity` and is a hard guarantee.
/// On **macOS** this uses `thread_policy_set(THREAD_AFFINITY_POLICY)` which is
/// only a *hint* to the scheduler — the kernel may still migrate the thread.
/// The function logs the outcome at the appropriate level.
pub fn pin_to_core(label: &str, core_id: usize) {
    let core_ids = core_affinity::get_core_ids().unwrap_or_default();
    if let Some(core) = core_ids.get(core_id) {
        if core_affinity::set_for_current(*core) {
            info!("[{}] Pinned to core {}", label, core_id);
        } else {
            // On macOS, set_for_current often returns false even though the
            // affinity hint was accepted.  This is not a real failure.
            if cfg!(target_os = "macos") {
                info!(
                    "[{}] Core affinity hint set for core {} (macOS — advisory only)",
                    label, core_id
                );
            } else {
                warn!("[{}] Failed to pin to core {}", label, core_id);
            }
        }
    } else {
        warn!(
            "[{}] Core {} not available ({} cores detected), running unpinned",
            label,
            core_id,
            core_ids.len()
        );
    }
}
