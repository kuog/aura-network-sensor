//! Alert export besides the console and SQLite: OCSF Detection Findings as
//! JSON Lines to a file, and one text line per alert to syslog.
//!
//! Runs on its own thread, so a slow disk or an unreachable syslog server
//! never holds up the exporter. Debug-level alerts (suppressed by reputation
//! or the anomaly model) are not exported.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, Sender, TrySendError};
use log::{info, warn};

use super::alert::{MitreAlert, Severity};
use super::console_fmt;
use super::ocsf::{self, Producer};
use super::syslog::{Syslog, Target};

/// Alerts waiting for export; beyond this they are dropped (and counted).
const QUEUE_CAPACITY: usize = 10_000;
/// Repeated write/send failures are logged at most this often.
const WARN_INTERVAL: Duration = Duration::from_secs(30);

pub struct ExportConfig {
    pub ocsf_file: Option<PathBuf>,
    pub syslog: Option<Target>,
}

/// Hands alerts to the export thread without blocking.
pub struct EventSender {
    tx: Sender<MitreAlert>,
    dropped: AtomicU64,
}

impl EventSender {
    pub fn submit(&self, alert: &MitreAlert) {
        if alert.severity == Severity::Debug {
            return;
        }
        if let Err(TrySendError::Full(_)) = self.tx.try_send(alert.clone()) {
            let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if n == 1 || n % 1000 == 0 {
                warn!("[Export] Queue full: {} alerts not exported so far", n);
            }
        }
    }
}

/// Start the export thread. Fails if the OCSF file cannot be opened.
pub fn start(config: ExportConfig) -> Result<(EventSender, JoinHandle<()>)> {
    let hostname = hostname();
    let file = match &config.ocsf_file {
        Some(path) => Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("cannot open OCSF file {}", path.display()))?,
        ),
        None => None,
    };
    let syslog = config.syslog.map(|target| Syslog::new(target, &hostname));

    let (tx, rx) = crossbeam_channel::bounded(QUEUE_CAPACITY);
    let handle = std::thread::Builder::new()
        .name("export".to_string())
        .spawn(move || run(rx, file, syslog, Producer { hostname }))
        .context("failed to spawn the export thread")?;
    Ok((EventSender { tx, dropped: AtomicU64::new(0) }, handle))
}

/// Exports until every sender is gone, i.e. until the exporter has stopped.
fn run(rx: Receiver<MitreAlert>, mut file: Option<File>, mut syslog: Option<Syslog>, producer: Producer) {
    let (mut written, mut sent, mut failed) = (0u64, 0u64, 0u64);
    let mut file_warned = None;
    let mut syslog_warned = None;

    for alert in rx.iter() {
        if let Some(f) = file.as_mut() {
            let mut line = ocsf::detection_finding(&alert, &producer, &new_uid()).to_string();
            line.push('\n');
            // One write per event keeps lines whole for readers tailing the file.
            match f.write_all(line.as_bytes()) {
                Ok(()) => written += 1,
                Err(e) => warn_now(&mut file_warned, || format!("[Export] OCSF file write failed: {e}")),
            }
        }
        if let Some(s) = syslog.as_mut() {
            let msgid = ocsf::technique_uid(&alert.technique_id);
            match s.send(alert.severity, msgid, &console_fmt::alert_text(&alert), alert.timestamp) {
                Ok(()) => sent += 1,
                Err(e) => {
                    failed += 1;
                    warn_now(&mut syslog_warned, || format!("[Export] syslog send failed: {e}"));
                }
            }
        }
    }
    info!(
        "[Export] Stopped. OCSF events written: {}, syslog messages sent: {}, failed: {}",
        written, sent, failed
    );
}

fn warn_now(last: &mut Option<Instant>, message: impl FnOnce() -> String) {
    if last.is_none_or(|at| at.elapsed() >= WARN_INTERVAL) {
        warn!("{}", message());
        *last = Some(Instant::now());
    }
}

/// Random (version 4) UUID for `finding_info.uid`.
fn new_uid() -> String {
    let mut b: [u8; 16] = rand::random();
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: valid buffer; gethostname NUL-terminates within its length.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return "unknown".to_string();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uids_are_v4_uuids() {
        let a = new_uid();
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4");
        assert!(matches!(&a[19..20], "8" | "9" | "a" | "b"));
        assert_ne!(a, new_uid());
    }

    #[test]
    fn file_gets_one_ocsf_line_per_alert_and_debug_is_skipped() {
        let dir = std::env::temp_dir().join(format!("mcp-export-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("alerts.ocsf.jsonl");
        let _ = std::fs::remove_file(&path);

        let (events, handle) = start(ExportConfig { ocsf_file: Some(path.clone()), syslog: None }).unwrap();
        let alert = |severity| {
            MitreAlert::new("T1046", "Network Service Discovery", severity, 70,
                            "192.168.1.10", "203.0.113.5", 40000, 22, "tcp", "port_scan", "scan")
        };
        events.submit(&alert(Severity::Medium));
        events.submit(&alert(Severity::Debug));
        events.submit(&alert(Severity::High));
        drop(events);
        handle.join().unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["class_uid"], 2004);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
