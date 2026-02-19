//! Stage 3: Async Exporter Task — Tokio-based alert output pipeline.
//!
//! Runs as a `tokio::spawn` task on the remaining cores (2–N). Responsibilities:
//!
//! 1. **Console**: Print each alert as pretty JSON (buffered, non-blocking).
//! 2. **Persistence**: Write alerts to a local SQLite database.
//! 3. **Cloud/Telegram**: (Stub) Prepare to send alerts via HTTPS.
//!
//! The exporter drains the `tokio::sync::mpsc` channel until it is closed
//! (graceful shutdown), ensuring all remaining alerts are flushed to the DB.

use log::{error, info, warn};
use rusqlite::Connection;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

use super::alert::MitreAlert;

/// Shared counters for the exporter.
pub struct ExporterStats {
    /// Alerts written to console.
    pub console_writes: AtomicU64,
    /// Alerts persisted to SQLite.
    pub db_writes: AtomicU64,
    /// Alerts that failed to persist.
    pub db_errors: AtomicU64,
}

impl ExporterStats {
    pub fn new() -> Self {
        Self {
            console_writes: AtomicU64::new(0),
            db_writes: AtomicU64::new(0),
            db_errors: AtomicU64::new(0),
        }
    }
}

/// Default SQLite database path.
const DEFAULT_DB_PATH: &str = "alerts.db";

/// Initialize the SQLite database and create the alerts table if needed.
fn init_db(path: &str) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open(path)?;

    // Enable WAL mode for better concurrent read performance
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA synchronous=NORMAL;")?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            technique_id TEXT   NOT NULL,
            technique_name TEXT NOT NULL,
            severity    TEXT    NOT NULL,
            confidence  INTEGER NOT NULL,
            src_ip      TEXT    NOT NULL,
            dst_ip      TEXT    NOT NULL,
            src_port    INTEGER NOT NULL,
            dst_port    INTEGER NOT NULL,
            protocol    TEXT    NOT NULL,
            trigger_name TEXT   NOT NULL,
            logic       TEXT    NOT NULL,
            metadata    TEXT,
            raw_json    TEXT    NOT NULL,
            created_at  TEXT    DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_technique ON alerts(technique_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_src_ip    ON alerts(src_ip);
        CREATE INDEX IF NOT EXISTS idx_alerts_dst_ip    ON alerts(dst_ip);",
    )?;

    info!("[Exporter] SQLite database initialized at '{}'", path);
    Ok(conn)
}

/// Persist a single alert to the SQLite database.
fn persist_alert(conn: &Connection, alert: &MitreAlert) -> Result<(), rusqlite::Error> {
    let raw_json = serde_json::to_string(alert).unwrap_or_default();
    let metadata_json = if alert.metadata.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&alert.metadata).unwrap_or_default())
    };

    conn.execute(
        "INSERT INTO alerts (
            timestamp, technique_id, technique_name, severity, confidence,
            src_ip, dst_ip, src_port, dst_port, protocol,
            trigger_name, logic, metadata, raw_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        rusqlite::params![
            alert.timestamp.to_rfc3339(),
            alert.technique_id,
            alert.technique_name,
            alert.severity.to_string(),
            alert.confidence,
            alert.src_ip,
            alert.dst_ip,
            alert.src_port,
            alert.dst_port,
            alert.protocol,
            alert.trigger,
            alert.logic,
            metadata_json,
            raw_json,
        ],
    )?;
    Ok(())
}

/// Stub: send alert to a cloud endpoint or Telegram bot.
///
/// This is a placeholder for future HTTPS-based delivery. Currently it just
/// logs the intent at debug level.
async fn send_to_cloud(_alert: &MitreAlert) {
    // TODO: Implement HTTPS POST to cloud/Telegram endpoint.
    // Example:
    //   let client = reqwest::Client::new();
    //   client.post("https://api.telegram.org/bot<TOKEN>/sendMessage")
    //       .json(&json!({ "chat_id": CHAT_ID, "text": alert.to_json_pretty() }))
    //       .send()
    //       .await;
    log::debug!("[Exporter] Cloud/Telegram stub: would send alert {}", _alert.technique_id);
}

/// Run the async exporter task. Call this via `tokio::spawn`.
///
/// # Arguments
/// * `rx`      – Tokio unbounded receiver for incoming alerts.
/// * `stats`   – Shared atomic counters.
/// * `db_path` – Path to the SQLite database file (created if absent).
pub async fn run(
    mut rx: UnboundedReceiver<MitreAlert>,
    stats: Arc<ExporterStats>,
    db_path: Option<String>,
) {
    let db_file = db_path.unwrap_or_else(|| DEFAULT_DB_PATH.to_string());

    // Initialize SQLite
    let conn = match init_db(&db_file) {
        Ok(c) => Some(c),
        Err(e) => {
            error!("[Exporter] Failed to open SQLite DB '{}': {}. Alerts will NOT be persisted.", db_file, e);
            None
        }
    };

    info!("[Exporter] Async exporter task started");

    // ── Main drain loop ───────────────────────────────────────────────
    while let Some(alert) = rx.recv().await {
        // 1. Console output (pretty JSON)
        let json = alert.to_json_pretty();
        println!("{}", json);
        stats.console_writes.fetch_add(1, Ordering::Relaxed);

        // 2. SQLite persistence
        if let Some(ref db) = conn {
            match persist_alert(db, &alert) {
                Ok(()) => {
                    stats.db_writes.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    stats.db_errors.fetch_add(1, Ordering::Relaxed);
                    warn!("[Exporter] DB write failed: {}", e);
                }
            }
        }

        // 3. Cloud / Telegram (stub)
        send_to_cloud(&alert).await;
    }

    // ── Channel closed — flush remaining work ─────────────────────────
    info!(
        "[Exporter] Channel closed. Console: {}, DB writes: {}, DB errors: {}",
        stats.console_writes.load(Ordering::Relaxed),
        stats.db_writes.load(Ordering::Relaxed),
        stats.db_errors.load(Ordering::Relaxed),
    );

    // Ensure WAL checkpoint on shutdown
    if let Some(ref db) = conn {
        if let Err(e) = db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
            warn!("[Exporter] WAL checkpoint failed: {}", e);
        }
    }

    info!("[Exporter] Async exporter task finished");
}
