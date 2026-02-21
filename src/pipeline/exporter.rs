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

use log::{debug, error, info, warn};
use rusqlite::Connection;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::analysis::dns_resolver::{self, DnsCache};
use crate::analysis::dns_tracker::{self, DnsTracker};
use crate::analysis::enrichment;
use crate::analysis::reputation;
use crate::anomaly::detector::AnomalyDetector;
use crate::anomaly::types::{DetectorPhase, FlowMetrics, Protocol};

use super::alert::{MitreAlert, Severity};

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
/// * `rx`               – Tokio unbounded receiver for incoming alerts.
/// * `stats`            – Shared atomic counters.
/// * `db_path`          – Path to the SQLite database file (created if absent).
/// * `dns_tracker`      – Shared passive DNS cache for reverse-DNS fallback.
/// * `dns_cache`        – Shared active DNS resolver cache (hickory-resolver).
/// * `anomaly_detector` – Shared anomaly detector for AI-based alert suppression.
pub async fn run(
    mut rx: UnboundedReceiver<MitreAlert>,
    stats: Arc<ExporterStats>,
    db_path: Option<String>,
    dns_tracker: Arc<DnsTracker>,
    dns_cache: Arc<DnsCache>,
    anomaly_detector: Arc<AnomalyDetector>,
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

    info!("[Exporter] Async exporter task started (with DNS reverse-lookup fallback + hickory-resolver + anomaly detection)");

    // ── Periodic DNS cache eviction counter ────────────────────────────
    let mut alert_count: u64 = 0;

    // ── Main drain loop ───────────────────────────────────────────────
    while let Some(mut alert) = rx.recv().await {
        alert_count += 1;

        // ── AI-driven Alert Suppression (Isolation Forest) ─────────────
        apply_anomaly_suppression(&mut alert, &anomaly_detector);

        // ── Active DNS Resolver Enrichment (hickory-resolver) ─────────
        // Performs async reverse lookup, known-good matching, fast-flux
        // detection, and domain squatting analysis.
        dns_resolver::enrich_alert(&mut alert, &dns_cache).await;

        // ── Post-enrichment importance-lowering ─────────────────────────
        // After DNS resolution, apply service-keyword and domain-reputation
        // based confidence adjustments. This catches cases where the engine
        // couldn't resolve the domain (no SNI, IP not in CIDR ranges) but
        // the async resolver found a legitimate service domain.
        post_enrichment_adjust(&mut alert);

        // ── Passive DNS Fallback (legacy dns_tracker) ─────────────────
        // If the active resolver didn't resolve a DNS name for dst_ip,
        // fall back to the passive DNS tracker + libc getnameinfo.
        if !alert.metadata.contains_key("dns_resolver_dst")
            && !alert.metadata.contains_key("dns_dst")
        {
            if let Ok(dst_ip) = alert.dst_ip.parse::<IpAddr>() {
                if !dns_tracker.has_entry(&dst_ip) {
                    // Perform async reverse lookup via libc fallback
                    let tracker = dns_tracker.clone();
                    let ip = dst_ip;

                    if let Some(name) = dns_tracker::reverse_lookup(ip).await {
                        debug!("[Exporter] Reverse DNS (libc fallback): {} → {}", ip, name);
                        tracker.set_reverse(ip, name.clone());
                        alert.metadata.insert("dns_dst".to_string(), name.clone());

                        // Re-apply confidence adjustment with the newly resolved name
                        let adj = dns_tracker::adjust_confidence(
                            &tracker,
                            &ip,
                            alert.confidence,
                            alert
                                .metadata
                                .get("entropy")
                                .and_then(|e| e.parse::<f64>().ok()),
                        );
                        if adj.confidence != alert.confidence {
                            alert.metadata.insert(
                                "dns_confidence_reason".to_string(),
                                adj.reason,
                            );
                            alert.confidence = adj.confidence;
                        }
                    }
                }
            }
        }

        // Same for src_ip (libc fallback)
        if !alert.metadata.contains_key("dns_resolver_src")
            && !alert.metadata.contains_key("dns_src")
        {
            if let Ok(src_ip) = alert.src_ip.parse::<IpAddr>() {
                if !dns_tracker.has_entry(&src_ip) {
                    if let Some(name) = dns_tracker::reverse_lookup(src_ip).await {
                        debug!("[Exporter] Reverse DNS (libc fallback): {} → {}", src_ip, name);
                        dns_tracker.set_reverse(src_ip, name.clone());
                        alert.metadata.insert("dns_src".to_string(), name);
                    }
                }
            }
        }

        // 1. Console output (colored human-readable format)
        super::console_fmt::print_alert(&alert);
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

        // 4. Periodic DNS cache maintenance (every 100 alerts)
        if alert_count % 100 == 0 {
            dns_tracker.evict_expired();
            dns_cache.evict_expired();
        }
    }

    // ── Channel closed — flush remaining work ─────────────────────────
    info!(
        "[Exporter] Channel closed. Console: {}, DB writes: {}, DB errors: {}, DNS tracker: {}, DNS resolver cache: {}",
        stats.console_writes.load(Ordering::Relaxed),
        stats.db_writes.load(Ordering::Relaxed),
        stats.db_errors.load(Ordering::Relaxed),
        dns_tracker.len(),
        dns_cache.len(),
    );

    // Ensure WAL checkpoint on shutdown
    if let Some(ref db) = conn {
        if let Err(e) = db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
            warn!("[Exporter] WAL checkpoint failed: {}", e);
        }
    }

    info!("[Exporter] Async exporter task finished");
}

// ── Post-Enrichment Importance Lowering ────────────────────────────────────

/// Service keywords in resolved domain names that strongly indicate legitimate
/// traffic. If the resolved domain contains any of these AND the traffic is on
/// a standard port, confidence is significantly reduced.
const SERVICE_KEYWORDS: &[&str] = &[
    // Email / messaging
    "exchange",
    "outlook",
    "mail",
    "imap",
    "smtp",
    "pop3",
    "mimecast",
    "protonmail",
    // Collaboration / productivity
    "teams",
    "sharepoint",
    "onedrive",
    "slack",
    "zoom",
    // Updates / telemetry
    "update",
    "windowsupdate",
    "swscan",
    "officecdn",
    // Authentication / SSO
    "login",
    "auth",
    "sso",
    "adfs",
    "microsoftonline",
    "okta",
    // DNS / NTP infrastructure
    "ntp",
    "dns",
    "resolver",
];

/// Standard ports where service-keyword traffic is expected and benign.
const STANDARD_SERVICE_PORTS: &[u16] = &[
    25, 80, 110, 143, 443, 465, 587, 853, 993, 995,
    8080, 8443,
];

/// Apply post-enrichment importance-lowering based on resolved domain names.
///
/// This function is called after the async DNS resolver has enriched the alert
/// with `dns_resolver_dst` / `dns_dst` metadata. It checks whether the resolved
/// domain contains service keywords (exchange, outlook, mail, etc.) and whether
/// the traffic is on a standard port, then reduces confidence and severity
/// accordingly.
///
/// This catches the case where the engine couldn't identify the domain (no SNI
/// extracted, IP not in known CIDR ranges) but the async resolver found a
/// legitimate service domain like `exchange.aspose.com`.
fn post_enrichment_adjust(alert: &mut MitreAlert) {
    // Get the resolved domain from any available source
    let domain = alert
        .metadata
        .get("dns_resolver_dst")
        .or_else(|| alert.metadata.get("dns_dst"))
        .cloned();

    let domain = match domain {
        Some(d) => d,
        None => return, // No domain resolved — nothing to adjust
    };

    let domain_lower = domain.to_lowercase();

    // ── Check 0: Provider fallback from DNS hostname ─────────────────────
    // If the provider metadata is still "Unknown" (CIDR lookup missed), try
    // to identify the provider from the DNS-resolved hostname using the
    // enrichment module's domain-keyword matching.
    let current_provider = alert.metadata.get("provider").map(|s| s.as_str());
    if current_provider == Some("Unknown") || current_provider.is_none() {
        if let Some(dns_provider) = enrichment::identify_provider(&domain_lower) {
            alert.metadata.insert("provider".to_string(), dns_provider.clone());
            alert.metadata.insert("provider_name".to_string(), dns_provider);
        }
    }

    // ── Check 1: Service keyword match ──────────────────────────────────
    let matched_keyword = SERVICE_KEYWORDS
        .iter()
        .find(|kw| domain_lower.contains(**kw));

    if let Some(keyword) = matched_keyword {
        let is_standard_port = STANDARD_SERVICE_PORTS.contains(&alert.dst_port)
            || STANDARD_SERVICE_PORTS.contains(&alert.src_port);

        let (new_confidence, reason) = if is_standard_port {
            // Service keyword + standard port → very likely legitimate
            let reduced = alert.confidence.saturating_sub(80);
            (
                reduced,
                format!(
                    "Domain '{}' contains service keyword '{}' on standard port {} (-80 confidence)",
                    domain, keyword, alert.dst_port
                ),
            )
        } else {
            // Service keyword but non-standard port → moderate reduction
            let reduced = alert.confidence.saturating_sub(50);
            (
                reduced,
                format!(
                    "Domain '{}' contains service keyword '{}' on non-standard port {} (-50 confidence)",
                    domain, keyword, alert.dst_port
                ),
            )
        };

        if new_confidence < alert.confidence {
            alert.metadata.insert(
                "post_enrichment_reason".to_string(),
                reason,
            );
            alert.confidence = new_confidence;
        }
    }

    // ── Check 2: Safe domain suffix match ───────────────────────────────
    // Also check if the resolved domain matches known-safe suffixes from
    // the enrichment module (e.g. .microsoft.com, .google.com, etc.)
    if matched_keyword.is_none() && enrichment::is_safe_domain(&domain_lower) {
        let is_standard_port = STANDARD_SERVICE_PORTS.contains(&alert.dst_port)
            || reputation::is_expected_encrypted_port(alert.dst_port);

        if is_standard_port {
            let reduced = alert.confidence.saturating_sub(60);
            if reduced < alert.confidence {
                alert.metadata.insert(
                    "post_enrichment_reason".to_string(),
                    format!(
                        "Domain '{}' matches safe domain list on standard port {} (-60 confidence)",
                        domain, alert.dst_port
                    ),
                );
                alert.confidence = reduced;
            }
        }
    }

    // ── Re-evaluate severity based on new confidence ────────────────────
    // Only downgrade severity, never upgrade it (to avoid masking the
    // original engine's assessment when confidence wasn't changed).
    let new_severity = match alert.confidence {
        0..=9 => Severity::Debug,
        10..=29 => Severity::Info,
        30..=49 => Severity::Low,
        50..=75 => Severity::Medium,
        76..=89 => Severity::High,
        _ => Severity::Critical,
    };

    // Only downgrade, never upgrade
    if new_severity < alert.severity {
        alert.metadata.insert(
            "severity_adjusted".to_string(),
            format!("{} → {}", alert.severity, new_severity),
        );
        alert.severity = new_severity;
    }
}

// ── AI-driven Anomaly Suppression ──────────────────────────────────────────

/// Apply Isolation Forest-based anomaly suppression to an alert.
///
/// During the **Learning Phase**, alerts are tagged with `[LEARNING MODE]` metadata
/// but not suppressed. During the **Inference Phase**, the alert's flow characteristics
/// are scored by the Isolation Forest model:
///
/// - If the model classifies the flow as **Normal** (typical traffic pattern for this
///   network), the alert severity is reduced to DEBUG/INFO and an `ai_confidence_score`
///   metadata field is added.
/// - If the model classifies the flow as **Anomalous**, the alert is left unchanged
///   (or even boosted if the anomaly score is very high).
fn apply_anomaly_suppression(alert: &mut MitreAlert, detector: &AnomalyDetector) {
    let phase = detector.phase();

    match phase {
        DetectorPhase::Learning => {
            // Tag alerts during learning phase
            alert.metadata.insert(
                "ai_phase".to_string(),
                "LEARNING".to_string(),
            );
            let remaining = detector.remaining_learning_time();
            alert.metadata.insert(
                "ai_learning_remaining_secs".to_string(),
                remaining.as_secs().to_string(),
            );
        }
        DetectorPhase::Training => {
            // Model is being trained — tag but don't suppress
            alert.metadata.insert(
                "ai_phase".to_string(),
                "TRAINING".to_string(),
            );
        }
        DetectorPhase::Inference => {
            // Build a FlowMetrics from the alert for scoring
            let flow = match alert_to_flow_metrics(alert) {
                Some(f) => f,
                None => {
                    // Insufficient data to score — tag and skip
                    alert.metadata.insert(
                        "ai_phase".to_string(),
                        "INFERENCE".to_string(),
                    );
                    alert.metadata.insert(
                        "ai_classification".to_string(),
                        "NO_FLOW_DATA".to_string(),
                    );
                    return;
                }
            };
            if let Some(result) = detector.predict(&flow) {
                // Always add the AI confidence score to metadata
                alert.metadata.insert(
                    "ai_confidence_score".to_string(),
                    format!("{:.4}", result.anomaly_score),
                );
                alert.metadata.insert(
                    "ai_phase".to_string(),
                    "INFERENCE".to_string(),
                );
                alert.metadata.insert(
                    "ai_classification".to_string(),
                    if result.is_normal {
                        "NORMAL".to_string()
                    } else {
                        "ANOMALOUS".to_string()
                    },
                );

                if result.is_normal && result.confidence > 0.15 {
                    // Flow is classified as normal with reasonable confidence.
                    // Suppress the alert by reducing severity and confidence.
                    let original_severity = alert.severity;
                    let original_confidence = alert.confidence;

                    // Scale down confidence based on AI confidence
                    // Higher AI confidence in "normal" → more suppression
                    let suppression_factor = result.confidence.min(0.9);
                    let new_confidence = (alert.confidence as f64 * (1.0 - suppression_factor)) as u8;

                    alert.confidence = new_confidence;

                    // Reduce severity based on new confidence
                    let new_severity = if new_confidence <= 10 {
                        Severity::Debug
                    } else if new_confidence <= 25 {
                        Severity::Info
                    } else if new_confidence <= 40 {
                        Severity::Low
                    } else {
                        alert.severity // Keep original if suppression wasn't strong enough
                    };

                    // Only downgrade severity, never upgrade
                    if new_severity < alert.severity {
                        alert.severity = new_severity;
                    }

                    alert.metadata.insert(
                        "ai_suppression".to_string(),
                        format!(
                            "Normal traffic pattern (score={:.4}, confidence={:.2}). Severity: {} → {}, Confidence: {} → {}",
                            result.anomaly_score,
                            result.confidence,
                            original_severity,
                            alert.severity,
                            original_confidence,
                            alert.confidence,
                        ),
                    );

                    debug!(
                        "[Exporter] AI suppression: {} {} → {} (score={:.4}, ai_conf={:.2})",
                        alert.technique_id,
                        original_severity,
                        alert.severity,
                        result.anomaly_score,
                        result.confidence,
                    );
                }
                // If anomalous, leave the alert as-is (the signature detection is confirmed)
            }
        }
    }
}

/// Convert a MitreAlert into a FlowMetrics for anomaly scoring.
///
/// Prefers real flow data from `flow_*` metadata keys (injected by the engine
/// via `enrich_alert_with_flow_metrics`). Falls back to legacy metadata keys
/// (`entropy`, `observed_entropy`, etc.) if flow data is not available.
///
/// Returns `None` if insufficient real data is available — this prevents
/// scoring with fake defaults that would make all alerts look similar.
fn alert_to_flow_metrics(alert: &MitreAlert) -> Option<FlowMetrics> {
    let src_ip: IpAddr = alert.src_ip.parse().ok()?;
    let dst_ip: IpAddr = alert.dst_ip.parse().ok()?;

    let protocol = match alert.protocol.as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        _ => return None,
    };

    // Check if we have real flow data from the engine (flow_* keys)
    let has_flow_data = alert.metadata.contains_key("flow_entropy");

    if has_flow_data {
        // Use real flow metrics from the FlowTracker
        let entropy = alert.metadata.get("flow_entropy")
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);
        let duration_ms = alert.metadata.get("flow_duration_ms")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let packet_count = alert.metadata.get("flow_packet_count")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(1);
        let bytes_count = alert.metadata.get("flow_bytes_count")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let iat_mean = alert.metadata.get("flow_iat_mean")
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);
        let bytes_per_packet = alert.metadata.get("flow_bytes_per_packet")
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);
        let pkt_size_variance = alert.metadata.get("flow_pkt_size_variance")
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);
        let iat_std = alert.metadata.get("flow_iat_std")
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);
        let payload_ratio = alert.metadata.get("flow_payload_ratio")
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);

        Some(FlowMetrics {
            timestamp: alert.timestamp.timestamp() as f64,
            src_ip,
            dst_ip,
            src_port: alert.src_port,
            dst_port: alert.dst_port,
            protocol,
            entropy,
            duration_ms,
            packet_count,
            bytes_count,
            iat_mean,
            bytes_per_packet,
            pkt_size_variance,
            iat_std,
            payload_ratio,
        })
    } else {
        // No real flow data available — skip scoring entirely.
        //
        // Previously this branch fabricated defaults (duration=1000ms,
        // packet_count=10, etc.) which made all legacy-scored alerts look
        // identical to the model, producing misleading scores.  Returning
        // None causes the caller to tag the alert as NO_FLOW_DATA instead.
        None
    }
}
