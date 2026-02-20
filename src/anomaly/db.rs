//! SQLite persistence layer for network flow features.
//!
//! Manages the `network_features` table used to store aggregated flow metrics
//! for Isolation Forest training and historical analysis.

use log::{info, warn};
use rusqlite::{params, Connection};
use std::net::IpAddr;
use std::path::Path;

use super::types::{FlowMetrics, Protocol};

/// Errors specific to the anomaly detection database layer.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("IP parse error: {0}")]
    IpParse(#[from] std::net::AddrParseError),
}

/// Initialize the anomaly detection database.
///
/// Creates the `network_features` table and required indices if they don't exist.
/// Uses WAL mode for concurrent read performance (compatible with the main alerts DB).
pub fn init_anomaly_db(path: &str) -> Result<Connection, DbError> {
    let conn = Connection::open(path)?;

    // Enable WAL mode for better concurrent read performance
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA synchronous=NORMAL;")?;

    // Create the network_features table
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS network_features (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     REAL    NOT NULL,
            src_ip        TEXT    NOT NULL,
            dst_ip        TEXT    NOT NULL,
            src_port      INTEGER NOT NULL,
            dst_port      INTEGER NOT NULL,
            protocol      TEXT    NOT NULL,
            entropy       REAL    NOT NULL,
            duration_ms   INTEGER NOT NULL,
            packet_count  INTEGER NOT NULL,
            bytes_count   INTEGER NOT NULL,
            iat_mean      REAL    NOT NULL,
            created_at    TEXT    DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_nf_timestamp ON network_features(timestamp);
        CREATE INDEX IF NOT EXISTS idx_nf_src_ip    ON network_features(src_ip);
        CREATE INDEX IF NOT EXISTS idx_nf_dst_ip    ON network_features(dst_ip);
        CREATE INDEX IF NOT EXISTS idx_nf_protocol  ON network_features(protocol);",
    )?;

    // ── Schema migration: add extended features (v2) ──────────────────
    // ALTER TABLE ... ADD COLUMN is safe: it's a no-op if the column already exists
    // in SQLite (we catch the "duplicate column" error and ignore it).
    let new_columns = [
        "ALTER TABLE network_features ADD COLUMN bytes_per_packet REAL DEFAULT 0;",
        "ALTER TABLE network_features ADD COLUMN pkt_size_variance REAL DEFAULT 0;",
        "ALTER TABLE network_features ADD COLUMN iat_std REAL DEFAULT 0;",
        "ALTER TABLE network_features ADD COLUMN payload_ratio REAL DEFAULT 0;",
    ];
    for ddl in &new_columns {
        match conn.execute_batch(ddl) {
            Ok(_) => {}
            Err(e) => {
                let msg = e.to_string();
                if !msg.contains("duplicate column") {
                    return Err(DbError::Sqlite(e));
                }
                // Column already exists — safe to ignore
            }
        }
    }

    info!(
        "[AnomalyDB] Database initialized at '{}'",
        path
    );
    Ok(conn)
}

/// Insert a single flow metrics record into the database.
pub fn insert_flow(conn: &Connection, flow: &FlowMetrics) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO network_features (
            timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
            entropy, duration_ms, packet_count, bytes_count, iat_mean,
            bytes_per_packet, pkt_size_variance, iat_std, payload_ratio
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            flow.timestamp,
            flow.src_ip.to_string(),
            flow.dst_ip.to_string(),
            flow.src_port,
            flow.dst_port,
            flow.protocol.to_string(),
            flow.entropy,
            flow.duration_ms,
            flow.packet_count,
            flow.bytes_count,
            flow.iat_mean,
            flow.bytes_per_packet,
            flow.pkt_size_variance,
            flow.iat_std,
            flow.payload_ratio,
        ],
    )?;
    Ok(())
}

/// Batch-insert multiple flow metrics records (within a single transaction).
pub fn insert_flows_batch(conn: &Connection, flows: &[FlowMetrics]) -> Result<usize, DbError> {
    if flows.is_empty() {
        return Ok(0);
    }

    let tx = conn.unchecked_transaction()?;
    let mut count = 0;

    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO network_features (
                timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                entropy, duration_ms, packet_count, bytes_count, iat_mean,
                bytes_per_packet, pkt_size_variance, iat_std, payload_ratio
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        )?;

        for flow in flows {
            stmt.execute(params![
                flow.timestamp,
                flow.src_ip.to_string(),
                flow.dst_ip.to_string(),
                flow.src_port,
                flow.dst_port,
                flow.protocol.to_string(),
                flow.entropy,
                flow.duration_ms,
                flow.packet_count,
                flow.bytes_count,
                flow.iat_mean,
                flow.bytes_per_packet,
                flow.pkt_size_variance,
                flow.iat_std,
                flow.payload_ratio,
            ])?;
            count += 1;
        }
    }

    tx.commit()?;
    Ok(count)
}

/// Load the last N flow records from the database as feature vectors.
///
/// Returns a Vec of `(feature_vector, FlowMetrics)` tuples.
/// The feature vectors are ready for Isolation Forest training.
pub fn load_recent_features(
    conn: &Connection,
    limit: usize,
) -> Result<Vec<FlowMetrics>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                entropy, duration_ms, packet_count, bytes_count, iat_mean,
                COALESCE(bytes_per_packet, 0.0),
                COALESCE(pkt_size_variance, 0.0),
                COALESCE(iat_std, 0.0),
                COALESCE(payload_ratio, 0.0)
         FROM network_features
         ORDER BY id DESC
         LIMIT ?1",
    )?;

    let rows = stmt.query_map(params![limit as i64], |row| {
        let src_ip_str: String = row.get(1)?;
        let dst_ip_str: String = row.get(2)?;
        let protocol_str: String = row.get(5)?;

        Ok((
            row.get::<_, f64>(0)?,       // timestamp
            src_ip_str,
            dst_ip_str,
            row.get::<_, u16>(3)?,       // src_port
            row.get::<_, u16>(4)?,       // dst_port
            protocol_str,
            row.get::<_, f64>(6)?,       // entropy
            row.get::<_, u64>(7)?,       // duration_ms
            row.get::<_, u32>(8)?,       // packet_count
            row.get::<_, u64>(9)?,       // bytes_count
            row.get::<_, f64>(10)?,      // iat_mean
            row.get::<_, f64>(11)?,      // bytes_per_packet
            row.get::<_, f64>(12)?,      // pkt_size_variance
            row.get::<_, f64>(13)?,      // iat_std
            row.get::<_, f64>(14)?,      // payload_ratio
        ))
    })?;

    let mut features = Vec::new();
    for row in rows {
        let (timestamp, src_ip_str, dst_ip_str, src_port, dst_port, protocol_str,
             entropy, duration_ms, packet_count, bytes_count, iat_mean,
             bytes_per_packet, pkt_size_variance, iat_std, payload_ratio) = row?;

        let src_ip: IpAddr = match src_ip_str.parse() {
            Ok(ip) => ip,
            Err(e) => {
                warn!("[AnomalyDB] Skipping row with invalid src_ip '{}': {}", src_ip_str, e);
                continue;
            }
        };
        let dst_ip: IpAddr = match dst_ip_str.parse() {
            Ok(ip) => ip,
            Err(e) => {
                warn!("[AnomalyDB] Skipping row with invalid dst_ip '{}': {}", dst_ip_str, e);
                continue;
            }
        };

        let protocol = match protocol_str.as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            "icmp" => Protocol::Icmp,
            _ => Protocol::Other(0),
        };

        features.push(FlowMetrics {
            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
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
        });
    }

    Ok(features)
}

/// Count total records in the network_features table.
pub fn count_features(conn: &Connection) -> Result<u64, DbError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM network_features",
        [],
        |row| row.get(0),
    )?;
    Ok(count as u64)
}

/// Get the database file path, creating parent directories if needed.
pub fn ensure_db_path(base_path: &str) -> String {
    let features_db = if base_path.ends_with(".db") {
        base_path.replace(".db", "_features.db")
    } else {
        format!("{}_features.db", base_path)
    };

    // Ensure parent directory exists
    if let Some(parent) = Path::new(&features_db).parent() {
        if !parent.exists() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    features_db
}
