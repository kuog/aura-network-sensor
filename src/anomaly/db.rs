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
            entropy, duration_ms, packet_count, bytes_count, iat_mean
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
                entropy, duration_ms, packet_count, bytes_count, iat_mean
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
                entropy, duration_ms, packet_count, bytes_count, iat_mean
         FROM network_features
         ORDER BY id DESC
         LIMIT ?1",
    )?;

    let rows = stmt.query_map(params![limit as i64], |row| {
        let src_ip_str: String = row.get(1)?;
        let dst_ip_str: String = row.get(2)?;
        let protocol_str: String = row.get(5)?;

        Ok((
            row.get::<_, f64>(0)?,
            src_ip_str,
            dst_ip_str,
            row.get::<_, u16>(3)?,
            row.get::<_, u16>(4)?,
            protocol_str,
            row.get::<_, f64>(6)?,
            row.get::<_, u64>(7)?,
            row.get::<_, u32>(8)?,
            row.get::<_, u64>(9)?,
            row.get::<_, f64>(10)?,
        ))
    })?;

    let mut features = Vec::new();
    for row in rows {
        let (timestamp, src_ip_str, dst_ip_str, src_port, dst_port, protocol_str, entropy, duration_ms, packet_count, bytes_count, iat_mean) = row?;

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
