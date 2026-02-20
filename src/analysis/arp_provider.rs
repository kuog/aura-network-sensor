//! ARP Guardian — Stickiness-based ARP spoofing detection.
//!
//! Maintains a Trust-on-First-Use (TOFU) IP→MAC state table and applies
//! stickiness rules to distinguish legitimate Gratuitous ARP (router heartbeats)
//! from real MITM attacks.
//!
//! ## Detection Rules
//!
//! | Rule | Condition | Action |
//! |------|-----------|--------|
//! | **Stickiness** | ARP Reply for known IP | Compare MACs |
//! | **Legitimate Update** | `new_mac == existing_mac` | Suppress alert |
//! | **Red Line** | `new_mac != existing_mac` | CRITICAL alert |
//! | **New Device** | IP not in table | Add (TOFU) + INFO event |
//!
//! ## Persistence
//!
//! The ARP binding table is persisted to SQLite on shutdown and restored on
//! startup, so known devices survive restarts without triggering "New Device"
//! alerts again.
//!
//! ## Performance
//!
//! - O(1) lookups via [`DashMap`] (lock-free concurrent hash map).
//! - No mutex contention on the analysis thread.

use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use dashmap::DashMap;
use log::{debug, info, warn};
use serde::Serialize;

use crate::protocols::arp::mac_to_string;

// ── Public types ──────────────────────────────────────────────────────────

/// Verdict returned by [`ArpGuardian::evaluate`] for each ARP packet.
#[derive(Debug, Clone)]
pub enum ArpVerdict {
    /// MAC matches the known binding — routine heartbeat / refresh.
    /// No alert should be emitted.
    Legitimate,

    /// IP was not previously known; added to the state table (TOFU).
    /// Emit an INFO-level "New device discovered" event.
    NewDevice {
        ip: IpAddr,
        mac: String,
    },

    /// MAC conflict detected for a known IP — potential MITM.
    /// Emit a CRITICAL alert with full forensic context.
    Conflict(ArpConflict),
}

/// Forensic detail for a MAC conflict (Rule 3 — The Red Line).
#[derive(Debug, Clone, Serialize)]
pub struct ArpConflict {
    /// The IP address whose binding changed.
    pub ip: IpAddr,
    /// The MAC that was previously trusted for this IP.
    pub previous_mac: String,
    /// The new (conflicting) MAC claiming this IP.
    pub conflicting_mac: String,
    /// Whether this IP is the default gateway.
    pub is_gateway_attack: bool,
    /// Human-readable description.
    pub message: String,
    /// MITRE ATT&CK technique ID.
    pub technique_id: String,
}

/// Internal record for each IP→MAC binding.
#[derive(Debug, Clone)]
struct MacBinding {
    /// The trusted MAC address (first seen or configured).
    mac: [u8; 6],
    /// When this binding was first established (retained for forensic snapshots).
    #[allow(dead_code)]
    first_seen: Instant,
    /// When the last ARP packet confirmed this binding.
    last_seen: Instant,
    /// Number of ARP packets that confirmed this binding.
    hit_count: u64,
}

// ── ArpGuardian ───────────────────────────────────────────────────────────

/// Thread-safe ARP state machine with stickiness-based spoofing detection.
///
/// Uses [`DashMap`] for O(1) concurrent lookups without locking the entire
/// analysis thread during table updates. Gateway fields use [`Mutex`] for
/// interior mutability, allowing the guardian to be shared across threads
/// (e.g., for persistence on shutdown).
pub struct ArpGuardian {
    /// IP → MAC binding table (TOFU state).
    state: DashMap<IpAddr, MacBinding>,
    /// The default gateway IP, if discovered.
    gateway_ip: Mutex<Option<IpAddr>>,
    /// The default gateway MAC, if discovered.
    gateway_mac: Mutex<Option<[u8; 6]>>,
}

impl ArpGuardian {
    /// Create a new guardian with no pre-configured gateway.
    ///
    /// The gateway will be auto-discovered from the first ARP traffic that
    /// matches common gateway patterns (e.g., `.1` or `.254` suffix).
    pub fn new() -> Self {
        info!("[ArpGuardian] Initialized (TOFU mode, no pre-configured gateway)");
        Self {
            state: DashMap::with_capacity(256),
            gateway_ip: Mutex::new(None),
            gateway_mac: Mutex::new(None),
        }
    }

    /// Create a new guardian with a pre-configured gateway IP.
    ///
    /// The gateway MAC will be learned from the first ARP packet from this IP.
    pub fn with_gateway(gateway_ip: IpAddr) -> Self {
        info!(
            "[ArpGuardian] Initialized with gateway IP: {}",
            gateway_ip
        );
        Self {
            state: DashMap::with_capacity(256),
            gateway_ip: Mutex::new(Some(gateway_ip)),
            gateway_mac: Mutex::new(None),
        }
    }

    /// Evaluate an ARP packet against the stickiness rules.
    ///
    /// Handles both ARP Request (opcode 1) for passive learning and
    /// ARP Reply (opcode 2) for active validation.
    ///
    /// # Arguments
    /// * `sender_mac` — Source hardware address from the ARP header.
    /// * `sender_ip`  — Source protocol address from the ARP header.
    /// * `opcode`     — 1 = Request, 2 = Reply.
    ///
    /// # Returns
    /// An [`ArpVerdict`] indicating whether the packet is legitimate,
    /// introduces a new device, or represents a MAC conflict.
    pub fn evaluate(
        &self,
        sender_mac: [u8; 6],
        sender_ip: IpAddr,
        _opcode: u16,
    ) -> ArpVerdict {
        // ── Gateway auto-discovery ────────────────────────────────────
        self.try_discover_gateway(sender_ip, sender_mac);

        // ── Lookup existing binding ───────────────────────────────────
        if let Some(mut binding) = self.state.get_mut(&sender_ip) {
            // Rule 2: Legitimate Update — same MAC, just a refresh
            if binding.mac == sender_mac {
                binding.last_seen = Instant::now();
                binding.hit_count += 1;
                debug!(
                    "[ArpGuardian] Heartbeat: {} → {} (hits: {})",
                    sender_ip,
                    mac_to_string(sender_mac),
                    binding.hit_count,
                );
                return ArpVerdict::Legitimate;
            }

            // Rule 3: The Red Line — MAC conflict!
            let previous_mac = mac_to_string(binding.mac);
            let conflicting_mac = mac_to_string(sender_mac);
            let is_gateway = self.is_gateway(&sender_ip);

            let severity_label = if is_gateway { "GATEWAY" } else { "HOST" };
            warn!(
                "[ArpGuardian] ⚠ MAC CONFLICT ({}) for {}: {} → {}",
                severity_label, sender_ip, previous_mac, conflicting_mac,
            );

            let message = format!(
                "ARP Spoofing detected: {} {} MAC changed from {} to {}",
                severity_label, sender_ip, previous_mac, conflicting_mac,
            );

            return ArpVerdict::Conflict(ArpConflict {
                ip: sender_ip,
                previous_mac,
                conflicting_mac,
                is_gateway_attack: is_gateway,
                message,
                technique_id: "T1557".to_string(),
            });
        }

        // ── Rule 4: New Device — Trust on First Use ──────────────────
        // For ARP Requests (opcode 1) we learn passively.
        // For ARP Replies (opcode 2) we also learn (the sender is announcing).
        let now = Instant::now();
        self.state.insert(
            sender_ip,
            MacBinding {
                mac: sender_mac,
                first_seen: now,
                last_seen: now,
                hit_count: 1,
            },
        );

        let mac_str = mac_to_string(sender_mac);
        let device_type = if self.is_gateway(&sender_ip) {
            "gateway"
        } else {
            "host"
        };
        info!(
            "[ArpGuardian] New {} discovered: {} → {}",
            device_type, sender_ip, mac_str,
        );

        ArpVerdict::NewDevice {
            ip: sender_ip,
            mac: mac_str,
        }
    }

    /// Returns `true` if the given IP is the default gateway.
    pub fn is_gateway(&self, ip: &IpAddr) -> bool {
        self.gateway_ip.lock().unwrap().as_ref() == Some(ip)
    }

    /// Returns the current number of tracked IP→MAC bindings.
    pub fn binding_count(&self) -> usize {
        self.state.len()
    }

    /// Returns a snapshot of all current bindings (for diagnostics).
    pub fn snapshot(&self) -> Vec<(IpAddr, String, u64)> {
        self.state
            .iter()
            .map(|entry| {
                let ip = *entry.key();
                let mac = mac_to_string(entry.value().mac);
                let hits = entry.value().hit_count;
                (ip, mac, hits)
            })
            .collect()
    }

    // ── Persistence ───────────────────────────────────────────────────

    /// Save the current ARP binding table to a SQLite database.
    ///
    /// Creates the `arp_bindings` table if it doesn't exist, then replaces
    /// all rows with the current in-memory state. This is designed to be
    /// called once at shutdown.
    pub fn save_to_db(&self, conn: &rusqlite::Connection) -> Result<usize, String> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS arp_bindings (
                ip          TEXT    PRIMARY KEY,
                mac         TEXT    NOT NULL,
                hit_count   INTEGER NOT NULL DEFAULT 1,
                updated_at  TEXT    DEFAULT (datetime('now'))
            );",
        )
        .map_err(|e| format!("Failed to create arp_bindings table: {}", e))?;

        // Clear old data and insert current state in a transaction
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;

        tx.execute("DELETE FROM arp_bindings", [])
            .map_err(|e| format!("Failed to clear arp_bindings: {}", e))?;

        let mut count = 0;
        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO arp_bindings (ip, mac, hit_count) VALUES (?1, ?2, ?3)",
                )
                .map_err(|e| format!("Failed to prepare insert: {}", e))?;

            for entry in self.state.iter() {
                let ip_str = entry.key().to_string();
                let mac_str = mac_to_string(entry.value().mac);
                let hits = entry.value().hit_count as i64;
                stmt.execute(rusqlite::params![ip_str, mac_str, hits])
                    .map_err(|e| format!("Failed to insert binding: {}", e))?;
                count += 1;
            }
        }

        // Also save gateway info
        let gw_ip_opt = *self.gateway_ip.lock().unwrap();
        let gw_mac_opt = *self.gateway_mac.lock().unwrap();
        if let Some(gw_ip) = gw_ip_opt {
            if let Some(gw_mac) = gw_mac_opt {
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS arp_gateway (
                        id      INTEGER PRIMARY KEY CHECK (id = 1),
                        ip      TEXT    NOT NULL,
                        mac     TEXT    NOT NULL
                    );",
                )
                .map_err(|e| format!("Failed to create arp_gateway table: {}", e))?;

                tx.execute("DELETE FROM arp_gateway", [])
                    .map_err(|e| format!("Failed to clear arp_gateway: {}", e))?;
                tx.execute(
                    "INSERT INTO arp_gateway (id, ip, mac) VALUES (1, ?1, ?2)",
                    rusqlite::params![gw_ip.to_string(), mac_to_string(gw_mac)],
                )
                .map_err(|e| format!("Failed to insert gateway: {}", e))?;
            }
        }

        tx.commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        info!(
            "[ArpGuardian] Saved {} ARP bindings to database",
            count
        );
        Ok(count)
    }

    /// Load ARP bindings from a SQLite database, restoring the state table.
    ///
    /// This should be called once at startup, before the engine thread begins
    /// processing packets. Bindings loaded from the DB are treated as trusted
    /// (TOFU — they were learned in a previous session).
    pub fn load_from_db(&self, conn: &rusqlite::Connection) -> Result<usize, String> {
        // Check if the table exists
        let table_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='arp_bindings'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);

        if !table_exists {
            info!("[ArpGuardian] No saved ARP bindings found (first run)");
            return Ok(0);
        }

        // Load bindings
        let mut stmt = conn
            .prepare("SELECT ip, mac, hit_count FROM arp_bindings")
            .map_err(|e| format!("Failed to prepare select: {}", e))?;

        let now = Instant::now();
        let mut count = 0;

        let rows = stmt
            .query_map([], |row| {
                let ip_str: String = row.get(0)?;
                let mac_str: String = row.get(1)?;
                let hit_count: i64 = row.get(2)?;
                Ok((ip_str, mac_str, hit_count))
            })
            .map_err(|e| format!("Failed to query arp_bindings: {}", e))?;

        for row in rows {
            let (ip_str, mac_str, hit_count) =
                row.map_err(|e| format!("Failed to read row: {}", e))?;

            let ip: IpAddr = match ip_str.parse() {
                Ok(ip) => ip,
                Err(e) => {
                    warn!(
                        "[ArpGuardian] Skipping invalid IP '{}': {}",
                        ip_str, e
                    );
                    continue;
                }
            };

            let mac = match parse_mac_string(&mac_str) {
                Some(m) => m,
                None => {
                    warn!(
                        "[ArpGuardian] Skipping invalid MAC '{}' for IP {}",
                        mac_str, ip_str
                    );
                    continue;
                }
            };

            self.state.insert(
                ip,
                MacBinding {
                    mac,
                    first_seen: now,
                    last_seen: now,
                    hit_count: hit_count as u64,
                },
            );
            count += 1;
        }

        // Load gateway info
        let gw_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='arp_gateway'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);

        if gw_exists {
            if let Ok(row) = conn.query_row(
                "SELECT ip, mac FROM arp_gateway WHERE id = 1",
                [],
                |row| {
                    let ip_str: String = row.get(0)?;
                    let mac_str: String = row.get(1)?;
                    Ok((ip_str, mac_str))
                },
            ) {
                if let Ok(gw_ip) = row.0.parse::<IpAddr>() {
                    if let Some(gw_mac) = parse_mac_string(&row.1) {
                        *self.gateway_ip.lock().unwrap() = Some(gw_ip);
                        *self.gateway_mac.lock().unwrap() = Some(gw_mac);
                        info!(
                            "[ArpGuardian] Restored gateway: {} → {}",
                            gw_ip, row.1
                        );
                    }
                }
            }
        }

        info!(
            "[ArpGuardian] Restored {} ARP bindings from database",
            count
        );
        Ok(count)
    }

    // ── Private helpers ───────────────────────────────────────────────

    /// Attempt to auto-discover the default gateway from ARP traffic.
    ///
    /// Heuristic: if no gateway is configured, the first IP ending in `.1`
    /// or `.254` is assumed to be the gateway. Once set, the gateway IP is
    /// locked and won't change.
    fn try_discover_gateway(&self, ip: IpAddr, mac: [u8; 6]) {
        // Already have a gateway MAC? Nothing to do.
        // Note: we use gateway_mac as the "fully discovered" flag.
        if self.gateway_mac.lock().unwrap().is_some() {
            return;
        }

        let should_adopt = match *self.gateway_ip.lock().unwrap() {
            Some(gw_ip) => {
                // Gateway IP is pre-configured; learn its MAC.
                ip == gw_ip
            }
            None => {
                // Auto-detect: common gateway suffixes.
                Self::looks_like_gateway(&ip)
            }
        };

        if should_adopt {
            *self.gateway_ip.lock().unwrap() = Some(ip);
            *self.gateway_mac.lock().unwrap() = Some(mac);
            info!(
                "[ArpGuardian] Gateway discovered: {} → {}",
                ip,
                mac_to_string(mac),
            );
        }
    }

    /// Heuristic: does this IP look like a default gateway?
    fn looks_like_gateway(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // Common gateway addresses: x.x.x.1 or x.x.x.254
                octets[3] == 1 || octets[3] == 254
            }
            IpAddr::V6(v6) => {
                let segs = v6.segments();
                // fe80::1 is the most common IPv6 link-local gateway address.
                // Also match fe80::<anything>::1 (last segment == 1).
                let is_link_local = (segs[0] & 0xffc0) == 0xfe80;
                is_link_local && segs[7] == 1
            }
        }
    }
}

/// Parse a MAC address string (e.g. "aa:bb:cc:dd:ee:ff") into a 6-byte array.
///
/// Returns `None` if the string is not a valid MAC address.
fn parse_mac_string(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn mac(bytes: [u8; 6]) -> [u8; 6] {
        bytes
    }

    #[test]
    fn test_new_device_tofu() {
        let guardian = ArpGuardian::new();
        let verdict = guardian.evaluate(mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]), ip(192, 168, 1, 100), 2);
        match verdict {
            ArpVerdict::NewDevice { ip: addr, mac: m } => {
                assert_eq!(addr, ip(192, 168, 1, 100));
                assert_eq!(m, "aa:bb:cc:dd:ee:01");
            }
            _ => panic!("Expected NewDevice verdict"),
        }
        assert_eq!(guardian.binding_count(), 1);
    }

    #[test]
    fn test_legitimate_heartbeat() {
        let guardian = ArpGuardian::new();
        let m = mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        let addr = ip(192, 168, 1, 100);

        // First packet: new device
        guardian.evaluate(m, addr, 2);

        // Second packet: same MAC → legitimate
        let verdict = guardian.evaluate(m, addr, 2);
        assert!(matches!(verdict, ArpVerdict::Legitimate));
    }

    #[test]
    fn test_mac_conflict_triggers_alert() {
        let guardian = ArpGuardian::new();
        let original_mac = mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        let spoofed_mac = mac([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let addr = ip(192, 168, 1, 100);

        // Establish binding
        guardian.evaluate(original_mac, addr, 2);

        // Conflict!
        let verdict = guardian.evaluate(spoofed_mac, addr, 2);
        match verdict {
            ArpVerdict::Conflict(conflict) => {
                assert_eq!(conflict.ip, addr);
                assert_eq!(conflict.previous_mac, "aa:bb:cc:dd:ee:01");
                assert_eq!(conflict.conflicting_mac, "11:22:33:44:55:66");
                assert!(!conflict.is_gateway_attack);
            }
            _ => panic!("Expected Conflict verdict"),
        }
    }

    #[test]
    fn test_gateway_attack_detection() {
        let gw_ip = ip(192, 168, 1, 1);
        let guardian = ArpGuardian::with_gateway(gw_ip);
        let real_mac = mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        let evil_mac = mac([0x66, 0x66, 0x66, 0x66, 0x66, 0x66]);

        // Gateway announces itself
        guardian.evaluate(real_mac, gw_ip, 2);

        // Attacker spoofs gateway
        let verdict = guardian.evaluate(evil_mac, gw_ip, 2);
        match verdict {
            ArpVerdict::Conflict(conflict) => {
                assert!(conflict.is_gateway_attack);
                assert_eq!(conflict.previous_mac, "aa:bb:cc:dd:ee:01");
                assert_eq!(conflict.conflicting_mac, "66:66:66:66:66:66");
            }
            _ => panic!("Expected Conflict verdict for gateway attack"),
        }
    }

    #[test]
    fn test_gateway_auto_discovery() {
        let guardian = ArpGuardian::new();
        let gw_mac = mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        let gw_ip = ip(192, 168, 1, 1); // ends in .1 → auto-detected

        guardian.evaluate(gw_mac, gw_ip, 1);
        assert!(guardian.is_gateway(&gw_ip));
    }

    #[test]
    fn test_arp_request_learns_passively() {
        let guardian = ArpGuardian::new();
        let m = mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        let addr = ip(192, 168, 1, 50);

        // ARP Request (opcode 1) should still learn the sender
        let verdict = guardian.evaluate(m, addr, 1);
        assert!(matches!(verdict, ArpVerdict::NewDevice { .. }));
        assert_eq!(guardian.binding_count(), 1);

        // Subsequent request with same MAC → legitimate
        let verdict = guardian.evaluate(m, addr, 1);
        assert!(matches!(verdict, ArpVerdict::Legitimate));
    }
}
