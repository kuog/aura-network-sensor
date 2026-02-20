use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use serde::Serialize;

// ── UDP Connection Tracker (Stateful Inspection) ────────────────────────────
//
// Tracks outbound UDP flows so that inbound packets can be classified as
// "return traffic" (response to a previously seen request) vs. "unsolicited"
// (potential scan).  A flow is identified by the 4-tuple (local_ip, local_port,
// remote_ip, remote_port).  Entries expire after `flow_timeout`.

/// 4-tuple identifying a UDP "connection" (pseudo-connection).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct UdpFlowKey {
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
}

/// Lightweight UDP connection tracker.
///
/// Call [`ConnTracker::record_flow`] for every UDP packet.
/// Then call [`ConnTracker::is_return_traffic`] to check if a packet
/// is a response to a previously seen packet in the opposite direction.
pub struct ConnTracker {
    /// Active flows: key → last-seen timestamp.
    flows: HashMap<UdpFlowKey, Instant>,
    /// How long a flow entry stays valid after the last packet.
    flow_timeout: Duration,
    /// Maximum number of tracked flows (LRU eviction when exceeded).
    capacity: usize,
    /// Counter for periodic garbage-collection sweeps.
    ops_since_gc: u32,
}

impl ConnTracker {
    pub fn new(flow_timeout: Duration) -> Self {
        Self {
            flows: HashMap::new(),
            flow_timeout,
            capacity: 50_000,
            ops_since_gc: 0,
        }
    }

    /// Record a UDP packet.
    pub fn record_flow(
        &mut self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) {
        let key = UdpFlowKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };
        let now = Instant::now();
        self.flows.insert(key, now);

        self.maybe_gc();
    }

    /// Check whether a UDP packet is return traffic for a known flow.
    ///
    /// Returns `true` if we have recently seen a packet in the opposite direction.
    pub fn is_return_traffic(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> bool {
        // The reverse of the flow:
        let key = UdpFlowKey {
            src_ip: dst_ip,
            src_port: dst_port,
            dst_ip: src_ip,
            dst_port: src_port,
        };
        if let Some(last_seen) = self.flows.get(&key) {
            Instant::now().duration_since(*last_seen) <= self.flow_timeout
        } else {
            false
        }
    }

    /// Periodic garbage collection — remove expired entries.
    fn maybe_gc(&mut self) {
        self.ops_since_gc += 1;
        if self.ops_since_gc < 1000 {
            return;
        }
        self.ops_since_gc = 0;

        let now = Instant::now();
        self.flows
            .retain(|_, last_seen| now.duration_since(*last_seen) <= self.flow_timeout);

        // If still over capacity, drop oldest entries
        if self.flows.len() > self.capacity {
            let mut entries: Vec<_> = self.flows.iter().map(|(k, v)| (k.clone(), *v)).collect();
            entries.sort_by_key(|(_, ts)| *ts);
            let to_remove = self.flows.len() - self.capacity;
            for (key, _) in entries.into_iter().take(to_remove) {
                self.flows.remove(&key);
            }
        }
    }
}

#[derive(Debug, Clone)]
struct HostScanStats {
    // Map destination IP to set of ports visited on that IP
    dst_ports_per_ip: HashMap<IpAddr, HashSet<u16>>,
    first_seen: Instant,
    last_seen: Instant,
    connection_attempts: u32,
}

impl HostScanStats {
    fn new(now: Instant) -> Self {
        Self {
            dst_ports_per_ip: HashMap::new(),
            first_seen: now,
            last_seen: now,
            connection_attempts: 0,
        }
    }

    fn reset(&mut self, now: Instant) {
        self.dst_ports_per_ip.clear();
        self.connection_attempts = 0;
        self.first_seen = now;
        // last_seen is updated separately
    }
}

#[derive(Debug, Serialize)]
pub struct ScanAlert {
    pub scanner_ip: String,
    pub unique_targets_count: usize,
    pub unique_ports_count: usize,
    pub technique_id: String,
    pub trigger_reason: String,
}

pub struct ScannerTracker {
    scanners: HashMap<IpAddr, HostScanStats>,
    // Use BTreeMap to track access order for LRU eviction: (last_seen, src_ip) -> ()
    access_order: BTreeMap<(Instant, IpAddr), ()>,
    window_duration: Duration,
    capacity: usize,
}

impl ScannerTracker {
    pub fn new(window_duration: Duration) -> Self {
        Self {
            scanners: HashMap::new(),
            access_order: BTreeMap::new(),
            window_duration,
            capacity: 10000, // Default capacity
        }
    }

    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    pub fn update(&mut self, src_ip: IpAddr, dst_ip: IpAddr, dst_port: u16, is_initiator: bool) -> Option<ScanAlert> {
        let now = Instant::now();
        let mut is_new = false;
        let mut old_last_seen = None;

        if let Some(stats) = self.scanners.get_mut(&src_ip) {
            old_last_seen = Some(stats.last_seen);
            stats.last_seen = now;
            
            // Check window expiry
            if now.duration_since(stats.first_seen) > self.window_duration {
                stats.reset(now);
            }
        } else {
            is_new = true;
        }

        if let Some(last_seen) = old_last_seen {
            self.access_order.remove(&(last_seen, src_ip));
            self.access_order.insert((now, src_ip), ());
        } else if is_new {
            // Check capacity and evict if needed
            if self.scanners.len() >= self.capacity {
                if let Some((( _, old_ip), _)) = self.access_order.pop_first() {
                    self.scanners.remove(&old_ip);
                }
            }
            
            let stats = HostScanStats::new(now);
            self.scanners.insert(src_ip, stats);
            self.access_order.insert((now, src_ip), ());
        }

        // Now update stats
        let stats = self.scanners.get_mut(&src_ip).unwrap();
        
        if is_initiator {
            let ports = stats.dst_ports_per_ip
                .entry(dst_ip)
                .or_insert_with(HashSet::new);
                
            if ports.insert(dst_port) {
                stats.connection_attempts += 1;
            }
        }

        // Check triggers
        let unique_targets = stats.dst_ports_per_ip.len();
        
        let mut all_unique_ports = HashSet::new();
        for ports in stats.dst_ports_per_ip.values() {
            for port in ports {
                all_unique_ports.insert(*port);
            }
        }
        let unique_ports_count = all_unique_ports.len();

        let mut trigger_reason = String::new();
        let mut triggered = false;

        // Trigger 1: Horizontal Scan (> 15 unique IPs)
        if unique_targets > 15 {
            trigger_reason = format!("Horizontal Scan: {} unique IPs", unique_targets);
            triggered = true;
        }

        // Trigger 2: Vertical Scan (> 20 unique ports on a single IP)
        if !triggered {
            for (ip, ports) in &stats.dst_ports_per_ip {
                if ports.len() > 20 {
                    trigger_reason = format!("Vertical Scan: {} ports on {}", ports.len(), ip);
                    triggered = true;
                    break;
                }
            }
        }

        // Trigger 3: Fast Scan (> 100 attempts)
        if !triggered && stats.connection_attempts > 100 {
            trigger_reason = format!("Fast Scan: {} attempts", stats.connection_attempts);
            triggered = true;
        }

        if triggered {
            stats.reset(now);
            return Some(ScanAlert {
                scanner_ip: src_ip.to_string(),
                unique_targets_count: unique_targets,
                unique_ports_count,
                technique_id: "T1046".to_string(),
                trigger_reason,
            });
        }

        None
    }
}
