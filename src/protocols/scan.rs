use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};
use foldhash::fast::RandomState;
use lru::LruCache;
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

/// Maximum number of tracked UDP flows; the least recently seen is dropped.
const UDP_FLOW_CAPACITY: NonZeroUsize = NonZeroUsize::new(50_000).unwrap();

/// Lightweight UDP connection tracker.
///
/// Call [`ConnTracker::is_return_traffic`] to check if a packet is a response
/// to a previously seen packet in the opposite direction, then
/// [`ConnTracker::record_flow`] to remember it.
pub struct ConnTracker {
    /// Active flows: key → last-seen timestamp.
    flows: LruCache<UdpFlowKey, Instant>,
    /// How long a flow entry stays valid after the last packet.
    flow_timeout: Duration,
}

impl ConnTracker {
    pub fn new(flow_timeout: Duration) -> Self {
        Self {
            flows: LruCache::new(UDP_FLOW_CAPACITY),
            flow_timeout,
        }
    }

    /// Record a UDP packet.
    pub fn record_flow(
        &mut self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        now: Instant,
    ) {
        let key = UdpFlowKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };
        self.flows.put(key, now);
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
        now: Instant,
    ) -> bool {
        // The reverse of the flow:
        let key = UdpFlowKey {
            src_ip: dst_ip,
            src_port: dst_port,
            dst_ip: src_ip,
            dst_port: src_port,
        };
        self.flows
            .peek(&key)
            .is_some_and(|last_seen| now.duration_since(*last_seen) <= self.flow_timeout)
    }
}

/// Ports that are commonly used by browsers and legitimate applications.
/// Horizontal scans targeting *only* these ports on external hosts are
/// almost certainly normal traffic (CDN, API, web browsing).
const WELL_KNOWN_SERVICE_PORTS: &[u16] = &[
    53,   // DNS
    80,   // HTTP
    123,  // NTP
    443,  // HTTPS / QUIC
    853,  // DNS-over-TLS
    993,  // IMAPS
    995,  // POP3S
    5228, // Google push / FCM
    5229, // Google push
    5230, // Google push
    5353, // mDNS
    8080, // HTTP alt
    8443, // HTTPS alt
];

#[derive(Debug, Clone)]
struct HostScanStats {
    // Map destination IP to set of ports visited on that IP
    dst_ports_per_ip: HashMap<IpAddr, HashSet<u16, RandomState>, RandomState>,
    /// How many of the unique destination IPs are *external* (non-local).
    external_dst_count: usize,
    /// Unique ports across all destinations.
    all_ports: HashSet<u16, RandomState>,
    /// How many of `all_ports` are in [`WELL_KNOWN_SERVICE_PORTS`].
    well_known_ports: usize,
    first_seen: Instant,
    connection_attempts: u32,
}

impl HostScanStats {
    fn new(now: Instant) -> Self {
        Self {
            dst_ports_per_ip: HashMap::default(),
            external_dst_count: 0,
            all_ports: HashSet::default(),
            well_known_ports: 0,
            first_seen: now,
            connection_attempts: 0,
        }
    }

    fn reset(&mut self, now: Instant) {
        self.dst_ports_per_ip.clear();
        self.external_dst_count = 0;
        self.all_ports.clear();
        self.well_known_ports = 0;
        self.connection_attempts = 0;
        self.first_seen = now;
    }

    /// Whether the *majority* (≥ 80%) of ports are well-known. A softer check
    /// for cases where one or two unusual ports shouldn't invalidate an
    /// otherwise benign traffic pattern.
    fn mostly_well_known_ports(&self) -> bool {
        !self.all_ports.is_empty() && self.well_known_ports * 100 / self.all_ports.len() >= 80
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

/// Maximum number of scanning hosts tracked; the least recently seen is dropped.
const SCANNER_CAPACITY: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();

pub struct ScannerTracker {
    scanners: LruCache<IpAddr, HostScanStats>,
    window_duration: Duration,
}

impl ScannerTracker {
    pub fn new(window_duration: Duration) -> Self {
        Self {
            scanners: LruCache::new(SCANNER_CAPACITY),
            window_duration,
        }
    }

    pub fn update(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        is_initiator: bool,
        dst_is_local: bool,
        now: Instant,
    ) -> Option<ScanAlert> {
        let stats = self.scanners.get_or_insert_mut(src_ip, || HostScanStats::new(now));

        // Check window expiry
        if now.duration_since(stats.first_seen) > self.window_duration {
            stats.reset(now);
        }

        // Ports seen on this destination so far.
        let mut ports_on_dst = 0;

        if is_initiator {
            let entry = stats.dst_ports_per_ip.entry(dst_ip);
            let is_new_ip = matches!(entry, Entry::Vacant(_));
            let ports = entry.or_default();

            if ports.insert(dst_port) {
                stats.connection_attempts += 1;
                if stats.all_ports.insert(dst_port) && WELL_KNOWN_SERVICE_PORTS.contains(&dst_port) {
                    stats.well_known_ports += 1;
                }
            }
            ports_on_dst = ports.len();

            // Track external destination count
            if is_new_ip && !dst_is_local {
                stats.external_dst_count += 1;
            }
        }

        // Check triggers
        let unique_targets = stats.dst_ports_per_ip.len();
        let unique_ports_count = stats.all_ports.len();

        let mut trigger_reason = String::new();
        let mut triggered = false;

        // Trigger 1: Horizontal Scan
        //
        // Normal browsing / app traffic routinely fans out to many CDN /
        // API / push-notification endpoints within a 60-second window.
        // We use graduated thresholds:
        //
        //   - All external + well-known ports → suppress entirely (normal browsing)
        //   - Mixed (some local) + well-known ports → 50 IPs (browsing + local services)
        //   - All external + unusual ports → 50 IPs
        //   - Mixed + unusual ports → 15 IPs (lateral movement is suspicious)
        let all_external = stats.external_dst_count == unique_targets;
        let benign_ports = stats.mostly_well_known_ports();

        let horizontal_threshold: usize = match (all_external, benign_ports) {
            (true,  true)  => {
                // Pure outbound web/app traffic — suppress entirely.
                // If we exceed 50 unique targets, just reset; never alert.
                if unique_targets > 50 {
                    stats.reset(now);
                    return None;
                }
                usize::MAX // effectively never triggers below
            }
            (true,  false) => 50,  // external but unusual ports
            (false, true)  => 50,  // mixed destinations but benign ports (browsing + local DNS/router)
            (false, false) => 15,  // mixed destinations + unusual ports — suspicious
        };

        if unique_targets > horizontal_threshold {
            trigger_reason = format!("Horizontal Scan: {} unique IPs", unique_targets);
            triggered = true;
        }

        // Trigger 2: Vertical Scan (> 20 unique ports on a single IP). Only
        // the current destination can have crossed the limit: any other would
        // have fired and reset the window when it did.
        if !triggered && ports_on_dst > 20 {
            trigger_reason = format!("Vertical Scan: {} ports on {}", ports_on_dst, dst_ip);
            triggered = true;
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

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_secs(60);

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::from([a, b, c, d])
    }

    fn scanner() -> IpAddr {
        ip(192, 168, 1, 10)
    }

    #[test]
    fn vertical_scan_fires_on_the_twenty_first_port() {
        let (mut tracker, now) = (ScannerTracker::new(WINDOW), Instant::now());
        let target = ip(192, 168, 1, 20);
        for port in 1000..1020 {
            assert!(tracker.update(scanner(), target, port, true, true, now).is_none());
        }
        let alert = tracker.update(scanner(), target, 1020, true, true, now).expect("alert");
        assert_eq!(alert.trigger_reason, "Vertical Scan: 21 ports on 192.168.1.20");
        assert_eq!((alert.unique_targets_count, alert.unique_ports_count), (1, 21));
    }

    #[test]
    fn horizontal_scan_of_local_hosts_on_an_unusual_port() {
        let (mut tracker, now) = (ScannerTracker::new(WINDOW), Instant::now());
        for host in 1..=15 {
            assert!(tracker.update(scanner(), ip(192, 168, 2, host), 7777, true, true, now).is_none());
        }
        let alert = tracker.update(scanner(), ip(192, 168, 2, 16), 7777, true, true, now).expect("alert");
        assert_eq!(alert.trigger_reason, "Horizontal Scan: 16 unique IPs");
    }

    #[test]
    fn fast_scan_counts_new_ports_only() {
        let (mut tracker, now) = (ScannerTracker::new(WINDOW), Instant::now());
        for host in 1..=14 {
            for port in 3000..3007 {
                assert!(tracker.update(scanner(), ip(192, 168, 2, host), port, true, true, now).is_none());
                assert!(tracker.update(scanner(), ip(192, 168, 2, host), port, true, true, now).is_none());
            }
        }
        // 98 attempts so far.
        assert!(tracker.update(scanner(), ip(192, 168, 2, 1), 3007, true, true, now).is_none());
        assert!(tracker.update(scanner(), ip(192, 168, 2, 2), 3007, true, true, now).is_none());
        let alert = tracker.update(scanner(), ip(192, 168, 2, 3), 3007, true, true, now).expect("alert");
        assert_eq!(alert.trigger_reason, "Fast Scan: 101 attempts");
    }

    #[test]
    fn browsing_external_services_never_alerts() {
        let (mut tracker, now) = (ScannerTracker::new(WINDOW), Instant::now());
        for host in 1..=200 {
            assert!(tracker.update(scanner(), ip(198, 51, 100, host), 443, true, false, now).is_none());
        }
    }

    #[test]
    fn a_new_window_starts_from_zero() {
        let (mut tracker, now) = (ScannerTracker::new(WINDOW), Instant::now());
        let target = ip(192, 168, 1, 20);
        for port in 1000..1020 {
            tracker.update(scanner(), target, port, true, true, now);
        }
        let later = now + WINDOW + Duration::from_secs(1);
        assert!(tracker.update(scanner(), target, 2000, true, true, later).is_none());
    }

    #[test]
    fn a_reset_also_forgets_the_port_totals() {
        let (mut tracker, now) = (ScannerTracker::new(WINDOW), Instant::now());
        let target = ip(192, 168, 1, 20);
        for port in 1000..1021 {
            tracker.update(scanner(), target, port, true, true, now);
        }
        for port in 2000..2020 {
            assert!(tracker.update(scanner(), target, port, true, true, now).is_none());
        }
        let alert = tracker.update(scanner(), target, 2020, true, true, now).expect("alert");
        assert_eq!(alert.unique_ports_count, 21);
    }

    #[test]
    fn the_least_recently_seen_scanner_is_forgotten() {
        let (mut tracker, now) = (ScannerTracker::new(WINDOW), Instant::now());
        let target = ip(192, 168, 1, 20);
        for port in 1000..1020 {
            tracker.update(scanner(), target, port, true, true, now);
        }
        for host in 0..SCANNER_CAPACITY.get() as u32 {
            let [_, a, b, c] = (0x0a00_0000 + host).to_be_bytes();
            tracker.update(ip(10, a, b, c), target, 443, true, true, now);
        }
        assert!(tracker.update(scanner(), target, 1020, true, true, now).is_none());
    }

    #[test]
    fn replies_within_the_timeout_are_return_traffic() {
        let (mut tracker, now) = (ConnTracker::new(WINDOW), Instant::now());
        let (client, server) = (ip(192, 168, 1, 10), ip(8, 8, 8, 8));
        assert!(!tracker.is_return_traffic(server, 53, client, 40_000, now));

        tracker.record_flow(client, 40_000, server, 53, now);
        assert!(tracker.is_return_traffic(server, 53, client, 40_000, now + WINDOW));
        assert!(!tracker.is_return_traffic(server, 53, client, 40_000, now + WINDOW + Duration::from_secs(1)));
        // Same direction is not a reply, nor is another port.
        assert!(!tracker.is_return_traffic(client, 40_000, server, 53, now));
        assert!(!tracker.is_return_traffic(server, 53, client, 40_001, now));
    }

    #[test]
    fn the_flow_table_is_bounded() {
        let (mut tracker, now) = (ConnTracker::new(WINDOW), Instant::now());
        let (client, server) = (ip(192, 168, 1, 10), ip(8, 8, 8, 8));
        tracker.record_flow(client, 1, server, 53, now);
        for flow in 0..UDP_FLOW_CAPACITY.get() as u32 {
            let [_, a, b, c] = (0x0a00_0000 + flow).to_be_bytes();
            tracker.record_flow(ip(10, a, b, c), 40_000, server, 53, now);
        }
        assert_eq!(tracker.flows.len(), UDP_FLOW_CAPACITY.get());
        assert!(!tracker.is_return_traffic(server, 53, client, 1, now));
    }
}
