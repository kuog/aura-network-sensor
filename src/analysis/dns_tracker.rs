//! Passive DNS Tracking and Reverse IP Resolution.
//!
//! This module maintains a live mapping of IP addresses → domain names by:
//!
//! 1. **Passive DNS**: Parsing DNS response packets (port 53, UDP) in real-time,
//!    extracting A/AAAA records and their TTLs.
//! 2. **Reverse DNS Fallback**: When an IP has no passive DNS entry, the async
//!    exporter can perform a background PTR lookup via [`reverse_lookup`].
//! 3. **Security Scoring**: Adjusting alert confidence based on whether a domain
//!    is known (CDN/cloud) or unknown ("dark" traffic).
//!
//! The cache uses [`DashMap`] for lock-free concurrent reads from the engine
//! thread and writes from both the passive listener and the async resolver.

use dashmap::DashMap;
use log::{debug, trace};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long an address the system resolver has no name for is not asked about again.
const NO_NAME_TTL: Duration = Duration::from_secs(300);

/// How long lookups are skipped after one timed out.
const LOOKUP_BACKOFF: Duration = Duration::from_secs(30);

/// A lookup slower than this, even if it ends in "no name", was waiting on an
/// unreachable server rather than getting an answer.
const SLOW_LOOKUP: Duration = Duration::from_secs(2);

/// Skips DNS lookups for a while after one timed out. Alerts are processed
/// one at a time: with DNS unreachable, each would wait for the full timeout.
pub struct LookupBackoff {
    until: Mutex<Option<Instant>>,
}

impl LookupBackoff {
    pub const fn new() -> Self {
        Self { until: Mutex::new(None) }
    }

    pub fn is_active(&self, now: Instant) -> bool {
        let until = self.until.lock().unwrap_or_else(|e| e.into_inner());
        until.is_some_and(|until| now < until)
    }

    pub fn trip(&self, now: Instant) {
        *self.until.lock().unwrap_or_else(|e| e.into_inner()) = Some(now + LOOKUP_BACKOFF);
    }
}

/// Backoff for lookups through the system resolver.
static SYSTEM_RESOLVER_BACKOFF: LookupBackoff = LookupBackoff::new();

// ── Cache Entry ────────────────────────────────────────────────────────────

/// A single DNS cache entry with TTL-based expiration.
#[derive(Debug, Clone)]
pub struct DnsEntry {
    /// The resolved domain name (e.g. "ec2-1-2-3-4.compute.amazonaws.com").
    pub domain: String,
    /// When this entry was inserted or last refreshed.
    pub inserted_at: Instant,
    /// Time-to-live from the DNS response (or a default for PTR lookups).
    pub ttl: Duration,
    /// Source of the resolution: passive sniffing or reverse lookup.
    pub source: DnsSource,
}

/// How the DNS name was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsSource {
    /// Extracted from a DNS response packet on the wire.
    Passive,
    /// Resolved via an async PTR (reverse DNS) query.
    ReverseLookup,
}

impl DnsEntry {
    /// Returns `true` if this entry has exceeded its TTL.
    pub fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

// ── DNS Tracker (shared state) ─────────────────────────────────────────────

/// Thread-safe DNS cache mapping IP addresses to domain names.
///
/// Designed to be wrapped in `Arc` and shared between:
/// - The engine thread (reads via [`get_name`])
/// - The passive DNS parser (writes via [`ingest_dns_response`])
/// - The async exporter (writes via [`set_reverse`], reads via [`get_name`])
#[derive(Debug)]
pub struct DnsTracker {
    cache: DashMap<IpAddr, DnsEntry>,
    /// Addresses the system resolver has no name for, and when it said so.
    no_name: DashMap<IpAddr, Instant>,
}

impl DnsTracker {
    /// Create a new, empty DNS tracker.
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
            no_name: DashMap::new(),
        }
    }

    /// Wrap in an `Arc` for sharing across threads.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    // ── Reads ──────────────────────────────────────────────────────────

    /// Look up the domain name for an IP address.
    ///
    /// Returns `None` if the IP is not in the cache or the entry has expired.
    pub fn get_name(&self, ip: &IpAddr) -> Option<String> {
        let entry = self.cache.get(ip)?;
        if entry.is_expired() {
            // Lazy expiration: remove stale entries on read
            drop(entry); // release the read lock before removing
            self.cache.remove(ip);
            None
        } else {
            Some(entry.domain.clone())
        }
    }

    /// Check if an IP has a cached (non-expired) DNS entry.
    pub fn has_entry(&self, ip: &IpAddr) -> bool {
        self.get_name(ip).is_some()
    }

    /// Whether the system resolver recently said it has no name for this IP.
    fn is_known_nameless(&self, ip: &IpAddr, now: Instant) -> bool {
        self.no_name
            .get(ip)
            .is_some_and(|since| now.duration_since(*since) <= NO_NAME_TTL)
    }

    /// Return the number of entries currently in the cache (including expired).
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Return `true` if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    // ── Writes ─────────────────────────────────────────────────────────

    /// Insert or update a passive DNS entry (from a sniffed DNS response).
    pub fn set_passive(&self, ip: IpAddr, domain: String, ttl_secs: u32) {
        let ttl = Duration::from_secs(ttl_secs.max(60) as u64); // minimum 60s
        trace!(
            "[DnsTracker] Passive: {} → {} (TTL {}s)",
            ip,
            domain,
            ttl_secs
        );
        self.cache.insert(
            ip,
            DnsEntry {
                domain,
                inserted_at: Instant::now(),
                ttl,
                source: DnsSource::Passive,
            },
        );
    }

    /// Insert or update a reverse-DNS entry (from an async PTR lookup).
    pub fn set_reverse(&self, ip: IpAddr, domain: String) {
        // PTR results get a generous TTL since they change infrequently
        let ttl = Duration::from_secs(300);
        trace!("[DnsTracker] Reverse: {} → {}", ip, domain);
        // Only insert if there's no existing passive entry (passive wins)
        self.cache
            .entry(ip)
            .and_modify(|existing| {
                if existing.is_expired() || existing.source == DnsSource::ReverseLookup {
                    *existing = DnsEntry {
                        domain: domain.clone(),
                        inserted_at: Instant::now(),
                        ttl,
                        source: DnsSource::ReverseLookup,
                    };
                }
            })
            .or_insert_with(|| DnsEntry {
                domain,
                inserted_at: Instant::now(),
                ttl,
                source: DnsSource::ReverseLookup,
            });
    }

    /// Evict all expired entries. Call periodically from a maintenance task.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.no_name.retain(|_ip, since| now.duration_since(*since) <= NO_NAME_TTL);

        let before = self.cache.len();
        self.cache.retain(|_ip, entry| !entry.is_expired());
        let evicted = before - self.cache.len();
        if evicted > 0 {
            debug!("[DnsTracker] Evicted {} expired entries", evicted);
        }
    }
}

// ── Passive DNS Parser ─────────────────────────────────────────────────────
//
// Parses raw DNS response packets (UDP port 53) and extracts A/AAAA records
// with their TTLs. This is called from the engine thread's hot path, so it
// must be fast and allocation-light.

/// Parse a DNS response packet and feed resolved names into the tracker.
///
/// # Arguments
/// * `dns_payload` — The UDP payload (DNS wire format, starting at the DNS header).
/// * `tracker`     — Shared DNS tracker to populate.
///
/// Returns the number of records extracted.
pub fn ingest_dns_response(dns_payload: &[u8], tracker: &DnsTracker) -> usize {
    // DNS header is 12 bytes minimum
    if dns_payload.len() < 12 {
        return 0;
    }

    // Check QR bit (bit 15 of flags) — we only want responses
    let flags = u16::from_be_bytes([dns_payload[2], dns_payload[3]]);
    let is_response = (flags & 0x8000) != 0;
    if !is_response {
        return 0;
    }

    // Check RCODE — only process successful responses (RCODE == 0)
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return 0;
    }

    let qd_count = u16::from_be_bytes([dns_payload[4], dns_payload[5]]) as usize;
    let an_count = u16::from_be_bytes([dns_payload[6], dns_payload[7]]) as usize;

    if an_count == 0 {
        return 0;
    }

    // Skip the question section
    let mut pos = 12;
    for _ in 0..qd_count {
        pos = match skip_dns_name(dns_payload, pos) {
            Some(p) => p,
            None => return 0,
        };
        pos += 4; // QTYPE (2) + QCLASS (2)
        if pos > dns_payload.len() {
            return 0;
        }
    }

    // Parse answer section — extract A and AAAA records
    let mut extracted = 0;
    for _ in 0..an_count {
        if pos >= dns_payload.len() {
            break;
        }

        // Read the name this record answers for
        let (name, next_pos) = match read_dns_name(dns_payload, pos) {
            Some(result) => result,
            None => break,
        };
        pos = next_pos;

        // Need at least 10 bytes for TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
        if pos + 10 > dns_payload.len() {
            break;
        }

        let rtype = u16::from_be_bytes([dns_payload[pos], dns_payload[pos + 1]]);
        let _rclass = u16::from_be_bytes([dns_payload[pos + 2], dns_payload[pos + 3]]);
        let ttl = u32::from_be_bytes([
            dns_payload[pos + 4],
            dns_payload[pos + 5],
            dns_payload[pos + 6],
            dns_payload[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([dns_payload[pos + 8], dns_payload[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > dns_payload.len() {
            break;
        }

        match rtype {
            1 if rdlength == 4 => {
                // A record → IPv4
                let ip = IpAddr::V4(Ipv4Addr::new(
                    dns_payload[pos],
                    dns_payload[pos + 1],
                    dns_payload[pos + 2],
                    dns_payload[pos + 3],
                ));
                if !name.is_empty() {
                    tracker.set_passive(ip, name.clone(), ttl);
                    extracted += 1;
                }
            }
            28 if rdlength == 16 => {
                // AAAA record → IPv6
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&dns_payload[pos..pos + 16]);
                let ip = IpAddr::V6(Ipv6Addr::from(octets));
                if !name.is_empty() {
                    tracker.set_passive(ip, name.clone(), ttl);
                    extracted += 1;
                }
            }
            _ => {
                // Skip other record types (CNAME, MX, etc.)
            }
        }

        pos += rdlength;
    }

    if extracted > 0 {
        debug!(
            "[DnsTracker] Ingested {} records from DNS response",
            extracted
        );
    }

    extracted
}

// ── DNS Wire Format Helpers ────────────────────────────────────────────────

/// Skip over a DNS name in wire format (handles compression pointers).
/// Returns the position after the name.
fn skip_dns_name(data: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0;
    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            // Compression pointer — 2 bytes total, name ends here
            return Some(pos + 2);
        }
        pos += 1 + len;
        jumps += 1;
        if jumps > 128 {
            return None; // Prevent infinite loops
        }
    }
}

/// Read a DNS name from wire format, following compression pointers.
/// Returns (name, position_after_name_field).
fn read_dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut parts: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end_pos: Option<usize> = None;
    let mut jumps = 0;

    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;

        if len == 0 {
            if end_pos.is_none() {
                end_pos = Some(pos + 1);
            }
            break;
        }

        if (len & 0xC0) == 0xC0 {
            // Compression pointer
            if pos + 1 >= data.len() {
                return None;
            }
            if end_pos.is_none() {
                end_pos = Some(pos + 2);
            }
            let offset = ((len & 0x3F) << 8) | (data[pos + 1] as usize);
            pos = offset;
            jumps += 1;
            if jumps > 128 {
                return None; // Prevent infinite loops
            }
            continue;
        }

        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        let label = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
        parts.push(label);
        pos += len;
    }

    let name = parts.join(".");
    Some((name, end_pos.unwrap_or(pos)))
}

// ── Reverse DNS (Async) ───────────────────────────────────────────────────

/// Perform an async reverse DNS (PTR) lookup for the given IP.
///
/// This is intended to be called from the Tokio exporter task when an IP
/// has no passive DNS entry. Uses the system resolver via `getnameinfo`.
///
/// Returns `Some(domain)` on success, `None` on failure or timeout. Addresses
/// known to have no name are not looked up again for a while, and nothing is
/// looked up for a while after a lookup timed out.
pub async fn reverse_lookup(tracker: &DnsTracker, ip: IpAddr) -> Option<String> {
    let started = Instant::now();
    if SYSTEM_RESOLVER_BACKOFF.is_active(started) || tracker.is_known_nameless(&ip, started) {
        return None;
    }

    let answer = tokio::task::spawn_blocking(move || reverse_lookup_blocking(ip)).await.ok()?;
    let now = Instant::now();
    match answer {
        SystemLookup::Name(name) => Some(name),
        SystemLookup::NoName if now.duration_since(started) < SLOW_LOOKUP => {
            tracker.no_name.insert(ip, now);
            None
        }
        SystemLookup::NoName | SystemLookup::Unavailable => {
            SYSTEM_RESOLVER_BACKOFF.trip(now);
            None
        }
        SystemLookup::Failed => None,
    }
}

/// Outcome of a lookup through the system resolver.
enum SystemLookup {
    Name(String),
    /// The resolver answered: this address has no name.
    NoName,
    /// The resolver could not be reached in time.
    Unavailable,
    /// Any other error.
    Failed,
}

/// Blocking reverse DNS lookup using libc getnameinfo.
fn reverse_lookup_blocking(ip: IpAddr) -> SystemLookup {
    use std::ffi::CStr;

    let mut host_buf = [0u8; 256];

    let ret = match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_addr.s_addr = u32::from_ne_bytes(octets);
            // BSD-family sockaddrs carry their own length; Linux has no such field.
            #[cfg(target_os = "macos")]
            {
                sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            }
            unsafe {
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host_buf.as_mut_ptr() as *mut libc::c_char,
                    host_buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_addr.s6_addr = octets;
            #[cfg(target_os = "macos")]
            {
                sa.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
            }
            unsafe {
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host_buf.as_mut_ptr() as *mut libc::c_char,
                    host_buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };

    match ret {
        0 => {
            let c_str = unsafe { CStr::from_ptr(host_buf.as_ptr() as *const libc::c_char) };
            let name = c_str.to_string_lossy().to_string();
            // If getnameinfo just returned the IP as a string, treat as no result
            if name == ip.to_string() {
                SystemLookup::NoName
            } else {
                SystemLookup::Name(name)
            }
        }
        libc::EAI_NONAME => SystemLookup::NoName,
        libc::EAI_AGAIN => SystemLookup::Unavailable,
        _ => SystemLookup::Failed,
    }
}

// ── Security Scoring ───────────────────────────────────────────────────────

/// Result of DNS-based confidence adjustment.
#[derive(Debug, Clone)]
pub struct DnsConfidenceAdjustment {
    /// The adjusted confidence score (0–100).
    pub confidence: u8,
    /// Human-readable reason for the adjustment.
    pub reason: String,
    /// The resolved domain name, if any.
    pub domain: Option<String>,
}

/// Service keywords in domains that strongly indicate legitimate traffic.
/// If a resolved domain contains any of these, confidence is reduced by 90 points.
const SERVICE_KEYWORDS: &[&str] = &[
    // Email / messaging
    "exchange",
    "outlook",
    "mail",
    "imap",
    "smtp",
    "pop3",
    "postfix",
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
    "swscan",       // Apple software update
    "mesu.apple",   // Apple software update
    "officecdn",
    "delivery.mp.microsoft",
    // Authentication / SSO
    "login",
    "auth",
    "sso",
    "adfs",
    "microsoftonline",
    "okta",
    // DNS / NTP infrastructure
    "ntp",
    "time.apple",
    "time.windows",
    "dns",
    "resolver",
];

/// Known benign domain suffixes that reduce suspicion.
const TRUSTED_SUFFIXES: &[&str] = &[
    ".amazonaws.com",
    ".cloudflare.com",
    ".cloudfront.net",
    ".akamai.net",
    ".akamaiedge.net",
    ".google.com",
    ".googleapis.com",
    ".googlevideo.com",
    ".microsoft.com",
    ".azure.com",
    ".azureedge.net",
    ".office.net",
    ".office365.com",
    ".windows.net",
    ".apple.com",
    ".icloud.com",
    ".fastly.net",
    ".cdn77.org",
    ".edgecastcdn.net",
    ".github.com",
    ".github.io",
    ".gitlab.com",
];

/// Adjust the confidence score of an alert based on DNS resolution.
///
/// # Logic
/// - If the domain is a known CDN/cloud provider → **decrease** confidence
///   (likely legitimate traffic).
/// - If the IP has no DNS name and the traffic has high entropy → **increase**
///   confidence (suspicious "dark" traffic).
/// - Otherwise, add the domain name as metadata without changing the score.
///
/// # Arguments
/// * `tracker`            — The shared DNS tracker.
/// * `ip`                 — The IP address to look up.
/// * `current_confidence` — The current confidence score (0–100).
/// * `entropy`            — Shannon entropy of the traffic (0.0–8.0), if available.
pub fn adjust_confidence(
    tracker: &DnsTracker,
    ip: &IpAddr,
    current_confidence: u8,
    entropy: Option<f64>,
) -> DnsConfidenceAdjustment {
    match tracker.get_name(ip) {
        Some(domain) => {
            let domain_lower = domain.to_lowercase();

            // ── Service Keyword Filter ──────────────────────────────
            // If the resolved domain contains service-related keywords
            // (exchange, outlook, mail, imap), this is almost certainly
            // legitimate email/service traffic — reduce confidence by 90.
            let matched_service_kw = SERVICE_KEYWORDS
                .iter()
                .find(|kw| domain_lower.contains(**kw));

            if let Some(keyword) = matched_service_kw {
                let reduction = 90u8;
                let new_confidence = current_confidence.saturating_sub(reduction);
                return DnsConfidenceAdjustment {
                    confidence: new_confidence,
                    reason: format!(
                        "DNS '{}' contains service keyword '{}' (-{} confidence)",
                        domain, keyword, reduction
                    ),
                    domain: Some(domain),
                };
            }

            // Check if domain matches a trusted suffix
            let is_trusted = TRUSTED_SUFFIXES
                .iter()
                .any(|suffix| domain_lower.ends_with(suffix));

            if is_trusted {
                // Decrease confidence for known CDN/cloud traffic
                let reduction = 20u8;
                let new_confidence = current_confidence.saturating_sub(reduction);
                DnsConfidenceAdjustment {
                    confidence: new_confidence,
                    reason: format!(
                        "DNS resolved to trusted domain '{}' (-{} confidence)",
                        domain, reduction
                    ),
                    domain: Some(domain),
                }
            } else {
                // Domain is known but not trusted — no change, just enrich
                DnsConfidenceAdjustment {
                    confidence: current_confidence,
                    reason: format!("DNS resolved to '{}'", domain),
                    domain: Some(domain),
                }
            }
        }
        None => {
            // No DNS name — check if this is suspicious "dark" traffic
            if let Some(ent) = entropy {
                if ent > 6.0 {
                    // High entropy + no DNS name = suspicious
                    let boost = 10u8;
                    let new_confidence = current_confidence.saturating_add(boost).min(100);
                    DnsConfidenceAdjustment {
                        confidence: new_confidence,
                        reason: format!(
                            "No DNS name for IP, high entropy ({:.2}) — dark traffic (+{} confidence)",
                            ent, boost
                        ),
                        domain: None,
                    }
                } else {
                    DnsConfidenceAdjustment {
                        confidence: current_confidence,
                        reason: "No DNS name for IP".to_string(),
                        domain: None,
                    }
                }
            } else {
                DnsConfidenceAdjustment {
                    confidence: current_confidence,
                    reason: "No DNS name for IP".to_string(),
                    domain: None,
                }
            }
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nameless_addresses_are_remembered_for_a_while() {
        let tracker = DnsTracker::new();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let now = Instant::now();
        assert!(!tracker.is_known_nameless(&ip, now));

        tracker.no_name.insert(ip, now);
        assert!(tracker.is_known_nameless(&ip, now + NO_NAME_TTL));
        assert!(!tracker.is_known_nameless(&ip, now + NO_NAME_TTL + Duration::from_secs(1)));
    }

    #[test]
    fn evicting_forgets_old_nameless_addresses() {
        let tracker = DnsTracker::new();
        let (old, recent): (IpAddr, IpAddr) = ("203.0.113.7".parse().unwrap(), "203.0.113.8".parse().unwrap());
        let now = Instant::now();
        let long_ago = now.checked_sub(NO_NAME_TTL + Duration::from_secs(1)).expect("uptime");
        tracker.no_name.insert(old, long_ago);
        tracker.no_name.insert(recent, now);

        tracker.evict_expired();
        assert!(!tracker.no_name.contains_key(&old));
        assert!(tracker.no_name.contains_key(&recent));
    }

    #[test]
    fn backoff_lasts_for_its_period() {
        let backoff = LookupBackoff::new();
        let now = Instant::now();
        assert!(!backoff.is_active(now));

        backoff.trip(now);
        assert!(backoff.is_active(now + LOOKUP_BACKOFF - Duration::from_secs(1)));
        assert!(!backoff.is_active(now + LOOKUP_BACKOFF));
    }

    #[test]
    fn test_cache_basic_operations() {
        let tracker = DnsTracker::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(tracker.get_name(&ip).is_none());

        tracker.set_passive(ip, "example.com".to_string(), 300);
        assert_eq!(tracker.get_name(&ip), Some("example.com".to_string()));
        assert!(tracker.has_entry(&ip));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn test_reverse_does_not_overwrite_passive() {
        let tracker = DnsTracker::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        tracker.set_passive(ip, "passive.example.com".to_string(), 300);
        tracker.set_reverse(ip, "reverse.example.com".to_string());

        // Passive entry should win
        assert_eq!(
            tracker.get_name(&ip),
            Some("passive.example.com".to_string())
        );
    }

    #[test]
    fn test_trusted_domain_reduces_confidence() {
        let tracker = DnsTracker::new();
        let ip: IpAddr = "52.94.76.1".parse().unwrap();
        tracker.set_passive(ip, "ec2-52-94-76-1.compute.amazonaws.com".to_string(), 300);

        let adj = adjust_confidence(&tracker, &ip, 80, Some(7.5));
        assert!(adj.confidence < 80);
        assert!(adj.domain.is_some());
    }

    #[test]
    fn test_dark_traffic_increases_confidence() {
        let tracker = DnsTracker::new();
        let ip: IpAddr = "185.220.101.1".parse().unwrap();
        // No DNS entry for this IP

        let adj = adjust_confidence(&tracker, &ip, 70, Some(7.8));
        assert!(adj.confidence > 70);
        assert!(adj.domain.is_none());
    }

    #[test]
    fn test_dns_response_parsing() {
        // Minimal DNS response: 1 question, 1 A record answer
        // Header: ID=0x1234, QR=1 (response), RCODE=0, QDCOUNT=1, ANCOUNT=1
        let mut pkt = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: QR=1, RD=1, RA=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];

        // Question: example.com, type A, class IN
        // "example" (7 bytes)
        pkt.push(7);
        pkt.extend_from_slice(b"example");
        // "com" (3 bytes)
        pkt.push(3);
        pkt.extend_from_slice(b"com");
        // null terminator
        pkt.push(0);
        // QTYPE = A (1), QCLASS = IN (1)
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        // Answer: example.com (pointer to offset 12), type A, class IN, TTL=300, RDLENGTH=4, RDATA=93.184.216.34
        pkt.extend_from_slice(&[0xC0, 0x0C]); // Name pointer to offset 12
        pkt.extend_from_slice(&[0x00, 0x01]); // TYPE = A
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL = 300
        pkt.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        pkt.extend_from_slice(&[93, 184, 216, 34]); // RDATA = 93.184.216.34

        let tracker = DnsTracker::new();
        let count = ingest_dns_response(&pkt, &tracker);

        assert_eq!(count, 1);
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(tracker.get_name(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn test_service_keyword_reduces_confidence_by_90() {
        let tracker = DnsTracker::new();

        // "outlook" keyword
        let ip1: IpAddr = "40.97.128.1".parse().unwrap();
        tracker.set_passive(ip1, "outlook.office365.com".to_string(), 300);
        let adj = adjust_confidence(&tracker, &ip1, 95, None);
        assert_eq!(adj.confidence, 5); // 95 - 90
        assert!(adj.reason.contains("outlook"));

        // "mail" keyword
        let ip2: IpAddr = "142.250.74.5".parse().unwrap();
        tracker.set_passive(ip2, "mail.google.com".to_string(), 300);
        let adj = adjust_confidence(&tracker, &ip2, 80, None);
        assert_eq!(adj.confidence, 0); // 80 - 90, saturates to 0
        assert!(adj.reason.contains("mail"));

        // "exchange" keyword
        let ip3: IpAddr = "10.0.0.50".parse().unwrap();
        tracker.set_passive(ip3, "exchange.corp.example.com".to_string(), 300);
        let adj = adjust_confidence(&tracker, &ip3, 100, None);
        assert_eq!(adj.confidence, 10); // 100 - 90
        assert!(adj.reason.contains("exchange"));

        // "imap" keyword
        let ip4: IpAddr = "10.0.0.51".parse().unwrap();
        tracker.set_passive(ip4, "imap.fastmail.com".to_string(), 300);
        let adj = adjust_confidence(&tracker, &ip4, 50, None);
        assert_eq!(adj.confidence, 0); // 50 - 90, saturates to 0
        assert!(adj.reason.contains("imap"));
    }

    #[test]
    fn test_service_keyword_takes_priority_over_trusted_suffix() {
        let tracker = DnsTracker::new();
        // Domain matches both a service keyword ("mail") and a trusted suffix (".google.com")
        let ip: IpAddr = "142.250.74.5".parse().unwrap();
        tracker.set_passive(ip, "mail.google.com".to_string(), 300);
        let adj = adjust_confidence(&tracker, &ip, 80, None);
        // Service keyword filter should apply (-90), not trusted suffix (-20)
        assert_eq!(adj.confidence, 0); // 80 - 90, saturates to 0
        assert!(adj.reason.contains("service keyword"));
    }

    #[test]
    fn test_ignores_dns_queries() {
        // DNS query (QR=0)
        let pkt = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: QR=0 (query)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, 0x00, 0x00,
        ];

        let tracker = DnsTracker::new();
        let count = ingest_dns_response(&pkt, &tracker);
        assert_eq!(count, 0);
    }
}
