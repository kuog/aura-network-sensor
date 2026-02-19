//! Active DNS Resolution & Security Analysis for Alert Enrichment.
//!
//! This module provides a high-performance, async DNS resolver built on
//! [`hickory_resolver::AsyncResolver`] (the modern successor to trust-dns).
//! It complements the passive DNS tracking in [`super::dns_tracker`] by
//! performing active reverse lookups and applying security heuristics.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────┐     ┌──────────────┐     ┌──────────────────────┐
//! │  Engine (S2)  │────▶│  DnsCache    │────▶│  Alert Metadata      │
//! │  check cache  │     │  (DashMap)   │     │  hostname enrichment │
//! └──────────────┘     └──────┬───────┘     └──────────────────────┘
//!                             │ miss
//!                             ▼
//!                      ┌──────────────┐
//!                      │ Background   │
//!                      │ Tokio Task   │
//!                      │ (AsyncResolver)│
//!                      └──────┬───────┘
//!                             │
//!                      ┌──────▼───────┐
//!                      │ Security     │
//!                      │ Analysis     │
//!                      │ • Fast Flux  │
//!                      │ • Squatting  │
//!                      │ • Known Good │
//!                      └──────────────┘
//! ```
//!
//! ## Features
//!
//! - **TTL-aware cache** using `DashMap<IpAddr, CacheEntry>` with per-entry
//!   expiration derived from DNS response TTLs.
//! - **Async reverse lookup** via `hickory_resolver::AsyncResolver::reverse_lookup`.
//! - **Known Good pattern matching**: domains matching `*.microsoft.com`,
//!   `*.apple.com`, etc. automatically reduce alert severity to INFO.
//! - **DNS Fast Flux detection**: IPs with rapidly changing hostnames get
//!   increased confidence scores.
//! - **Domain Squatting detection**: Levenshtein distance checks against
//!   well-known brands (e.g. `g00gle.com` vs `google.com`).
//!
//! ## MITRE Coverage
//! - **T1568.001** (Fast Flux DNS) — detected via name-change velocity.
//! - **T1583.001** (Domain Squatting) — detected via Levenshtein distance.

use dashmap::DashMap;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use log::{debug, info, trace, warn};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::OnceCell;

use crate::pipeline::alert::{MitreAlert, Severity};

/// Convenience alias for the Tokio-backed async resolver.
type TokioResolver = Resolver<TokioConnectionProvider>;

// ═══════════════════════════════════════════════════════════════════════════
// Cache Entry
// ═══════════════════════════════════════════════════════════════════════════

/// A single entry in the DNS resolution cache.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The resolved hostname (e.g. `"ec2-1-2-3-4.compute.amazonaws.com"`).
    pub hostname: String,
    /// When this entry was inserted or last refreshed.
    pub inserted_at: Instant,
    /// Time-to-live derived from the DNS response.
    pub ttl: Duration,
    /// Historical hostnames seen for this IP (for fast-flux detection).
    /// Stores `(hostname, timestamp)` pairs.
    pub history: Vec<(String, Instant)>,
}

impl CacheEntry {
    /// Returns `true` if this entry has exceeded its TTL.
    pub fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DNS Cache
// ═══════════════════════════════════════════════════════════════════════════

/// Default TTL for reverse DNS lookups when no TTL is provided (5 minutes).
const DEFAULT_REVERSE_TTL: Duration = Duration::from_secs(300);

/// Maximum number of historical hostnames to retain per IP for fast-flux
/// detection.
const MAX_HISTORY_PER_IP: usize = 20;

/// Time window for fast-flux detection: if an IP has ≥ `FAST_FLUX_THRESHOLD`
/// distinct hostnames within this window, it is flagged.
const FAST_FLUX_WINDOW: Duration = Duration::from_secs(600); // 10 minutes

/// Minimum number of distinct hostnames within [`FAST_FLUX_WINDOW`] to
/// trigger a fast-flux alert.
const FAST_FLUX_THRESHOLD: usize = 5;

/// Thread-safe DNS resolution cache with TTL-based expiration.
///
/// Designed to be wrapped in `Arc` and shared between:
/// - The engine thread (synchronous reads via [`get`])
/// - The async exporter (writes via [`resolve_and_cache`])
#[derive(Debug)]
pub struct DnsCache {
    /// IP → resolved hostname + metadata.
    entries: DashMap<IpAddr, CacheEntry>,
}

impl DnsCache {
    /// Create a new, empty DNS cache.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Wrap in an `Arc` for sharing across threads.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    // ── Reads ──────────────────────────────────────────────────────────

    /// Look up the cached hostname for an IP address.
    ///
    /// Returns `None` if the IP is not cached or the entry has expired.
    /// Expired entries are lazily removed on read.
    pub fn get(&self, ip: &IpAddr) -> Option<String> {
        let entry = self.entries.get(ip)?;
        if entry.is_expired() {
            drop(entry);
            self.entries.remove(ip);
            None
        } else {
            Some(entry.hostname.clone())
        }
    }

    /// Check if an IP has a cached (non-expired) entry.
    pub fn has_entry(&self, ip: &IpAddr) -> bool {
        self.get(ip).is_some()
    }

    /// Return the full [`CacheEntry`] for an IP (including history).
    pub fn get_entry(&self, ip: &IpAddr) -> Option<CacheEntry> {
        let entry = self.entries.get(ip)?;
        if entry.is_expired() {
            drop(entry);
            self.entries.remove(ip);
            None
        } else {
            Some(entry.clone())
        }
    }

    /// Return the number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // ── Writes ─────────────────────────────────────────────────────────

    /// Insert or update a cache entry.
    ///
    /// If the IP already exists, the hostname history is preserved and
    /// appended to (for fast-flux detection). If the hostname has changed,
    /// the old hostname is pushed into the history ring buffer.
    pub fn insert(&self, ip: IpAddr, hostname: String, ttl: Duration) {
        let now = Instant::now();

        self.entries
            .entry(ip)
            .and_modify(|existing| {
                // Track hostname changes for fast-flux detection
                if existing.hostname != hostname {
                    existing
                        .history
                        .push((existing.hostname.clone(), existing.inserted_at));
                    // Trim history to MAX_HISTORY_PER_IP
                    if existing.history.len() > MAX_HISTORY_PER_IP {
                        existing.history.remove(0);
                    }
                }
                existing.hostname = hostname.clone();
                existing.inserted_at = now;
                existing.ttl = ttl;
            })
            .or_insert_with(|| CacheEntry {
                hostname,
                inserted_at: now,
                ttl,
                history: Vec::new(),
            });
    }

    /// Evict all expired entries. Call periodically from a maintenance task.
    pub fn evict_expired(&self) {
        let before = self.entries.len();
        self.entries.retain(|_ip, entry| !entry.is_expired());
        let evicted = before - self.entries.len();
        if evicted > 0 {
            debug!("[DnsResolver] Evicted {} expired cache entries", evicted);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Async Resolver (hickory-resolver)
// ═══════════════════════════════════════════════════════════════════════════

/// Global async resolver instance, initialized once per Tokio runtime.
static ASYNC_RESOLVER: OnceCell<TokioResolver> = OnceCell::const_new();

/// Get or initialize the global async DNS resolver.
///
/// Uses the system's `/etc/resolv.conf` configuration on Unix, or the
/// Google/Cloudflare public resolvers as fallback.
async fn get_resolver() -> &'static TokioResolver {
    ASYNC_RESOLVER
        .get_or_init(|| async {
            // Build the resolver with default config + Tokio provider
            let mut builder = Resolver::builder_with_config(
                ResolverConfig::default(),
                TokioConnectionProvider::default(),
            );
            let opts = builder.options_mut();
            opts.timeout = Duration::from_secs(3);
            opts.attempts = 2;
            opts.cache_size = 256;

            let resolver = builder.build();
            info!("[DnsResolver] Async resolver initialized (hickory-resolver)");
            resolver
        })
        .await
}

/// Perform an async reverse DNS (PTR) lookup for the given IP using
/// `hickory_resolver::AsyncResolver`.
///
/// Returns `Some((hostname, ttl))` on success, `None` on failure or timeout.
///
/// This function is non-blocking and safe to call from the Tokio exporter
/// task. It will **not** block the main packet capture loop.
pub async fn reverse_lookup(ip: IpAddr) -> Option<(String, Duration)> {
    let resolver = get_resolver().await;

    // Apply a timeout to prevent hanging on unresponsive DNS servers
    let result = tokio::time::timeout(Duration::from_secs(5), resolver.reverse_lookup(ip)).await;

    match result {
        Ok(Ok(lookup)) => {
            // Take the first PTR record
            if let Some(name) = lookup.iter().next() {
                let hostname = name.to_string().trim_end_matches('.').to_string();
                // hickory-resolver doesn't directly expose per-record TTL in
                // reverse_lookup results, so we use a sensible default.
                let ttl = DEFAULT_REVERSE_TTL;
                debug!("[DnsResolver] Reverse lookup: {} → {} (TTL {}s)", ip, hostname, ttl.as_secs());
                Some((hostname, ttl))
            } else {
                trace!("[DnsResolver] Reverse lookup for {} returned empty result", ip);
                None
            }
        }
        Ok(Err(e)) => {
            trace!("[DnsResolver] Reverse lookup failed for {}: {}", ip, e);
            None
        }
        Err(_) => {
            warn!("[DnsResolver] Reverse lookup timed out for {}", ip);
            None
        }
    }
}

/// Resolve an IP and insert the result into the cache.
///
/// This is the primary entry point for background DNS resolution from the
/// Tokio exporter. It performs the lookup, caches the result, and returns
/// the hostname (if resolved).
pub async fn resolve_and_cache(ip: IpAddr, cache: &DnsCache) -> Option<String> {
    if let Some(hostname) = cache.get(&ip) {
        return Some(hostname);
    }

    if let Some((hostname, ttl)) = reverse_lookup(ip).await {
        cache.insert(ip, hostname.clone(), ttl);
        Some(hostname)
    } else {
        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Known Good Pattern Matching
// ═══════════════════════════════════════════════════════════════════════════

/// Domain suffixes considered "Known Good" — traffic to these domains is
/// almost certainly legitimate and should have severity reduced to INFO.
const KNOWN_GOOD_SUFFIXES: &[&str] = &[
    // Microsoft
    ".microsoft.com",
    ".windows.com",
    ".windows.net",
    ".azure.com",
    ".azureedge.net",
    ".office.com",
    ".office.net",
    ".office365.com",
    ".live.com",
    ".outlook.com",
    ".msn.com",
    ".bing.com",
    ".skype.com",
    ".visualstudio.com",
    // Apple
    ".apple.com",
    ".icloud.com",
    ".icloud-content.com",
    ".mzstatic.com",
    ".cdn-apple.com",
    // Google
    ".google.com",
    ".googleapis.com",
    ".googlevideo.com",
    ".gstatic.com",
    ".youtube.com",
    ".ytimg.com",
    ".android.com",
    ".chromium.org",
    // Amazon / AWS
    ".amazonaws.com",
    ".amazon.com",
    ".cloudfront.net",
    ".aws.amazon.com",
    // Cloudflare
    ".cloudflare.com",
    ".cloudflare-dns.com",
    // Akamai
    ".akamai.net",
    ".akamaiedge.net",
    ".akamaized.net",
    // Fastly
    ".fastly.net",
    ".fastlylb.net",
    // GitHub
    ".github.com",
    ".github.io",
    ".githubusercontent.com",
    ".githubassets.com",
    // Other major providers
    ".gitlab.com",
    ".docker.com",
    ".docker.io",
    ".mozilla.org",
    ".mozilla.com",
    ".firefox.com",
    ".ubuntu.com",
    ".debian.org",
    ".fedoraproject.org",
    ".centos.org",
    ".redhat.com",
];

/// Check if a hostname matches a "Known Good" pattern.
///
/// Returns `true` if the hostname ends with any of the trusted suffixes.
pub fn is_known_good(hostname: &str) -> bool {
    let lower = hostname.to_lowercase();
    KNOWN_GOOD_SUFFIXES
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

// ═══════════════════════════════════════════════════════════════════════════
// DNS Fast Flux Detection (T1568.001)
// ═══════════════════════════════════════════════════════════════════════════

/// Result of fast-flux analysis for a single IP.
#[derive(Debug, Clone)]
pub struct FastFluxResult {
    /// Whether fast-flux behavior was detected.
    pub is_fast_flux: bool,
    /// Number of distinct hostnames seen within the detection window.
    pub distinct_names: usize,
    /// Confidence boost to apply (0 if not fast-flux).
    pub confidence_boost: u8,
    /// Human-readable explanation.
    pub reason: String,
}

/// Analyze an IP's hostname history for fast-flux behavior.
///
/// Fast flux is a DNS technique used by botnets where a single domain
/// resolves to many different IPs (or vice versa: a single IP maps to
/// many different hostnames) in rapid succession.
///
/// We detect the reverse case: an IP that has been associated with
/// multiple distinct hostnames within a short time window.
pub fn detect_fast_flux(cache: &DnsCache, ip: &IpAddr) -> FastFluxResult {
    let entry = match cache.get_entry(ip) {
        Some(e) => e,
        None => {
            return FastFluxResult {
                is_fast_flux: false,
                distinct_names: 0,
                confidence_boost: 0,
                reason: "No cache entry".to_string(),
            };
        }
    };

    let now = Instant::now();
    let window_start = now - FAST_FLUX_WINDOW;

    // Collect distinct hostnames within the detection window
    let mut recent_names: Vec<&str> = Vec::new();

    // Include current hostname
    recent_names.push(&entry.hostname);

    // Include historical hostnames within the window
    for (name, ts) in &entry.history {
        if *ts >= window_start && !recent_names.contains(&name.as_str()) {
            recent_names.push(name);
        }
    }

    let distinct = recent_names.len();

    if distinct >= FAST_FLUX_THRESHOLD {
        let boost = ((distinct - FAST_FLUX_THRESHOLD + 1) * 5).min(25) as u8;
        FastFluxResult {
            is_fast_flux: true,
            distinct_names: distinct,
            confidence_boost: boost,
            reason: format!(
                "Fast flux detected: {} distinct hostnames for {} in {}s window (threshold: {})",
                distinct,
                ip,
                FAST_FLUX_WINDOW.as_secs(),
                FAST_FLUX_THRESHOLD,
            ),
        }
    } else {
        FastFluxResult {
            is_fast_flux: false,
            distinct_names: distinct,
            confidence_boost: 0,
            reason: format!(
                "No fast flux: {} distinct hostnames (threshold: {})",
                distinct, FAST_FLUX_THRESHOLD,
            ),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Domain Squatting Detection (T1583.001)
// ═══════════════════════════════════════════════════════════════════════════

/// Well-known brand domains to check against for squatting detection.
const BRAND_DOMAINS: &[&str] = &[
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "twitter.com",
    "github.com",
    "linkedin.com",
    "paypal.com",
    "netflix.com",
    "instagram.com",
    "whatsapp.com",
    "youtube.com",
    "outlook.com",
    "office.com",
    "dropbox.com",
    "slack.com",
    "zoom.us",
    "chase.com",
    "wellsfargo.com",
    "bankofamerica.com",
    "citibank.com",
];

/// Maximum Levenshtein distance to consider a domain as a potential squat.
const SQUATTING_MAX_DISTANCE: usize = 2;

/// Result of domain squatting analysis.
#[derive(Debug, Clone)]
pub struct SquattingResult {
    /// Whether the domain looks like a squat of a known brand.
    pub is_squatting: bool,
    /// The brand domain it most closely resembles (if any).
    pub similar_to: Option<String>,
    /// The Levenshtein distance to the closest brand.
    pub distance: usize,
    /// Confidence boost to apply (0 if not squatting).
    pub confidence_boost: u8,
    /// Human-readable explanation.
    pub reason: String,
}

/// Compute the Levenshtein edit distance between two strings.
///
/// This is a standard dynamic-programming implementation with O(n*m) time
/// and O(min(n,m)) space.
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();

    // Ensure `a` is the shorter string for space optimization
    if a_len > b_len {
        return levenshtein_distance(b, a);
    }

    let mut prev_row: Vec<usize> = (0..=a_len).collect();
    let mut curr_row: Vec<usize> = vec![0; a_len + 1];

    for (j, b_char) in b.chars().enumerate() {
        curr_row[0] = j + 1;
        for (i, a_char) in a.chars().enumerate() {
            let cost = if a_char == b_char { 0 } else { 1 };
            curr_row[i + 1] = (prev_row[i + 1] + 1) // deletion
                .min(curr_row[i] + 1) // insertion
                .min(prev_row[i] + cost); // substitution
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[a_len]
}

/// Extract the registrable domain from a hostname.
///
/// For example: `"mail.g00gle.com"` → `"g00gle.com"`.
/// This is a simplified extraction that takes the last two labels.
fn extract_domain(hostname: &str) -> String {
    let parts: Vec<&str> = hostname.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        hostname.to_string()
    }
}

/// Check if a hostname looks like a domain squat of a well-known brand.
///
/// Uses Levenshtein distance to detect typosquatting, homoglyph attacks,
/// and similar deceptive domain names (e.g. `g00gle.com`, `micr0soft.com`).
pub fn detect_squatting(hostname: &str) -> SquattingResult {
    let lowered = hostname.to_lowercase();
    let domain = extract_domain(&lowered);

    // Don't flag exact matches — those are the real domains
    if BRAND_DOMAINS.contains(&domain.as_str()) {
        return SquattingResult {
            is_squatting: false,
            similar_to: None,
            distance: 0,
            confidence_boost: 0,
            reason: format!("'{}' is a legitimate brand domain", domain),
        };
    }

    let mut best_match: Option<(&str, usize)> = None;

    for &brand in BRAND_DOMAINS {
        let dist = levenshtein_distance(&domain, brand);
        if dist > 0 && dist <= SQUATTING_MAX_DISTANCE {
            if best_match.is_none() || dist < best_match.unwrap().1 {
                best_match = Some((brand, dist));
            }
        }
    }

    match best_match {
        Some((brand, dist)) => {
            let boost = if dist == 1 { 20 } else { 15 };
            SquattingResult {
                is_squatting: true,
                similar_to: Some(brand.to_string()),
                distance: dist,
                confidence_boost: boost,
                reason: format!(
                    "Domain squatting suspected: '{}' is Levenshtein distance {} from '{}'",
                    domain, dist, brand,
                ),
            }
        }
        None => SquattingResult {
            is_squatting: false,
            similar_to: None,
            distance: usize::MAX,
            confidence_boost: 0,
            reason: format!("'{}' does not resemble any known brand", domain),
        },
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Alert Enrichment (Integration Point)
// ═══════════════════════════════════════════════════════════════════════════

/// Result of DNS-based alert enrichment.
#[derive(Debug, Clone)]
pub struct EnrichmentResult {
    /// The resolved hostname, if any.
    pub hostname: Option<String>,
    /// Whether the hostname is a known-good domain.
    pub is_known_good: bool,
    /// Fast-flux analysis result.
    pub fast_flux: Option<FastFluxResult>,
    /// Domain squatting analysis result.
    pub squatting: Option<SquattingResult>,
    /// Adjusted severity (may be lowered to INFO for known-good).
    pub adjusted_severity: Option<Severity>,
    /// Adjusted confidence (may be boosted for fast-flux / squatting).
    pub adjusted_confidence: Option<u8>,
}

/// Enrich an alert with DNS resolution data and security analysis.
///
/// This is the main integration function called from the exporter. It:
///
/// 1. Checks the [`DnsCache`] for a cached hostname.
/// 2. If not found, performs an async reverse lookup via hickory-resolver.
/// 3. If the hostname matches a "Known Good" pattern, sets severity to INFO.
/// 4. Checks for fast-flux behavior.
/// 5. Checks for domain squatting.
///
/// The function mutates the alert in-place, adding metadata and adjusting
/// severity/confidence as needed.
pub async fn enrich_alert(alert: &mut MitreAlert, cache: &DnsCache) -> EnrichmentResult {
    let mut result = EnrichmentResult {
        hostname: None,
        is_known_good: false,
        fast_flux: None,
        squatting: None,
        adjusted_severity: None,
        adjusted_confidence: None,
    };

    // ── Step 1: Resolve dst_ip ─────────────────────────────────────────
    let dst_ip: IpAddr = match alert.dst_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return result,
    };

    let hostname = if let Some(cached) = cache.get(&dst_ip) {
        cached
    } else {
        // Step 2: Background async reverse lookup
        match resolve_and_cache(dst_ip, cache).await {
            Some(name) => name,
            None => return result,
        }
    };

    result.hostname = Some(hostname.clone());

    // Add hostname to alert metadata
    alert
        .metadata
        .insert("dns_resolver_dst".to_string(), hostname.clone());
    alert.metadata.insert(
        "dns_resolver_source".to_string(),
        "hickory_reverse_lookup".to_string(),
    );

    // ── Step 3: Known Good check ───────────────────────────────────────
    if is_known_good(&hostname) {
        result.is_known_good = true;
        result.adjusted_severity = Some(Severity::Info);
        alert.severity = Severity::Info;
        alert.metadata.insert(
            "dns_known_good".to_string(),
            format!("Matched known-good pattern: {}", hostname),
        );
        debug!(
            "[DnsResolver] Known-good domain '{}' for {} — severity → INFO",
            hostname, dst_ip
        );
    }

    // ── Step 4: Fast Flux detection ────────────────────────────────────
    let flux = detect_fast_flux(cache, &dst_ip);
    if flux.is_fast_flux {
        let new_confidence = alert.confidence.saturating_add(flux.confidence_boost).min(100);
        result.adjusted_confidence = Some(new_confidence);
        alert.confidence = new_confidence;
        alert
            .metadata
            .insert("dns_fast_flux".to_string(), flux.reason.clone());
        alert.metadata.insert(
            "dns_fast_flux_names".to_string(),
            flux.distinct_names.to_string(),
        );
        info!(
            "[DnsResolver] Fast flux detected for {}: {} distinct names (+{} confidence)",
            dst_ip, flux.distinct_names, flux.confidence_boost
        );
    }
    result.fast_flux = Some(flux);

    // ── Step 5: Domain Squatting detection ──────────────────────────────
    let squat = detect_squatting(&hostname);
    if squat.is_squatting {
        let new_confidence = alert
            .confidence
            .saturating_add(squat.confidence_boost)
            .min(100);
        result.adjusted_confidence = Some(new_confidence);
        alert.confidence = new_confidence;
        alert
            .metadata
            .insert("dns_squatting".to_string(), squat.reason.clone());
        if let Some(ref brand) = squat.similar_to {
            alert
                .metadata
                .insert("dns_squatting_brand".to_string(), brand.clone());
        }
        info!(
            "[DnsResolver] Domain squatting detected: '{}' resembles '{}'",
            hostname,
            squat.similar_to.as_deref().unwrap_or("unknown")
        );
    }
    result.squatting = Some(squat);

    // ── Also resolve src_ip if not already enriched ────────────────────
    if !alert.metadata.contains_key("dns_resolver_src") {
        if let Ok(src_ip) = alert.src_ip.parse::<IpAddr>() {
            if let Some(src_hostname) = resolve_and_cache(src_ip, cache).await {
                alert
                    .metadata
                    .insert("dns_resolver_src".to_string(), src_hostname);
            }
        }
    }

    result
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Levenshtein Distance Tests ─────────────────────────────────────

    #[test]
    fn test_levenshtein_identical() {
        assert_eq!(levenshtein_distance("google.com", "google.com"), 0);
    }

    #[test]
    fn test_levenshtein_one_substitution() {
        // g00gle.com vs google.com — two substitutions (o→0, o→0)
        assert_eq!(levenshtein_distance("g00gle.com", "google.com"), 2);
    }

    #[test]
    fn test_levenshtein_one_char_diff() {
        // gogle.com vs google.com — one deletion
        assert_eq!(levenshtein_distance("gogle.com", "google.com"), 1);
    }

    #[test]
    fn test_levenshtein_completely_different() {
        assert!(levenshtein_distance("xyz.com", "google.com") > 2);
    }

    // ── Domain Extraction Tests ────────────────────────────────────────

    #[test]
    fn test_extract_domain_simple() {
        assert_eq!(extract_domain("google.com"), "google.com");
    }

    #[test]
    fn test_extract_domain_subdomain() {
        assert_eq!(extract_domain("mail.google.com"), "google.com");
    }

    #[test]
    fn test_extract_domain_deep_subdomain() {
        assert_eq!(extract_domain("a.b.c.google.com"), "google.com");
    }

    // ── Known Good Tests ───────────────────────────────────────────────

    #[test]
    fn test_known_good_microsoft() {
        assert!(is_known_good("update.microsoft.com"));
        assert!(!is_known_good("login.microsoftonline.com")); // not in list
        assert!(is_known_good("portal.azure.com")); // subdomain of .azure.com
        assert!(!is_known_good("AZURE.COM")); // exact TLD, not a subdomain — no leading dot match
    }

    #[test]
    fn test_known_good_apple() {
        assert!(is_known_good("gs.apple.com"));
        assert!(is_known_good("p42.icloud.com")); // subdomain of .icloud.com
        assert!(!is_known_good("p42-icloud.com")); // hyphenated, not a subdomain
    }

    #[test]
    fn test_known_good_negative() {
        assert!(!is_known_good("evil-domain.xyz"));
        assert!(!is_known_good("totally-not-google.com"));
    }

    // ── Squatting Detection Tests ──────────────────────────────────────

    #[test]
    fn test_squatting_g00gle() {
        let result = detect_squatting("g00gle.com");
        assert!(result.is_squatting);
        assert_eq!(result.similar_to, Some("google.com".to_string()));
        assert_eq!(result.distance, 2);
    }

    #[test]
    fn test_squatting_gogle() {
        let result = detect_squatting("gogle.com");
        assert!(result.is_squatting);
        assert_eq!(result.similar_to, Some("google.com".to_string()));
        assert_eq!(result.distance, 1);
    }

    #[test]
    fn test_squatting_legitimate() {
        let result = detect_squatting("google.com");
        assert!(!result.is_squatting);
    }

    #[test]
    fn test_squatting_unrelated() {
        let result = detect_squatting("randomdomain.xyz");
        assert!(!result.is_squatting);
    }

    #[test]
    fn test_squatting_micr0soft() {
        let result = detect_squatting("micr0soft.com");
        assert!(result.is_squatting);
        assert_eq!(result.similar_to, Some("microsoft.com".to_string()));
    }

    #[test]
    fn test_squatting_with_subdomain() {
        let result = detect_squatting("login.g00gle.com");
        assert!(result.is_squatting);
        assert_eq!(result.similar_to, Some("google.com".to_string()));
    }

    // ── Cache Tests ────────────────────────────────────────────────────

    #[test]
    fn test_cache_basic_operations() {
        let cache = DnsCache::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(cache.get(&ip).is_none());
        assert!(!cache.has_entry(&ip));

        cache.insert(ip, "example.com".to_string(), Duration::from_secs(300));
        assert_eq!(cache.get(&ip), Some("example.com".to_string()));
        assert!(cache.has_entry(&ip));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cache_history_tracking() {
        let cache = DnsCache::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        cache.insert(ip, "host1.example.com".to_string(), Duration::from_secs(300));
        cache.insert(ip, "host2.example.com".to_string(), Duration::from_secs(300));
        cache.insert(ip, "host3.example.com".to_string(), Duration::from_secs(300));

        let entry = cache.get_entry(&ip).unwrap();
        assert_eq!(entry.hostname, "host3.example.com");
        assert_eq!(entry.history.len(), 2);
    }

    #[test]
    fn test_cache_same_hostname_no_history() {
        let cache = DnsCache::new();
        let ip: IpAddr = "10.0.0.2".parse().unwrap();

        cache.insert(ip, "same.example.com".to_string(), Duration::from_secs(300));
        cache.insert(ip, "same.example.com".to_string(), Duration::from_secs(300));

        let entry = cache.get_entry(&ip).unwrap();
        assert_eq!(entry.hostname, "same.example.com");
        assert_eq!(entry.history.len(), 0); // No change = no history
    }

    // ── Fast Flux Tests ────────────────────────────────────────────────

    #[test]
    fn test_fast_flux_not_detected() {
        let cache = DnsCache::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        cache.insert(ip, "host1.example.com".to_string(), Duration::from_secs(300));

        let result = detect_fast_flux(&cache, &ip);
        assert!(!result.is_fast_flux);
        assert_eq!(result.distinct_names, 1);
    }

    #[test]
    fn test_fast_flux_detected() {
        let cache = DnsCache::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Simulate rapid hostname changes
        for i in 0..FAST_FLUX_THRESHOLD + 2 {
            cache.insert(
                ip,
                format!("host{}.botnet.evil", i),
                Duration::from_secs(300),
            );
        }

        let result = detect_fast_flux(&cache, &ip);
        assert!(result.is_fast_flux);
        assert!(result.distinct_names >= FAST_FLUX_THRESHOLD);
        assert!(result.confidence_boost > 0);
    }
}
