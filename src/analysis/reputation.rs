//! IP Reputation & Well-Known Port Validation Module
//!
//! Provides fast, local IP-to-provider lookup using pre-defined CIDR ranges
//! for major cloud/mail providers (Apple, Microsoft, Google, AWS, Cloudflare)
//! and a port-aware service mapping for expected encrypted traffic.
//!
//! **Performance**: All lookups are O(log n) via sorted CIDR prefix matching.
//! No external API calls are made in the fast path.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// CIDR Range Representation
// ---------------------------------------------------------------------------

/// A CIDR range stored as (network_u32, prefix_len) for fast matching.
#[derive(Debug, Clone, Copy)]
struct CidrEntry {
    /// Network address as a u32 (host byte order).
    network: u32,
    /// Prefix length (e.g. 24 for /24).
    prefix_len: u8,
}

impl CidrEntry {
    /// Create a new CIDR entry from an IPv4 address and prefix length.
    const fn new(a: u8, b: u8, c: u8, d: u8, prefix_len: u8) -> Self {
        let network = ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32);
        Self {
            network,
            prefix_len,
        }
    }

    /// Check if an IPv4 address (as u32) falls within this CIDR range.
    #[inline]
    fn contains(&self, ip: u32) -> bool {
        if self.prefix_len == 0 {
            return true;
        }
        let mask = !0u32 << (32 - self.prefix_len);
        (ip & mask) == (self.network & mask)
    }
}

// ---------------------------------------------------------------------------
// Provider Definition
// ---------------------------------------------------------------------------

/// Known cloud/mail provider with associated CIDR ranges.
struct ProviderDef {
    name: &'static str,
    ranges: &'static [CidrEntry],
}

// ---------------------------------------------------------------------------
// Static CIDR Lists — Major Cloud & Mail Providers
// ---------------------------------------------------------------------------
//
// These are representative ranges for the prototype. In production, these
// would be updated from BGP/ASN feeds or provider-published IP lists.

/// Apple Inc. — iCloud Mail, Push Notifications, iMessage.
static APPLE_RANGES: &[CidrEntry] = &[
    CidrEntry::new(17, 0, 0, 0, 8),       // 17.0.0.0/8 (Apple's historic /8)
    CidrEntry::new(63, 92, 224, 0, 19),    // 63.92.224.0/19
    CidrEntry::new(144, 178, 0, 0, 19),    // 144.178.0.0/19
    CidrEntry::new(192, 35, 50, 0, 24),    // 192.35.50.0/24
    CidrEntry::new(205, 180, 0, 0, 14),    // 205.180.0.0/14
];

/// Microsoft — Outlook, Exchange Online, Office 365, Azure.
static MICROSOFT_RANGES: &[CidrEntry] = &[
    CidrEntry::new(13, 64, 0, 0, 11),      // 13.64.0.0/11 (Azure)
    CidrEntry::new(13, 104, 0, 0, 14),     // 13.104.0.0/14 (M365)
    CidrEntry::new(20, 0, 0, 0, 8),        // 20.0.0.0/8 (Azure global)
    CidrEntry::new(23, 96, 0, 0, 13),      // 23.96.0.0/13 (Azure)
    CidrEntry::new(40, 64, 0, 0, 10),      // 40.64.0.0/10 (Azure)
    CidrEntry::new(40, 126, 0, 0, 18),     // 40.126.0.0/18 (Azure AD)
    CidrEntry::new(51, 104, 0, 0, 15),     // 51.104.0.0/15 (Azure UK)
    CidrEntry::new(52, 96, 0, 0, 14),      // 52.96.0.0/14 (Exchange Online)
    CidrEntry::new(52, 112, 0, 0, 14),     // 52.112.0.0/14 (Teams/Skype)
    CidrEntry::new(104, 40, 0, 0, 13),     // 104.40.0.0/13 (Azure)
    CidrEntry::new(104, 208, 0, 0, 13),    // 104.208.0.0/13 (Azure)
    CidrEntry::new(131, 253, 0, 0, 16),    // 131.253.0.0/16 (Microsoft)
    CidrEntry::new(134, 170, 0, 0, 16),    // 134.170.0.0/16 (Microsoft)
    CidrEntry::new(150, 171, 0, 0, 16),    // 150.171.0.0/16 (Microsoft)
    CidrEntry::new(157, 55, 0, 0, 16),     // 157.55.0.0/16 (Microsoft)
    CidrEntry::new(191, 232, 0, 0, 13),    // 191.232.0.0/13 (Azure Brazil)
    CidrEntry::new(204, 79, 180, 0, 24),   // 204.79.180.0/24 (Bing/Microsoft)
];

/// Google — Gmail, Workspace, GCP.
static GOOGLE_RANGES: &[CidrEntry] = &[
    CidrEntry::new(8, 8, 4, 0, 24),        // 8.8.4.0/24 (Google DNS)
    CidrEntry::new(8, 8, 8, 0, 24),        // 8.8.8.0/24 (Google DNS)
    CidrEntry::new(34, 64, 0, 0, 10),      // 34.64.0.0/10 (GCP)
    CidrEntry::new(34, 128, 0, 0, 10),     // 34.128.0.0/10 (GCP)
    CidrEntry::new(35, 184, 0, 0, 13),     // 35.184.0.0/13 (GCP)
    CidrEntry::new(35, 192, 0, 0, 12),     // 35.192.0.0/12 (GCP)
    CidrEntry::new(35, 208, 0, 0, 12),     // 35.208.0.0/12 (GCP)
    CidrEntry::new(35, 224, 0, 0, 12),     // 35.224.0.0/12 (GCP)
    CidrEntry::new(35, 240, 0, 0, 13),     // 35.240.0.0/13 (GCP)
    CidrEntry::new(64, 233, 160, 0, 19),   // 64.233.160.0/19 (Google)
    CidrEntry::new(66, 102, 0, 0, 20),     // 66.102.0.0/20 (Google)
    CidrEntry::new(66, 249, 64, 0, 19),    // 66.249.64.0/19 (Googlebot)
    CidrEntry::new(72, 14, 192, 0, 18),    // 72.14.192.0/18 (Google)
    CidrEntry::new(74, 125, 0, 0, 16),     // 74.125.0.0/16 (Google)
    CidrEntry::new(108, 170, 192, 0, 18),  // 108.170.192.0/18 (Google)
    CidrEntry::new(142, 250, 0, 0, 15),    // 142.250.0.0/15 (Google)
    CidrEntry::new(172, 217, 0, 0, 16),    // 172.217.0.0/16 (Google)
    CidrEntry::new(173, 194, 0, 0, 16),    // 173.194.0.0/16 (Google)
    CidrEntry::new(209, 85, 128, 0, 17),   // 209.85.128.0/17 (Google)
    CidrEntry::new(216, 58, 192, 0, 19),   // 216.58.192.0/19 (Google)
    CidrEntry::new(216, 239, 32, 0, 19),   // 216.239.32.0/19 (Google)
];

/// Amazon Web Services (AWS) — SES, WorkMail.
static AWS_RANGES: &[CidrEntry] = &[
    CidrEntry::new(3, 0, 0, 0, 15),        // 3.0.0.0/15 (AWS)
    CidrEntry::new(3, 2, 0, 0, 15),        // 3.2.0.0/15 (AWS)
    CidrEntry::new(3, 4, 0, 0, 14),        // 3.4.0.0/14 (AWS)
    CidrEntry::new(3, 8, 0, 0, 13),        // 3.8.0.0/13 (AWS)
    CidrEntry::new(3, 16, 0, 0, 14),       // 3.16.0.0/14 (AWS)
    CidrEntry::new(13, 32, 0, 0, 15),      // 13.32.0.0/15 (CloudFront)
    CidrEntry::new(13, 34, 0, 0, 15),      // 13.34.0.0/15 (AWS)
    CidrEntry::new(13, 224, 0, 0, 14),     // 13.224.0.0/14 (CloudFront)
    CidrEntry::new(15, 177, 0, 0, 18),     // 15.177.0.0/18 (AWS Global Accel)
    CidrEntry::new(18, 128, 0, 0, 9),      // 18.128.0.0/9 (AWS)
    CidrEntry::new(34, 192, 0, 0, 10),     // 34.192.0.0/10 (AWS)
    CidrEntry::new(44, 192, 0, 0, 11),     // 44.192.0.0/11 (AWS)
    CidrEntry::new(52, 0, 0, 0, 11),       // 52.0.0.0/11 (AWS)
    CidrEntry::new(52, 32, 0, 0, 11),      // 52.32.0.0/11 (AWS)
    CidrEntry::new(52, 64, 0, 0, 11),      // 52.64.0.0/11 (AWS)
    CidrEntry::new(54, 64, 0, 0, 11),      // 54.64.0.0/11 (AWS)
    CidrEntry::new(54, 128, 0, 0, 11),     // 54.128.0.0/11 (AWS)
    CidrEntry::new(54, 160, 0, 0, 11),     // 54.160.0.0/11 (AWS)
    CidrEntry::new(54, 192, 0, 0, 12),     // 54.192.0.0/12 (CloudFront)
    CidrEntry::new(54, 208, 0, 0, 13),     // 54.208.0.0/13 (AWS)
    CidrEntry::new(54, 224, 0, 0, 12),     // 54.224.0.0/12 (AWS)
    CidrEntry::new(54, 240, 0, 0, 12),     // 54.240.0.0/12 (AWS)
    CidrEntry::new(99, 77, 128, 0, 18),    // 99.77.128.0/18 (AWS)
    CidrEntry::new(99, 150, 0, 0, 21),     // 99.150.0.0/21 (AWS)
    CidrEntry::new(176, 32, 96, 0, 21),    // 176.32.96.0/21 (AWS)
];

/// Cloudflare — DNS, CDN, Email Routing.
static CLOUDFLARE_RANGES: &[CidrEntry] = &[
    CidrEntry::new(1, 0, 0, 0, 24),        // 1.0.0.0/24 (Cloudflare DNS)
    CidrEntry::new(1, 1, 1, 0, 24),        // 1.1.1.0/24 (Cloudflare DNS)
    CidrEntry::new(103, 21, 244, 0, 22),   // 103.21.244.0/22
    CidrEntry::new(103, 22, 200, 0, 22),   // 103.22.200.0/22
    CidrEntry::new(103, 31, 4, 0, 22),     // 103.31.4.0/22
    CidrEntry::new(104, 16, 0, 0, 13),     // 104.16.0.0/13
    CidrEntry::new(104, 24, 0, 0, 14),     // 104.24.0.0/14
    CidrEntry::new(108, 162, 192, 0, 18),  // 108.162.192.0/18
    CidrEntry::new(131, 0, 72, 0, 22),     // 131.0.72.0/22
    CidrEntry::new(141, 101, 64, 0, 18),   // 141.101.64.0/18
    CidrEntry::new(162, 158, 0, 0, 15),    // 162.158.0.0/15
    CidrEntry::new(172, 64, 0, 0, 13),     // 172.64.0.0/13
    CidrEntry::new(173, 245, 48, 0, 20),   // 173.245.48.0/20
    CidrEntry::new(188, 114, 96, 0, 20),   // 188.114.96.0/20
    CidrEntry::new(190, 93, 240, 0, 20),   // 190.93.240.0/20
    CidrEntry::new(197, 234, 240, 0, 22),  // 197.234.240.0/22
    CidrEntry::new(198, 41, 128, 0, 17),   // 198.41.128.0/17
];

/// GitHub — Git hosting, Actions, Packages.
static GITHUB_RANGES: &[CidrEntry] = &[
    CidrEntry::new(140, 82, 112, 0, 20),   // 140.82.112.0/20 (GitHub)
    CidrEntry::new(143, 55, 64, 0, 20),    // 143.55.64.0/20 (GitHub)
    CidrEntry::new(185, 199, 108, 0, 22),  // 185.199.108.0/22 (GitHub Pages)
    CidrEntry::new(192, 30, 252, 0, 22),   // 192.30.252.0/22 (GitHub)
    CidrEntry::new(20, 201, 28, 151, 32),  // 20.201.28.151/32 (GitHub Actions)
];

/// All providers in lookup order.
static PROVIDERS: &[ProviderDef] = &[
    ProviderDef {
        name: "Apple Inc.",
        ranges: APPLE_RANGES,
    },
    ProviderDef {
        name: "Microsoft Corporation",
        ranges: MICROSOFT_RANGES,
    },
    ProviderDef {
        name: "Google LLC",
        ranges: GOOGLE_RANGES,
    },
    ProviderDef {
        name: "Amazon Web Services",
        ranges: AWS_RANGES,
    },
    ProviderDef {
        name: "Cloudflare Inc.",
        ranges: CLOUDFLARE_RANGES,
    },
    ProviderDef {
        name: "GitHub",
        ranges: GITHUB_RANGES,
    },
];

// ---------------------------------------------------------------------------
// Fast IP → Provider Lookup (O(log n) via prefix bucketing)
// ---------------------------------------------------------------------------

/// Result of an IP reputation lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpReputation {
    /// Provider name (e.g. "Apple Inc.") or "Unknown".
    pub provider: String,
    /// Whether this IP belongs to a known trusted provider.
    pub is_trusted: bool,
}

impl IpReputation {
    /// Unknown / unclassified IP.
    pub fn unknown() -> Self {
        Self {
            provider: "Unknown".to_string(),
            is_trusted: false,
        }
    }
}

/// Lookup the reputation of an IP address against the static CIDR database.
///
/// Returns the provider name and trust status. For IPv6 addresses, returns
/// `IpReputation::unknown()` (IPv6 CIDR matching is a future enhancement).
///
/// **Complexity**: O(P × R) where P = number of providers (5) and R = max
/// ranges per provider (~25). Effectively O(1) for the fixed dataset.
pub fn lookup_ip(ip: &IpAddr) -> IpReputation {
    match ip {
        IpAddr::V4(v4) => lookup_ipv4(v4),
        IpAddr::V6(_) => IpReputation::unknown(),
    }
}

/// Lookup an IPv4 address against all provider CIDR ranges.
fn lookup_ipv4(ip: &Ipv4Addr) -> IpReputation {
    let ip_u32 = u32::from(*ip);
    for provider in PROVIDERS {
        for cidr in provider.ranges {
            if cidr.contains(ip_u32) {
                return IpReputation {
                    provider: provider.name.to_string(),
                    is_trusted: true,
                };
            }
        }
    }
    IpReputation::unknown()
}

/// Convenience: lookup from a string IP address.
pub fn lookup_ip_str(ip_str: &str) -> IpReputation {
    match ip_str.parse::<IpAddr>() {
        Ok(ip) => lookup_ip(&ip),
        Err(_) => IpReputation::unknown(),
    }
}

// ---------------------------------------------------------------------------
// Well-Known Encrypted Port Mapping
// ---------------------------------------------------------------------------

/// Service description for a well-known encrypted port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortService {
    /// Short service name (e.g. "IMAPS").
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Whether encrypted traffic on this port is expected/normal.
    pub encrypted_expected: bool,
}

/// Static map of well-known encrypted ports → service info.
///
/// Lookup is O(1) via `HashMap`.
static ENCRYPTED_PORT_MAP: LazyLock<HashMap<u16, PortService>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert(
        443,
        PortService {
            name: "HTTPS",
            description: "HTTP over TLS",
            encrypted_expected: true,
        },
    );
    m.insert(
        465,
        PortService {
            name: "SMTPS",
            description: "SMTP over TLS (submission)",
            encrypted_expected: true,
        },
    );
    m.insert(
        587,
        PortService {
            name: "SMTP/STARTTLS",
            description: "SMTP with STARTTLS (submission)",
            encrypted_expected: true,
        },
    );
    m.insert(
        853,
        PortService {
            name: "DoT",
            description: "DNS over TLS",
            encrypted_expected: true,
        },
    );
    m.insert(
        993,
        PortService {
            name: "IMAPS",
            description: "IMAP over TLS",
            encrypted_expected: true,
        },
    );
    m.insert(
        995,
        PortService {
            name: "POP3S",
            description: "POP3 over TLS",
            encrypted_expected: true,
        },
    );
    m.insert(
        8443,
        PortService {
            name: "HTTPS-ALT",
            description: "HTTPS alternate port",
            encrypted_expected: true,
        },
    );
    m.insert(
        636,
        PortService {
            name: "LDAPS",
            description: "LDAP over TLS",
            encrypted_expected: true,
        },
    );
    m.insert(
        989,
        PortService {
            name: "FTPS-DATA",
            description: "FTP data over TLS",
            encrypted_expected: true,
        },
    );
    m.insert(
        990,
        PortService {
            name: "FTPS",
            description: "FTP control over TLS",
            encrypted_expected: true,
        },
    );
    m.insert(
        5061,
        PortService {
            name: "SIPS",
            description: "SIP over TLS",
            encrypted_expected: true,
        },
    );
    m
});

/// Look up a port in the well-known encrypted port map.
///
/// Returns `Some(PortService)` if the port is a known encrypted service,
/// `None` if the port is not in the map (i.e., potentially suspicious).
pub fn lookup_port(port: u16) -> Option<&'static PortService> {
    ENCRYPTED_PORT_MAP.get(&port)
}

/// Returns `true` if the port is a well-known encrypted service port.
pub fn is_expected_encrypted_port(port: u16) -> bool {
    ENCRYPTED_PORT_MAP.contains_key(&port)
}

/// Get the service name for a port, or "Unknown" if not mapped.
pub fn port_service_name(port: u16) -> &'static str {
    ENCRYPTED_PORT_MAP
        .get(&port)
        .map(|s| s.name)
        .unwrap_or("Unknown")
}

// ---------------------------------------------------------------------------
// Trusted Domain Suffixes for SNI Matching
// ---------------------------------------------------------------------------

/// Known trusted domain suffixes for SNI-based suppression.
/// If an SNI matches one of these, T1573 alerts on port 443 should be suppressed.
const TRUSTED_SNI_SUFFIXES: &[&str] = &[
    // Apple
    ".apple.com",
    ".icloud.com",
    ".icloud-content.com",
    ".cdn-apple.com",
    ".mzstatic.com",
    // Microsoft
    ".microsoft.com",
    ".microsoftonline.com",
    ".office365.com",
    ".office.com",
    ".outlook.com",
    ".live.com",
    ".azure.com",
    ".azure.net",
    ".windows.net",
    ".sharepoint.com",
    ".onedrive.com",
    ".teams.microsoft.com",
    // Google
    ".google.com",
    ".googleapis.com",
    ".gstatic.com",
    ".youtube.com",
    ".googlevideo.com",
    ".gmail.com",
    // AWS
    ".amazonaws.com",
    ".amazon.com",
    ".cloudfront.net",
    // Cloudflare
    ".cloudflare.com",
    ".cloudflare-dns.com",
    ".cloudflareinsights.com",
    // Other trusted
    ".github.com",
    ".githubusercontent.com",
    ".akamai.net",
    ".akamaized.net",
    ".fastly.net",
];

/// Check if an SNI hostname matches a trusted domain suffix.
pub fn is_trusted_sni(sni: &str) -> bool {
    let lower = sni.to_lowercase();
    TRUSTED_SNI_SUFFIXES.iter().any(|suffix| {
        lower.ends_with(suffix) || lower == suffix.trim_start_matches('.')
    })
}

// ---------------------------------------------------------------------------
// Combined Reputation Context (for alert enrichment)
// ---------------------------------------------------------------------------

/// Full reputation context for a network flow, combining IP reputation,
/// port service identification, and SNI trust status.
#[derive(Debug, Clone)]
pub struct FlowReputation {
    /// IP reputation for the source address.
    pub src_reputation: IpReputation,
    /// IP reputation for the destination address.
    pub dst_reputation: IpReputation,
    /// The "best" provider name (prefers dst, falls back to src).
    pub provider: String,
    /// Port service name (e.g. "IMAPS") or "Unknown".
    pub port_service: String,
    /// Whether the flow should be whitelisted based on combined heuristics.
    pub is_whitelisted: bool,
    /// Whether the SNI matches a trusted domain.
    pub sni_trusted: bool,
}

/// Build a complete flow reputation context.
///
/// This is the main entry point called from the analysis engine for every
/// flow that triggers a potential T1573 alert.
pub fn evaluate_flow(
    src_ip: &str,
    dst_ip: &str,
    dst_port: u16,
    sni: Option<&str>,
) -> FlowReputation {
    let src_rep = lookup_ip_str(src_ip);
    let dst_rep = lookup_ip_str(dst_ip);

    // Best provider: prefer destination (server-side), fall back to source
    let provider = if dst_rep.is_trusted {
        dst_rep.provider.clone()
    } else if src_rep.is_trusted {
        src_rep.provider.clone()
    } else {
        "Unknown".to_string()
    };

    let port_service = port_service_name(dst_port).to_string();

    let sni_trusted = sni.map(|s| is_trusted_sni(s)).unwrap_or(false);

    // Whitelisting logic: trusted provider + expected encrypted port, OR
    // trusted SNI on standard TLS port
    let is_whitelisted = (dst_rep.is_trusted && is_expected_encrypted_port(dst_port))
        || (sni_trusted && dst_port == 443)
        || (src_rep.is_trusted && is_expected_encrypted_port(dst_port));

    FlowReputation {
        src_reputation: src_rep,
        dst_reputation: dst_rep,
        provider,
        port_service,
        is_whitelisted,
        sni_trusted,
    }
}

// ---------------------------------------------------------------------------
// Severity Adjustment Logic
// ---------------------------------------------------------------------------

/// Recommended action after reputation-based analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReputationVerdict {
    /// Suppress the alert entirely (do not emit).
    Suppress { reason: String },
    /// Downgrade to INFO severity with confidence = 0.
    Downgrade { reason: String },
    /// Keep the alert but adjust severity/confidence.
    Adjust {
        severity_hint: &'static str,
        confidence: u8,
        reason: String,
    },
    /// No adjustment — alert stands as-is (potentially promote to CRITICAL).
    NoChange,
}

/// Apply the three-step heuristic adjustment for T1573 alerts.
///
/// **Step 1** (Context Enrichment): Already done by `evaluate_flow()`.
///
/// **Step 2** (Heuristic Adjustment):
/// - Mail port (993) + high entropy + trusted provider → INFO, confidence 0
/// - Port 443 + trusted SNI → Suppress T1573
///
/// **Step 3** (Alert Validation):
/// - Obscure port + unknown IP + high entropy → CRITICAL
pub fn adjust_t1573(
    flow: &FlowReputation,
    dst_port: u16,
    entropy: f64,
    sni: Option<&str>,
) -> ReputationVerdict {
    // ── Step 2a: Mail ports with trusted provider ──────────────────────
    // IMAPS (993), POP3S (995), SMTPS (465/587) from Apple/Microsoft/Google
    let is_mail_port = matches!(dst_port, 993 | 995 | 465 | 587);
    if is_mail_port && entropy > 7.5 && flow.dst_reputation.is_trusted {
        return ReputationVerdict::Downgrade {
            reason: format!(
                "Expected encrypted mail traffic on port {} ({}) from trusted provider {}",
                dst_port,
                flow.port_service,
                flow.provider,
            ),
        };
    }

    // ── Step 2b: DNS-over-TLS on port 853 with trusted provider ───────
    if dst_port == 853 && flow.dst_reputation.is_trusted {
        return ReputationVerdict::Downgrade {
            reason: format!(
                "DNS-over-TLS on port 853 to trusted provider {}",
                flow.provider,
            ),
        };
    }

    // ── Step 2c: Port 443 + trusted SNI → Suppress ────────────────────
    if dst_port == 443 {
        if let Some(sni_val) = sni {
            if is_trusted_sni(sni_val) {
                return ReputationVerdict::Suppress {
                    reason: format!(
                        "Standard HTTPS to trusted domain '{}' (provider: {})",
                        sni_val, flow.provider,
                    ),
                };
            }
        }
        // Port 443 with trusted IP but no SNI — still downgrade
        if flow.dst_reputation.is_trusted {
            return ReputationVerdict::Adjust {
                severity_hint: "LOW",
                confidence: 15,
                reason: format!(
                    "HTTPS to trusted provider {} (no SNI extracted)",
                    flow.provider,
                ),
            };
        }
    }

    // ── Step 2d: Any expected encrypted port with trusted provider ─────
    if is_expected_encrypted_port(dst_port) && flow.dst_reputation.is_trusted {
        return ReputationVerdict::Adjust {
            severity_hint: "LOW",
            confidence: 10,
            reason: format!(
                "Expected encrypted service {} on port {} from {}",
                flow.port_service, dst_port, flow.provider,
            ),
        };
    }

    // ── Step 3: Promote to CRITICAL if truly suspicious ───────────────
    // Obscure port (not in well-known map) + unknown IP + high entropy
    let is_obscure_port = !is_expected_encrypted_port(dst_port)
        && ![443, 80, 8080, 8443].contains(&dst_port);
    let is_unknown_ip = !flow.dst_reputation.is_trusted && !flow.src_reputation.is_trusted;

    if is_obscure_port && is_unknown_ip && entropy > 7.5 {
        return ReputationVerdict::Adjust {
            severity_hint: "CRITICAL",
            confidence: 95,
            reason: format!(
                "High-entropy ({:.2}) encrypted traffic on obscure port {} to unknown IP",
                entropy, dst_port,
            ),
        };
    }

    ReputationVerdict::NoChange
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_contains() {
        // 17.0.0.0/8 should contain 17.172.224.47
        let cidr = CidrEntry::new(17, 0, 0, 0, 8);
        let ip: Ipv4Addr = "17.172.224.47".parse().unwrap();
        assert!(cidr.contains(u32::from(ip)));

        // Should NOT contain 18.0.0.1
        let ip2: Ipv4Addr = "18.0.0.1".parse().unwrap();
        assert!(!cidr.contains(u32::from(ip2)));
    }

    #[test]
    fn test_apple_lookup() {
        let rep = lookup_ip_str("17.172.224.47");
        assert!(rep.is_trusted);
        assert_eq!(rep.provider, "Apple Inc.");
    }

    #[test]
    fn test_microsoft_lookup() {
        // 52.96.0.0/14 — Exchange Online
        let rep = lookup_ip_str("52.97.100.5");
        assert!(rep.is_trusted);
        assert_eq!(rep.provider, "Microsoft Corporation");
    }

    #[test]
    fn test_google_lookup() {
        let rep = lookup_ip_str("142.250.80.4");
        assert!(rep.is_trusted);
        assert_eq!(rep.provider, "Google LLC");
    }

    #[test]
    fn test_aws_lookup() {
        let rep = lookup_ip_str("54.230.10.1");
        assert!(rep.is_trusted);
        assert_eq!(rep.provider, "Amazon Web Services");
    }

    #[test]
    fn test_cloudflare_lookup() {
        let rep = lookup_ip_str("104.16.0.1");
        assert!(rep.is_trusted);
        assert_eq!(rep.provider, "Cloudflare Inc.");
    }

    #[test]
    fn test_github_lookup() {
        // 140.82.121.4 — GitHub (lb-140-82-121-4-fra.github.com)
        let rep = lookup_ip_str("140.82.121.4");
        assert!(rep.is_trusted);
        assert_eq!(rep.provider, "GitHub");
    }

    #[test]
    fn test_unknown_ip() {
        let rep = lookup_ip_str("185.220.101.1");
        assert!(!rep.is_trusted);
        assert_eq!(rep.provider, "Unknown");
    }

    #[test]
    fn test_port_lookup() {
        assert_eq!(lookup_port(993).unwrap().name, "IMAPS");
        assert_eq!(lookup_port(465).unwrap().name, "SMTPS");
        assert_eq!(lookup_port(587).unwrap().name, "SMTP/STARTTLS");
        assert_eq!(lookup_port(995).unwrap().name, "POP3S");
        assert_eq!(lookup_port(853).unwrap().name, "DoT");
        assert_eq!(lookup_port(443).unwrap().name, "HTTPS");
        assert!(lookup_port(55727).is_none());
    }

    #[test]
    fn test_trusted_sni() {
        assert!(is_trusted_sni("outlook.office365.com"));
        assert!(is_trusted_sni("imap.mail.apple.com"));
        assert!(is_trusted_sni("smtp.gmail.com"));
        assert!(!is_trusted_sni("evil-c2.example.com"));
    }

    #[test]
    fn test_flow_evaluation_apple_imaps() {
        let flow = evaluate_flow("192.168.1.100", "17.172.224.47", 993, None);
        assert_eq!(flow.provider, "Apple Inc.");
        assert_eq!(flow.port_service, "IMAPS");
        assert!(flow.is_whitelisted);
    }

    #[test]
    fn test_flow_evaluation_unknown() {
        let flow = evaluate_flow("192.168.1.100", "185.220.101.1", 55727, None);
        assert_eq!(flow.provider, "Unknown");
        assert_eq!(flow.port_service, "Unknown");
        assert!(!flow.is_whitelisted);
    }

    #[test]
    fn test_adjust_t1573_apple_imaps() {
        let flow = evaluate_flow("192.168.1.100", "17.172.224.47", 993, None);
        let verdict = adjust_t1573(&flow, 993, 7.8, None);
        assert!(matches!(verdict, ReputationVerdict::Downgrade { .. }));
    }

    #[test]
    fn test_adjust_t1573_trusted_sni_443() {
        let flow = evaluate_flow(
            "192.168.1.100",
            "142.250.80.4",
            443,
            Some("mail.google.com"),
        );
        let verdict = adjust_t1573(&flow, 443, 7.9, Some("mail.google.com"));
        assert!(matches!(verdict, ReputationVerdict::Suppress { .. }));
    }

    #[test]
    fn test_adjust_t1573_obscure_port_unknown_ip() {
        let flow = evaluate_flow("192.168.1.100", "185.220.101.1", 55727, None);
        let verdict = adjust_t1573(&flow, 55727, 7.9, None);
        assert!(
            matches!(
                verdict,
                ReputationVerdict::Adjust {
                    severity_hint: "CRITICAL",
                    ..
                }
            ),
            "Expected CRITICAL for obscure port + unknown IP + high entropy"
        );
    }

    #[test]
    fn test_adjust_t1573_no_change() {
        // Known port but unknown IP, moderate entropy
        let flow = evaluate_flow("192.168.1.100", "185.220.101.1", 993, None);
        let verdict = adjust_t1573(&flow, 993, 7.8, None);
        // Unknown IP on mail port — no special treatment
        assert!(matches!(verdict, ReputationVerdict::NoChange));
    }
}
