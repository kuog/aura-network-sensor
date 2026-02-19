//! Protocol-aware false-positive filter for T1059 (Interactive Shell) detection.
//!
//! Legitimate multimedia / streaming protocols (AirPlay/RAOP, Chromecast,
//! DLNA) often carry binary payloads that contain short byte sequences
//! coincidentally matching shell command keywords (e.g. `"id"`).  This module
//! inspects HTTP/RTSP-like headers, magic-byte signatures, and payload entropy
//! to decide whether a T1059 alert should be **suppressed**, **downgraded**,
//! or **emitted as-is**.
//!
//! Design goals:
//! - **Zero allocations on the hot path** where possible (byte-slice matching).
//! - **No DNS lookups** — everything is synchronous and local.
//! - **Handles fragmented payloads** — works with whatever reassembled data is
//!   available; partial headers are treated conservatively (no suppression).

use std::collections::BTreeMap;

// ───────────────────────────────────────────────────────────────────────────
// Public API
// ───────────────────────────────────────────────────────────────────────────

/// Verdict returned by the protocol filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterVerdict {
    /// The payload is legitimate multimedia/protocol traffic — suppress the
    /// T1059 alert entirely.
    Suppress {
        reason: String,
    },
    /// The payload looks like binary protocol data on a known media port —
    /// downgrade severity to INFO and set confidence < 10.
    Downgrade {
        reason: String,
        suggested_confidence: u8,
    },
    /// No protocol filter matched — let the alert through unchanged.
    Pass,
}

/// Inspect a reassembled TCP session payload and decide whether a T1059 alert
/// is a false positive caused by legitimate protocol traffic.
///
/// # Arguments
/// * `payload`  – The reassembled session bytes (may span multiple packets).
/// * `src_port` – Source TCP port.
/// * `dst_port` – Destination TCP port.
///
/// The function is intentionally **synchronous** and performs no I/O.
pub fn check_payload(payload: &[u8], src_port: u16, dst_port: u16) -> FilterVerdict {
    // ── 1. Magic-byte / signature check ────────────────────────────────
    if let Some(reason) = check_magic_bytes(payload) {
        return FilterVerdict::Suppress { reason };
    }

    // ── 2. HTTP/RTSP header inspection ─────────────────────────────────
    let headers = parse_headers(payload);

    if let Some(reason) = check_content_type(&headers) {
        return FilterVerdict::Suppress { reason };
    }

    if let Some(reason) = check_server_header(&headers) {
        return FilterVerdict::Suppress { reason };
    }

    if let Some(reason) = check_user_agent(&headers) {
        return FilterVerdict::Suppress { reason };
    }

    // ── 3. Known media port + binary payload heuristic ─────────────────
    if let Some(verdict) = check_media_port_binary(payload, src_port, dst_port) {
        return verdict;
    }

    // ── 4. Entropy-based binary data check ─────────────────────────────
    if let Some(verdict) = entropy_check(payload) {
        return verdict;
    }

    FilterVerdict::Pass
}

/// Convenience wrapper: returns `true` when the payload should **not** trigger
/// a T1059 alert at all (i.e. the verdict is [`FilterVerdict::Suppress`]).
pub fn is_legitimate(payload: &[u8], src_port: u16, dst_port: u16) -> bool {
    matches!(
        check_payload(payload, src_port, dst_port),
        FilterVerdict::Suppress { .. }
    )
}

/// If the alert is filtered but still logged, return metadata fields to attach
/// to the [`MitreAlert`].  Returns `None` when the verdict is `Pass`.
pub fn suppression_metadata(
    verdict: &FilterVerdict,
) -> Option<BTreeMap<String, String>> {
    match verdict {
        FilterVerdict::Suppress { reason } => {
            let mut m = BTreeMap::new();
            m.insert("suppression_reason".to_string(), reason.clone());
            m.insert("filter_action".to_string(), "suppressed".to_string());
            Some(m)
        }
        FilterVerdict::Downgrade {
            reason,
            suggested_confidence,
        } => {
            let mut m = BTreeMap::new();
            m.insert("suppression_reason".to_string(), reason.clone());
            m.insert("filter_action".to_string(), "downgraded".to_string());
            m.insert(
                "suggested_confidence".to_string(),
                suggested_confidence.to_string(),
            );
            Some(m)
        }
        FilterVerdict::Pass => None,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Header Parsing (lightweight, no allocations for the common case)
// ───────────────────────────────────────────────────────────────────────────

/// Extracted HTTP/RTSP-like header values (lowercased for comparison).
#[derive(Debug, Default)]
struct ParsedHeaders {
    server: Option<String>,
    user_agent: Option<String>,
    content_type: Option<String>,
}

/// Parse HTTP/RTSP-style headers from the beginning of `data`.
///
/// This is intentionally lenient: it looks for `\r\n`-delimited lines of the
/// form `Header-Name: value` and extracts the three fields we care about.
/// If the payload does not start with a recognizable request/status line the
/// parser still scans the first 4 KiB for header-like lines — this handles
/// cases where the reassembled stream starts mid-response.
///
/// Fragmented payloads: if the header block is incomplete (no `\r\n\r\n`
/// terminator found within the scan window) we still return whatever we
/// managed to extract.  The caller treats missing headers conservatively
/// (no suppression).
fn parse_headers(data: &[u8]) -> ParsedHeaders {
    let mut headers = ParsedHeaders::default();

    // Limit scan to the first 4 KiB to keep the hot path fast.
    let scan_limit = data.len().min(4096);
    let scan = &data[..scan_limit];

    // We need at least a plausible text start.  If the very first bytes are
    // high-entropy binary, skip header parsing entirely.
    if scan.len() < 4 {
        return headers;
    }

    // Quick check: does this look like HTTP or RTSP?
    let looks_like_http = scan.starts_with(b"HTTP/")
        || scan.starts_with(b"RTSP/")
        || scan.starts_with(b"GET ")
        || scan.starts_with(b"POST ")
        || scan.starts_with(b"PUT ")
        || scan.starts_with(b"HEAD ")
        || scan.starts_with(b"OPTIONS ")
        || scan.starts_with(b"SETUP ")
        || scan.starts_with(b"ANNOUNCE ")
        || scan.starts_with(b"RECORD ")
        || scan.starts_with(b"DESCRIBE ")
        || scan.starts_with(b"TEARDOWN ");

    if !looks_like_http {
        // Even without a recognizable first line, scan for header-like lines
        // (some reassembled streams may start mid-header block).
        if !scan.windows(2).any(|w| w == b"\r\n") {
            return headers;
        }
    }

    // Split on \r\n and extract known headers.
    let mut pos = 0;
    while pos < scan.len() {
        // Find end of current line.
        let line_end = find_crlf(scan, pos).unwrap_or(scan.len());
        let line = &scan[pos..line_end];

        // Empty line = end of headers.
        if line.is_empty() {
            break;
        }

        // Look for "Name: Value" pattern.
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let name = &line[..colon];
            let value_start = (colon + 1).min(line.len());
            let value = trim_ascii(&line[value_start..]);

            if ascii_eq_ignore_case(name, b"server") {
                headers.server = Some(to_lowercase_string(value));
            } else if ascii_eq_ignore_case(name, b"user-agent") {
                headers.user_agent = Some(to_lowercase_string(value));
            } else if ascii_eq_ignore_case(name, b"content-type") {
                headers.content_type = Some(to_lowercase_string(value));
            }
        }

        // Advance past \r\n (or to end).
        pos = if line_end + 2 <= scan.len() {
            line_end + 2
        } else {
            scan.len()
        };
    }

    headers
}

/// Find the position of the next `\r\n` starting from `offset`.
fn find_crlf(data: &[u8], offset: usize) -> Option<usize> {
    if offset >= data.len() {
        return None;
    }
    data[offset..]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| offset + p)
}

/// Trim leading/trailing ASCII whitespace from a byte slice.
fn trim_ascii(data: &[u8]) -> &[u8] {
    let start = data.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(data.len());
    let end = data.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(start, |p| p + 1);
    &data[start..end]
}

/// Case-insensitive comparison of two ASCII byte slices.
fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

/// Convert a byte slice to a lowercase `String` (lossy).
fn to_lowercase_string(data: &[u8]) -> String {
    String::from_utf8_lossy(data).to_ascii_lowercase()
}

// ───────────────────────────────────────────────────────────────────────────
// Magic Byte / Signature Checks
// ───────────────────────────────────────────────────────────────────────────

/// Well-known binary signatures that indicate non-shell data.
const MAGIC_SIGNATURES: &[(&[u8], &str)] = &[
    // Apple Binary Property List
    (b"bplist00", "Apple Binary Plist (bplist00)"),
    (b"bplist15", "Apple Binary Plist v1.5"),
    (b"bplist16", "Apple Binary Plist v1.6"),
    // XML Property List
    (b"<?xml version", "XML document"),
    // PNG image
    (&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A], "PNG image"),
    // JPEG
    (&[0xFF, 0xD8, 0xFF], "JPEG image"),
    // GIF
    (b"GIF87a", "GIF image (87a)"),
    (b"GIF89a", "GIF image (89a)"),
    // MPEG-4 / QuickTime (ftyp box)
    // The 'ftyp' atom starts at offset 4 in an MP4 container, but we check
    // a few common patterns.
    (b"\x00\x00\x00\x1cftyp", "MPEG-4 container (ftyp)"),
    (b"\x00\x00\x00\x20ftyp", "MPEG-4 container (ftyp)"),
    // Ogg container
    (b"OggS", "Ogg container"),
    // FLAC
    (b"fLaC", "FLAC audio"),
    // RIFF (WAV, AVI, WebP)
    (b"RIFF", "RIFF container (WAV/AVI/WebP)"),
    // Matroska / WebM
    (&[0x1A, 0x45, 0xDF, 0xA3], "Matroska/WebM container"),
    // gzip
    (&[0x1F, 0x8B], "gzip compressed data"),
    // zlib (common deflate)
    (&[0x78, 0x9C], "zlib compressed data"),
    (&[0x78, 0x01], "zlib compressed data (low)"),
    (&[0x78, 0xDA], "zlib compressed data (best)"),
];

/// Check if the payload starts with a known binary signature.
fn check_magic_bytes(payload: &[u8]) -> Option<String> {
    for &(magic, description) in MAGIC_SIGNATURES {
        if payload.len() >= magic.len() && &payload[..magic.len()] == magic {
            return Some(format!(
                "Matched legitimate binary signature: {}",
                description
            ));
        }
    }

    // Special case: MP4/QuickTime ftyp at offset 4
    if payload.len() >= 8 && &payload[4..8] == b"ftyp" {
        return Some("Matched legitimate binary signature: MPEG-4 container (ftyp at offset 4)".to_string());
    }

    None
}

// ───────────────────────────────────────────────────────────────────────────
// Header-Based False Positive Checks
// ───────────────────────────────────────────────────────────────────────────

/// Content-Type values that indicate non-shell binary data.
const LEGITIMATE_CONTENT_TYPES: &[&str] = &[
    "application/x-apple-binary-plist",
    "application/octet-stream",
    "application/x-plist",
    "application/binary",
    "audio/",
    "video/",
    "image/",
    "application/ogg",
    "application/mp4",
    "application/x-mpegurl",
    "application/vnd.apple.mpegurl",
    "application/dash+xml",
    "application/sdp",
];

fn check_content_type(headers: &ParsedHeaders) -> Option<String> {
    let ct = headers.content_type.as_deref()?;
    for &legit in LEGITIMATE_CONTENT_TYPES {
        if ct.contains(legit) {
            return Some(format!(
                "Matched legitimate multimedia protocol (Content-Type: {})",
                ct
            ));
        }
    }
    None
}

/// Server header values that indicate known multimedia infrastructure.
const LEGITIMATE_SERVERS: &[&str] = &[
    "airtunes",
    "airplay",
    "apple",
    "googlecast",
    "chromecast",
    "dlna",
    "roku",
    "sonos",
    "plex",
    "kodi",
    "upnp",
    "ssdp",
    "raop",
];

fn check_server_header(headers: &ParsedHeaders) -> Option<String> {
    let server = headers.server.as_deref()?;
    for &legit in LEGITIMATE_SERVERS {
        if server.contains(legit) {
            return Some(format!(
                "Matched legitimate multimedia protocol (Server: {})",
                server
            ));
        }
    }
    None
}

/// User-Agent values that indicate known multimedia clients.
const LEGITIMATE_USER_AGENTS: &[&str] = &[
    "airplay",
    "airtunes",
    "apple tv",
    "appletv",
    "googlecast",
    "chromecast",
    "dlna",
    "roku",
    "sonos",
    "plex",
    "vlc",
    "mediaplayer",
    "windows-media-player",
    "libvlc",
    "gstreamer",
    "lavf",       // FFmpeg/libavformat
    "ffmpeg",
];

fn check_user_agent(headers: &ParsedHeaders) -> Option<String> {
    let ua = headers.user_agent.as_deref()?;
    for &legit in LEGITIMATE_USER_AGENTS {
        if ua.contains(legit) {
            return Some(format!(
                "Matched legitimate multimedia client (User-Agent: {})",
                ua
            ));
        }
    }
    None
}

// ───────────────────────────────────────────────────────────────────────────
// Known Media Port + Binary Payload Heuristic
// ───────────────────────────────────────────────────────────────────────────

/// Well-known multimedia / streaming ports.
const MEDIA_PORTS: &[u16] = &[
    7000,  // AirPlay
    7100,  // AirPlay (mirroring)
    5000,  // DLNA / UPnP
    8008,  // Chromecast
    8009,  // Chromecast (TLS)
    8443,  // Plex (HTTPS)
    32400, // Plex Media Server
    32469, // Plex DLNA
    1900,  // SSDP / UPnP discovery
    3689,  // DAAP (iTunes)
    5353,  // mDNS (Bonjour)
    554,   // RTSP
    8554,  // RTSP (alt)
];

/// Check if traffic is on a known media port and the payload is predominantly
/// binary (low ASCII density).  If so, downgrade rather than suppress — the
/// traffic is *probably* legitimate but we're less certain without header
/// confirmation.
fn check_media_port_binary(
    payload: &[u8],
    src_port: u16,
    dst_port: u16,
) -> Option<FilterVerdict> {
    let on_media_port =
        MEDIA_PORTS.contains(&src_port) || MEDIA_PORTS.contains(&dst_port);

    if !on_media_port || payload.is_empty() {
        return None;
    }

    let ascii_density = compute_ascii_density(payload);

    // If less than 50% of the payload is printable ASCII, treat as binary
    // multimedia data on a known port → downgrade.
    if ascii_density < 0.50 {
        let port = if MEDIA_PORTS.contains(&dst_port) {
            dst_port
        } else {
            src_port
        };
        return Some(FilterVerdict::Downgrade {
            reason: format!(
                "Binary payload on known multimedia port {} (ASCII density: {:.1}%)",
                port,
                ascii_density * 100.0
            ),
            suggested_confidence: 8,
        });
    }

    None
}

// ───────────────────────────────────────────────────────────────────────────
// Entropy / Binary Data Check
// ───────────────────────────────────────────────────────────────────────────

/// Shell command fragments that, if present, override the binary-data
/// heuristic — even in a mostly-binary payload, these indicate a real shell.
const SHELL_INDICATORS: &[&[u8]] = &[
    b"/bin/sh",
    b"/bin/bash",
    b"/bin/zsh",
    b"/bin/dash",
    b"cmd.exe",
    b"powershell",
    b"pwsh",
    b"python -c",
    b"perl -e",
    b"ruby -e",
    b"bash -i",
    b"sh -i",
    b"exec ",
    b"/dev/tcp/",
    b"nc -e",
    b"ncat -e",
    b"mkfifo",
    b"0<&196",
];

/// Calculate the ratio of printable vs. non-printable characters and decide
/// whether the payload is binary data rather than a shell session.
///
/// If non-printable bytes exceed 30% **and** no clear shell command fragments
/// are found, the payload is treated as binary data → downgrade.
fn entropy_check(payload: &[u8]) -> Option<FilterVerdict> {
    if payload.len() < 16 {
        return None; // Too short to make a meaningful determination.
    }

    let non_printable_ratio = compute_non_printable_ratio(payload);

    if non_printable_ratio <= 0.30 {
        return None; // Mostly text — could be a real shell session.
    }

    // High non-printable ratio — but check for shell indicators first.
    if contains_shell_indicator(payload) {
        return None; // Real shell embedded in binary noise (e.g. exploit payload).
    }

    Some(FilterVerdict::Downgrade {
        reason: format!(
            "Binary data detected (non-printable: {:.1}%, no shell indicators found)",
            non_printable_ratio * 100.0
        ),
        suggested_confidence: 5,
    })
}

/// Compute the fraction of bytes that are printable ASCII (0x20..=0x7E) or
/// common whitespace (\\n, \\r, \\t).
fn compute_ascii_density(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let printable = data
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    printable as f64 / data.len() as f64
}

/// Compute the fraction of bytes that are **not** printable ASCII.
fn compute_non_printable_ratio(data: &[u8]) -> f64 {
    1.0 - compute_ascii_density(data)
}

/// Check whether the payload contains any known shell command indicator.
fn contains_shell_indicator(payload: &[u8]) -> bool {
    for &indicator in SHELL_INDICATORS {
        if payload.len() >= indicator.len()
            && payload
                .windows(indicator.len())
                .any(|w| w == indicator)
        {
            return true;
        }
    }
    false
}

// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bplist_magic_suppresses() {
        let payload = b"bplist00\x00\x01\x02\x03some binary data id whoami";
        let verdict = check_payload(payload, 12345, 7000);
        assert!(matches!(verdict, FilterVerdict::Suppress { .. }));
    }

    #[test]
    fn test_airplay_server_header_suppresses() {
        let payload = b"HTTP/1.1 200 OK\r\nServer: AirTunes/366.0\r\nContent-Type: application/octet-stream\r\n\r\n\x00\x01id\x02";
        let verdict = check_payload(payload, 7000, 54321);
        assert!(matches!(verdict, FilterVerdict::Suppress { .. }));
    }

    #[test]
    fn test_chromecast_port_binary_downgrades() {
        // Binary junk on port 8008 with no headers
        let mut payload = vec![0u8; 200];
        payload[50] = b'i';
        payload[51] = b'd';
        let verdict = check_payload(&payload, 12345, 8008);
        match verdict {
            FilterVerdict::Downgrade {
                suggested_confidence,
                ..
            } => assert!(suggested_confidence < 10),
            _ => panic!("Expected Downgrade, got {:?}", verdict),
        }
    }

    #[test]
    fn test_real_shell_passes_through() {
        let payload = b"root@victim:~# whoami\nroot\nroot@victim:~# id\nuid=0(root)\n";
        let verdict = check_payload(payload, 12345, 4444);
        assert_eq!(verdict, FilterVerdict::Pass);
    }

    #[test]
    fn test_binary_with_shell_indicator_passes() {
        // Mostly binary but contains /bin/sh — should NOT be suppressed.
        let mut payload = vec![0xFFu8; 200];
        payload[100..108].copy_from_slice(b"/bin/sh\x00");
        let verdict = check_payload(&payload, 12345, 4444);
        // Should pass because shell indicator overrides binary heuristic
        assert_eq!(verdict, FilterVerdict::Pass);
    }

    #[test]
    fn test_entropy_check_binary_downgrades() {
        // 80% non-printable, no shell indicators, not on a media port
        let mut payload = vec![0x01u8; 100];
        // Add some printable chars (20%)
        for i in 0..20 {
            payload[i] = b'A';
        }
        let verdict = check_payload(&payload, 12345, 9999);
        match verdict {
            FilterVerdict::Downgrade { .. } => {} // expected
            _ => panic!("Expected Downgrade, got {:?}", verdict),
        }
    }

    #[test]
    fn test_jpeg_magic_suppresses() {
        let mut payload = vec![0xFF, 0xD8, 0xFF, 0xE0];
        payload.extend_from_slice(&[0x00; 100]);
        let verdict = check_payload(&payload, 12345, 80);
        assert!(matches!(verdict, FilterVerdict::Suppress { .. }));
    }

    #[test]
    fn test_parse_headers_extracts_fields() {
        let data = b"HTTP/1.1 200 OK\r\nServer: AirTunes/366.0\r\nContent-Type: application/x-apple-binary-plist\r\nUser-Agent: AirPlay/1.0\r\n\r\nbody";
        let headers = parse_headers(data);
        assert!(headers.server.as_deref().unwrap().contains("airtunes"));
        assert!(headers
            .content_type
            .as_deref()
            .unwrap()
            .contains("x-apple-binary-plist"));
        assert!(headers.user_agent.as_deref().unwrap().contains("airplay"));
    }

    #[test]
    fn test_suppression_metadata() {
        let verdict = FilterVerdict::Suppress {
            reason: "test reason".to_string(),
        };
        let meta = suppression_metadata(&verdict).unwrap();
        assert_eq!(meta.get("suppression_reason").unwrap(), "test reason");
        assert_eq!(meta.get("filter_action").unwrap(), "suppressed");
    }

    #[test]
    fn test_dlna_port_binary_downgrades() {
        let payload = vec![0x00u8; 100];
        let verdict = check_payload(&payload, 12345, 5000);
        match verdict {
            FilterVerdict::Downgrade {
                suggested_confidence,
                ..
            } => assert!(suggested_confidence < 10),
            _ => panic!("Expected Downgrade for DLNA port, got {:?}", verdict),
        }
    }

    #[test]
    fn test_normal_text_on_media_port_passes() {
        let payload = b"This is normal text content with no binary data at all, just regular ASCII characters flowing through the wire.";
        let verdict = check_payload(payload, 12345, 7000);
        assert_eq!(verdict, FilterVerdict::Pass);
    }
}
