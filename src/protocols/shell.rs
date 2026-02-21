use serde::Serialize;
use std::collections::BTreeMap;
use std::net::IpAddr;

#[derive(Serialize, Debug)]
pub struct ShellContext {
    #[serde(flatten)]
    pub fields: BTreeMap<String, String>,
}

#[derive(Serialize, Debug)]
pub struct ShellDetectionResult {
    pub technique_id: String,
    pub shell_type: String,
    pub matched_patterns: Vec<String>,
    pub severity: String,
    pub context: ShellContext,
    /// Actual command lines extracted from the session payload.
    pub extracted_commands: Vec<String>,
    /// Sanitized snippet of the payload (printable ASCII, truncated).
    pub payload_snippet: String,
    /// Trust score: 0 = fully trusted (known infra), 100 = untrusted.
    /// Used by the engine to downgrade severity for known-good IPs.
    pub trust_score: u8,
}

/// Known shell commands that indicate reconnaissance or post-exploitation.
const RECON_COMMANDS: &[&str] = &[
    "whoami",
    "id",
    "hostname",
    "net user",
    "net localgroup",
    "net group",
    "uname -a",
    "uname",
    "ipconfig",
    "ifconfig",
    "ip addr",
    "ip a",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "ps aux",
    "ps -ef",
    "netstat",
    "ss -tlnp",
    "systeminfo",
    "tasklist",
    "dir",
    "ls -la",
    "ls -al",
    "pwd",
    "echo",
    "wget",
    "curl",
    "chmod",
    "chown",
    "scp",
    "ssh",
    "nc ",
    "ncat",
    "python",
    "perl",
    "ruby",
    "bash -i",
    "sh -i",
    "powershell",
    "cmd.exe",
    "reg query",
    "wmic",
    "certutil",
    "bitsadmin",
    "arp -a",
    "route print",
    "nslookup",
    "dig ",
    "find /",
    "locate ",
    "env",
    "export",
    "set",
    "history",
];

/// Maximum length of a "short" command pattern that requires word-boundary
/// validation to avoid false positives (e.g. "id" matching inside "valid").
const SHORT_CMD_THRESHOLD: usize = 4;

/// Check whether the character at the given byte position is a word boundary
/// (i.e. not an ASCII alphanumeric or underscore).  Positions outside the
/// string are treated as boundaries (start/end of string).
fn is_word_boundary(s: &str, byte_pos: usize) -> bool {
    if byte_pos >= s.len() {
        return true; // end of string is a boundary
    }
    let b = s.as_bytes()[byte_pos];
    // Word characters: a-z, A-Z, 0-9, _
    !(b.is_ascii_alphanumeric() || b == b'_')
}

/// Search for `pattern` in `haystack` with word-boundary awareness for short
/// patterns.  For patterns longer than [`SHORT_CMD_THRESHOLD`] bytes, a plain
/// `contains()` is used.  For shorter patterns (like "id", "env", "set",
/// "dir"), every occurrence is checked to ensure it is surrounded by
/// non-word characters (spaces, newlines, punctuation, start/end of string).
fn contains_word(haystack: &str, pattern: &str) -> bool {
    if pattern.len() > SHORT_CMD_THRESHOLD {
        // Long patterns are specific enough — plain substring match is fine.
        return haystack.contains(pattern);
    }

    let hay = haystack.as_bytes();
    let pat = pattern.as_bytes();
    if pat.is_empty() || hay.len() < pat.len() {
        return false;
    }

    let mut start = 0;
    while start + pat.len() <= hay.len() {
        if let Some(offset) = haystack[start..].find(pattern) {
            let match_start = start + offset;
            let match_end = match_start + pat.len();

            let left_ok = match_start == 0 || is_word_boundary(haystack, match_start - 1);
            let right_ok = is_word_boundary(haystack, match_end);

            if left_ok && right_ok {
                return true;
            }
            // Advance past this occurrence and keep searching.
            start = match_start + 1;
        } else {
            break;
        }
    }
    false
}

/// Extract individual command lines from a shell session payload.
///
/// Splits on common line terminators (`\r\n`, `\n`) and filters for lines
/// that look like typed commands (non-empty, not pure whitespace, not just
/// a prompt character).
fn extract_command_lines(payload_str: &str) -> Vec<String> {
    let mut commands = Vec::new();

    for raw_line in payload_str.split('\n') {
        let line = raw_line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }

        // Skip lines that are purely prompt characters or very short noise
        if line.len() < 2 {
            continue;
        }

        // Skip lines that look like output headers / banners rather than commands
        // (heuristic: lines starting with common output prefixes)
        let lower = line.to_ascii_lowercase();

        // Check if the line contains any known command (with word-boundary
        // awareness for short patterns like "id", "env", "set", "dir").
        let has_known_cmd = RECON_COMMANDS.iter().any(|cmd| contains_word(&lower, cmd));

        // Also accept lines that look like they were typed at a prompt:
        //   "root@host:~# whoami"  →  extract "whoami"
        //   "PS C:\> Get-Process"  →  extract "Get-Process"
        //   "$ ls -la"             →  extract "ls -la"
        let after_prompt = strip_prompt(line);

        if has_known_cmd {
            // Use the part after the prompt if available, otherwise the whole line
            let cmd = if !after_prompt.is_empty() {
                after_prompt.to_string()
            } else {
                line.to_string()
            };
            if !commands.contains(&cmd) {
                commands.push(cmd);
            }
        } else if !after_prompt.is_empty() && after_prompt != line {
            // The line had a recognizable prompt prefix — treat the remainder as a command
            let cmd = after_prompt.to_string();
            if !commands.contains(&cmd) {
                commands.push(cmd);
            }
        }
    }

    commands
}

/// Try to strip a shell prompt prefix and return the command portion.
///
/// Recognizes patterns like:
///   `root@host:~# <cmd>`
///   `user@host:~/dir$ <cmd>`
///   `PS C:\Users\admin> <cmd>`
///   `C:\> <cmd>`
///   `$ <cmd>`
///   `# <cmd>`
///   `> <cmd>`
fn strip_prompt(line: &str) -> &str {
    // Pattern: "user@host:path# cmd" or "user@host:path$ cmd"
    if let Some(pos) = line.find("# ") {
        let candidate = &line[pos + 2..];
        if !candidate.is_empty() {
            return candidate.trim();
        }
    }
    if let Some(pos) = line.find("$ ") {
        let candidate = &line[pos + 2..];
        if !candidate.is_empty() {
            return candidate.trim();
        }
    }
    // PowerShell: "PS C:\path> cmd"
    if let Some(pos) = line.find("> ") {
        let before = &line[..pos];
        if before.contains("PS ") || before.contains("C:\\") || before.ends_with(']') {
            let candidate = &line[pos + 2..];
            if !candidate.is_empty() {
                return candidate.trim();
            }
        }
    }
    ""
}

/// Build a sanitized, truncated snippet of the payload for display.
///
/// Replaces non-printable characters with '.' and caps at `max_len` bytes.
fn sanitize_payload(payload: &[u8], max_len: usize) -> String {
    let len = payload.len().min(max_len);
    let mut snippet = String::with_capacity(len);
    for &b in &payload[..len] {
        if b.is_ascii_graphic() || b == b' ' {
            snippet.push(b as char);
        } else if b == b'\n' || b == b'\r' {
            snippet.push('↵');
        } else if b == b'\t' {
            snippet.push('→');
        } else {
            snippet.push('.');
        }
    }
    if payload.len() > max_len {
        snippet.push_str("…");
    }
    snippet
}

// ---------------------------------------------------------------------------
// Trusted IP Ranges (Microsoft / Azure / O365)
// ---------------------------------------------------------------------------

/// Known Microsoft / Azure / O365 IP prefixes.
///
/// These are well-known ranges published by Microsoft.  Traffic from/to these
/// IPs is very likely legitimate infrastructure and should not trigger CRITICAL
/// shell alerts.
///
/// Reference: <https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges>
const MICROSOFT_IP_PREFIXES: &[([u8; 4], u8)] = &[
    // 13.64.0.0/11  — Azure
    ([13, 64, 0, 0], 11),
    // 13.104.0.0/14 — Microsoft 365
    ([13, 104, 0, 0], 14),
    // 20.0.0.0/11   — Azure
    ([20, 0, 0, 0], 11),
    // 20.33.0.0/16  — Azure
    ([20, 33, 0, 0], 16),
    // 20.34.0.0/15  — Azure
    ([20, 34, 0, 0], 15),
    // 20.36.0.0/14  — Azure
    ([20, 36, 0, 0], 14),
    // 20.40.0.0/13  — Azure
    ([20, 40, 0, 0], 13),
    // 20.48.0.0/12  — Azure
    ([20, 48, 0, 0], 12),
    // 20.64.0.0/10  — Azure
    ([20, 64, 0, 0], 10),
    // 20.128.0.0/16 — Azure
    ([20, 128, 0, 0], 16),
    // 23.96.0.0/13  — Azure
    ([23, 96, 0, 0], 13),
    // 40.64.0.0/10  — Azure / M365
    ([40, 64, 0, 0], 10),
    // 40.126.0.0/18 — Azure AD
    ([40, 126, 0, 0], 18),
    // 51.104.0.0/15 — Azure UK
    ([51, 104, 0, 0], 15),
    // 52.96.0.0/14  — Exchange Online
    ([52, 96, 0, 0], 14),
    // 52.100.0.0/14 — Exchange Online Protection
    ([52, 100, 0, 0], 14),
    // 52.104.0.0/14 — SharePoint / OneDrive
    ([52, 104, 0, 0], 14),
    // 52.108.0.0/14 — Microsoft 365
    ([52, 108, 0, 0], 14),
    // 52.112.0.0/14 — Teams
    ([52, 112, 0, 0], 14),
    // 52.120.0.0/14 — Microsoft 365
    ([52, 120, 0, 0], 14),
    // 52.224.0.0/11 — Azure
    ([52, 224, 0, 0], 11),
    // 104.40.0.0/13 — Azure
    ([104, 40, 0, 0], 13),
    // 104.146.0.0/15 — Azure
    ([104, 146, 0, 0], 15),
    // 104.208.0.0/13 — Azure
    ([104, 208, 0, 0], 13),
    // 131.253.0.0/16 — Microsoft
    ([131, 253, 0, 0], 16),
    // 132.245.0.0/16 — Microsoft
    ([132, 245, 0, 0], 16),
    // 134.170.0.0/16 — Microsoft
    ([134, 170, 0, 0], 16),
    // 150.171.0.0/16 — Microsoft
    ([150, 171, 0, 0], 16),
    // 157.55.0.0/16  — Microsoft
    ([157, 55, 0, 0], 16),
    // 157.56.0.0/14  — Microsoft
    ([157, 56, 0, 0], 14),
    // 168.61.0.0/16  — Azure
    ([168, 61, 0, 0], 16),
    // 168.62.0.0/15  — Azure
    ([168, 62, 0, 0], 15),
    // 191.232.0.0/13 — Azure Brazil
    ([191, 232, 0, 0], 13),
    // 198.17.118.0/24 — Microsoft (includes 198.17.118.203 from the log)
    ([198, 17, 118, 0], 24),
    // 204.79.197.0/24 — Microsoft
    ([204, 79, 197, 0], 24),
    // 204.152.18.0/23 — Microsoft
    ([204, 152, 18, 0], 23),
];

/// Known Microsoft / Azure IPv6 CIDR prefixes.
///
/// Source: Microsoft published IP ranges for Azure and M365.
static MICROSOFT_IPV6_PREFIXES: &[([u8; 16], u8)] = &[
    // 2603:1000::/24 — Azure
    ([0x26, 0x03, 0x10, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 24),
    // 2a01:111::/32 — Microsoft 365
    ([0x2a, 0x01, 0x01, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 32),
    // 2a01:112::/32 — Microsoft 365
    ([0x2a, 0x01, 0x01, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 32),
    // 2620:1ec::/40 — Microsoft
    ([0x26, 0x20, 0x01, 0xec, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 40),
];

/// Check whether an IP address (as string) falls within a known Microsoft range.
///
/// Supports both IPv4 and IPv6 addresses.
/// Returns `true` if the IP is in a trusted Microsoft prefix.
fn is_microsoft_ip(ip_str: &str) -> bool {
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    match ip {
        IpAddr::V4(v4) => {
            let ip_u32 = u32::from_be_bytes(v4.octets());
            for &(prefix, cidr) in MICROSOFT_IP_PREFIXES {
                let prefix_u32 = u32::from_be_bytes(prefix);
                let mask = if cidr == 0 { 0 } else { !0u32 << (32 - cidr) };
                if (ip_u32 & mask) == (prefix_u32 & mask) {
                    return true;
                }
            }
            false
        }
        IpAddr::V6(v6) => {
            let ip_u128 = u128::from_be_bytes(v6.octets());
            for &(prefix, cidr) in MICROSOFT_IPV6_PREFIXES {
                let prefix_u128 = u128::from_be_bytes(prefix);
                let mask = if cidr == 0 { 0 } else { !0u128 << (128 - cidr) };
                if (ip_u128 & mask) == (prefix_u128 & mask) {
                    return true;
                }
            }
            false
        }
    }
}

/// Compute a trust score for the connection endpoints.
///
/// Returns 0–100 where **0 = fully trusted** (known Microsoft infra) and
/// **100 = untrusted / unknown**.
fn compute_trust_score(src_ip: &str, dst_ip: &str) -> u8 {
    let src_trusted = is_microsoft_ip(src_ip);
    let dst_trusted = is_microsoft_ip(dst_ip);

    match (src_trusted, dst_trusted) {
        (true, true) => 0,   // Both endpoints are Microsoft — almost certainly benign
        (_, true) | (true, _) => 20, // One endpoint is Microsoft — likely benign
        _ => 100,             // Neither endpoint is known — untrusted
    }
}

// ---------------------------------------------------------------------------
// Binary / Garbage Payload Filter
// ---------------------------------------------------------------------------

/// Determine whether the payload is predominantly binary (non-printable) data.
///
/// If more than `threshold` fraction of bytes are non-printable ASCII, the
/// payload is considered binary garbage.  Pattern matches inside such payloads
/// are almost certainly coincidental byte sequences, not real shell commands.
fn is_binary_payload(payload: &[u8], threshold: f64) -> bool {
    if payload.is_empty() {
        return false;
    }
    let non_printable = payload
        .iter()
        .filter(|&&b| {
            // Printable ASCII: 0x20..=0x7E, plus common whitespace
            !(b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' || b == b'\t')
        })
        .count();
    (non_printable as f64 / payload.len() as f64) > threshold
}

/// Check whether a short pattern (like "id") appears only inside a region of
/// non-printable / binary data, making it a false positive.
///
/// For each occurrence of `pattern` in `payload`, we examine a window of
/// `context_radius` bytes around it.  If that window is predominantly
/// non-printable, the match is considered spurious.
fn pattern_in_binary_context(payload: &[u8], pattern: &[u8], context_radius: usize) -> bool {
    if pattern.is_empty() {
        return false;
    }
    // Find all occurrences of pattern
    let mut pos = 0;
    while pos + pattern.len() <= payload.len() {
        if let Some(offset) = payload[pos..]
            .windows(pattern.len())
            .position(|w| w == pattern)
        {
            let match_start = pos + offset;
            let ctx_start = match_start.saturating_sub(context_radius);
            let ctx_end = (match_start + pattern.len() + context_radius).min(payload.len());
            let context_window = &payload[ctx_start..ctx_end];

            let printable = context_window
                .iter()
                .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' || b == b'\t')
                .count();
            let ratio = printable as f64 / context_window.len() as f64;

            // If less than 50% of the surrounding context is printable, this
            // match is embedded in binary noise → spurious.
            if ratio < 0.50 {
                return true;
            }
            pos = match_start + 1;
        } else {
            break;
        }
    }
    false
}

/// Filter matched patterns: remove short patterns (≤3 chars) that appear only
/// inside binary/garbage regions of the payload.
fn filter_binary_false_positives(payload: &[u8], patterns: &mut Vec<String>) {
    // Only filter short patterns that are prone to false positives in binary data
    const SHORT_PATTERN_THRESHOLD: usize = 4;
    const CONTEXT_RADIUS: usize = 16;

    patterns.retain(|pat| {
        if pat.len() > SHORT_PATTERN_THRESHOLD {
            return true; // Keep longer patterns — unlikely to be coincidental
        }
        // Check if this pattern only appears in binary context
        !pattern_in_binary_context(payload, pat.as_bytes(), CONTEXT_RADIUS)
    });
}

pub fn detect_interactive_shell(payload: &[u8], src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> Option<ShellDetectionResult> {
    if payload.is_empty() {
        return None;
    }

    // ── Early exit: if the payload is predominantly binary, skip detection
    // entirely.  Shell sessions are text-based; a payload with >40% non-
    // printable bytes is almost certainly not a real shell session (e.g.
    // TLS ciphertext on port 443 typically has ~50% non-printable bytes).
    if is_binary_payload(payload, 0.40) {
        return None;
    }

    // Convert payload to string lossily to perform string matching
    let payload_str = String::from_utf8_lossy(payload);
    let mut matched_patterns = Vec::new();
    let mut shell_type = String::new();

    // Trigger 1: Shell Prompt Patterns
    let prompts = [
        ("PS C:\\>", "PowerShell"),
        ("root@", "Bash"),
        ("admin$", "CMD"),
        ("Last login:", "Bash"),
        ("Microsoft Windows [Version]", "CMD"),
        ("/bin/bash", "Bash"),
        ("/bin/sh", "Bash"),
        ("C:\\Windows\\System32", "CMD"),
    ];

    for (pattern, s_type) in prompts.iter() {
        if payload_str.contains(pattern) {
            matched_patterns.push(pattern.to_string());
            if shell_type.is_empty() {
                shell_type = s_type.to_string();
            } else if !shell_type.contains(s_type) {
                shell_type.push_str(&format!("/{}", s_type));
            }
        }
    }

    // Trigger 2: Command Execution Sequences
    // These are common reconnaissance commands
    let commands = [
        "whoami",
        "id",
        "hostname",
        "net user",
        "uname -a",
        "ipconfig",
        "ifconfig",
    ];

    for cmd in commands.iter() {
        // Use word-boundary-aware matching for short commands like "id"
        // to avoid false positives on words like "valid", "provide", etc.
        if contains_word(&payload_str, cmd) {
             matched_patterns.push(cmd.to_string());
        }
    }

    // Trigger 3: Terminal Escape Codes
    // ANSI escape sequences indicating interactive TTY
    // \x1b is 27 in decimal
    let ansi_sequences = [
        "\x1b[?1049h", // Enable alternative screen buffer
        "\x1b[?1h",    // Application cursor keys
        "\x1b[2J",     // Clear screen
    ];

    for seq in ansi_sequences.iter() {
        if payload_str.contains(seq) {
            matched_patterns.push(format!("ANSI Escape: {:?}", seq));
            if shell_type.is_empty() {
                shell_type = "Interactive TTY".to_string();
            }
        }
    }

    // ── Filter out patterns that only appear inside binary garbage ──────
    filter_binary_false_positives(payload, &mut matched_patterns);

    if !matched_patterns.is_empty() {
        // If we matched patterns but didn't determine a specific shell type, default to "Unknown Shell"
        if shell_type.is_empty() {
            shell_type = "Unknown Shell".to_string();
        }

        let mut fields = BTreeMap::new();
        fields.insert("src_ip".to_string(), src_ip.to_string());
        fields.insert("dst_ip".to_string(), dst_ip.to_string());
        fields.insert("src_port".to_string(), src_port.to_string());
        fields.insert("dst_port".to_string(), dst_port.to_string());
        fields.insert("protocol".to_string(), "tcp".to_string());

        // Extract command lines from the session
        let extracted_commands = extract_command_lines(&payload_str);

        // Build a sanitized payload snippet (up to 512 bytes)
        let payload_snippet = sanitize_payload(payload, 512);

        // Compute trust score based on IP reputation
        let trust_score = compute_trust_score(src_ip, dst_ip);

        // Determine severity: downgrade from CRITICAL if IP is trusted
        let severity = if trust_score == 0 {
            "LOW".to_string()
        } else if trust_score <= 20 {
            "MEDIUM".to_string()
        } else {
            "CRITICAL".to_string()
        };

        return Some(ShellDetectionResult {
            technique_id: "T1059".to_string(),
            shell_type,
            matched_patterns,
            severity,
            context: ShellContext { fields },
            extracted_commands,
            payload_snippet,
            trust_score,
        });
    }

    None
}
