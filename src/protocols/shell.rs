use serde::Serialize;
use std::collections::BTreeMap;

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

        // Check if the line contains any known command
        let has_known_cmd = RECON_COMMANDS.iter().any(|cmd| lower.contains(cmd));

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

pub fn detect_interactive_shell(payload: &[u8], src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> Option<ShellDetectionResult> {
    if payload.is_empty() {
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
        // Check for command followed by newline or space to avoid partial matches in other words
        // This is a simple heuristic.
        if payload_str.contains(cmd) {
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

        return Some(ShellDetectionResult {
            technique_id: "T1059".to_string(),
            shell_type,
            matched_patterns,
            severity: "CRITICAL".to_string(),
            context: ShellContext { fields },
            extracted_commands,
            payload_snippet,
        });
    }

    None
}
