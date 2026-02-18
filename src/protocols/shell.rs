use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct ShellDetectionResult {
    pub technique_id: String,
    pub shell_type: String,
    pub matched_patterns: Vec<String>,
    pub severity: String,
}

pub fn detect_interactive_shell(payload: &[u8]) -> Option<ShellDetectionResult> {
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

        return Some(ShellDetectionResult {
            technique_id: "T1059".to_string(),
            shell_type,
            matched_patterns,
            severity: "CRITICAL".to_string(),
        });
    }

    None
}
