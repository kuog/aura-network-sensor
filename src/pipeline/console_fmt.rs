//! Colored console formatter for [`MitreAlert`] output.
//!
//! Provides a human-friendly, color-coded representation of alerts for terminal
//! display. The JSON format itself is **not** modified — this module only affects
//! how alerts are rendered to the console via `println!`.
//!
//! Severity → color mapping:
//! - **CRITICAL** → bright red, bold
//! - **HIGH**     → red
//! - **MEDIUM**   → yellow
//! - **LOW**      → cyan
//! - **INFO**     → green
//! - **DEBUG**    → dimmed white

use colored::Colorize;
use unicode_width::UnicodeWidthStr;

use super::alert::{MitreAlert, Severity};

// ── Visual-width helpers ──────────────────────────────────────────────────

/// Strip ANSI escape sequences from a string, returning only visible characters.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip until we hit a letter (the terminator of the escape sequence)
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Calculate the visual (terminal column) width of a string, ignoring ANSI codes.
///
/// Uses `unicode-width` to correctly handle wide characters (emoji = 2 columns).
fn visual_width(s: &str) -> usize {
    let clean = strip_ansi(s);
    UnicodeWidthStr::width(clean.as_str())
}

/// Pad a plain-text string on the right so its visual width reaches `target_width`.
/// Returns the number of spaces needed (0 if already wider).
fn pad_count(plain_text: &str, target_width: usize) -> usize {
    let w = visual_width(plain_text);
    target_width.saturating_sub(w)
}

// ── Box-drawing constants ─────────────────────────────────────────────────

/// Total box width in terminal columns (including the ║ borders).
const BOX_WIDTH: usize = 76;

/// Inner content width (between "║ " and " ║").
const INNER_WIDTH: usize = BOX_WIDTH - 4; // 72

/// Draw a top border: ╔═══...═══╗
fn top_border() -> String {
    format!("╔{}╗", "═".repeat(BOX_WIDTH - 2))
}

/// Draw a mid border: ╠═══...═══╣
fn mid_border() -> String {
    format!("╠{}╣", "═".repeat(BOX_WIDTH - 2))
}

/// Draw a bottom border: ╚═══...═══╝
fn bot_border() -> String {
    format!("╚{}╝", "═".repeat(BOX_WIDTH - 2))
}

/// Print a line inside the box: ║ <content padded to INNER_WIDTH> ║
///
/// `plain_content` is the content *without* ANSI codes (for width calculation).
/// `colored_content` is the content *with* ANSI codes (for display).
fn box_line(plain_content: &str, colored_content: &str) {
    let pad = pad_count(plain_content, INNER_WIDTH);
    println!("║ {}{} ║", colored_content, " ".repeat(pad));
}

/// Print a line inside the box using only plain (uncolored) text.
fn box_line_plain(content: &str) {
    box_line(content, content);
}

// ── Severity helpers ──────────────────────────────────────────────────────

/// Color a border string according to severity.
fn color_border(border: &str, severity: Severity) -> String {
    match severity {
        Severity::Critical => border.bright_red().to_string(),
        Severity::High => border.red().to_string(),
        Severity::Medium => border.yellow().to_string(),
        Severity::Low => border.cyan().to_string(),
        Severity::Info => border.green().to_string(),
        Severity::Debug => border.dimmed().to_string(),
    }
}

/// Get the emoji icon for a severity level.
fn severity_icon(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "🚨",
        Severity::High => "🔴",
        Severity::Medium => "🟡",
        Severity::Low => "🔵",
        Severity::Info => "🟢",
        Severity::Debug => "⚪",
    }
}

/// Color a text string according to severity.
fn color_text(text: &str, severity: Severity) -> String {
    match severity {
        Severity::Critical => text.bright_red().bold().to_string(),
        Severity::High => text.red().bold().to_string(),
        Severity::Medium => text.yellow().bold().to_string(),
        Severity::Low => text.cyan().bold().to_string(),
        Severity::Info => text.green().bold().to_string(),
        Severity::Debug => text.dimmed().to_string(),
    }
}

// ── Alert box printer ─────────────────────────────────────────────────────

/// Format and print a [`MitreAlert`] to stdout with colored output.
///
/// Layout:
/// ```text
/// ╔══════════════════════════════════════════════════════════════════════════╗
/// ║ 🚨 ALERT — T1071.004 DNS Tunneling                     [CRITICAL 95]  ║
/// ╠══════════════════════════════════════════════════════════════════════════╣
/// ║ Trigger   : high_entropy                                               ║
/// ║ Protocol  : udp                                                        ║
/// ║ Source    : 192.168.1.10:54321                                         ║
/// ║ Dest      : 8.8.8.8:53                                                ║
/// ║ Timestamp : 2024-01-15 12:34:56 UTC                                    ║
/// ╠══════════════════════════════════════════════════════════════════════════╣
/// ║ Logic : DNS query with entropy 7.8 to suspicious domain                ║
/// ╠══════════════════════════════════════════════════════════════════════════╣
/// ║ Metadata:                                                              ║
/// ║   entropy                = 7.82                                        ║
/// ║   provider               = Cloudflare                                  ║
/// ╚══════════════════════════════════════════════════════════════════════════╝
/// ```
pub fn print_alert(alert: &MitreAlert) {
    let sev = alert.severity;
    let icon = severity_icon(sev);

    // ── Severity badge ────────────────────────────────────────────────
    let badge_plain = format!("[{} {}]", alert.severity, alert.confidence);
    let badge_colored = match sev {
        Severity::Critical => badge_plain.bright_red().bold().to_string(),
        Severity::High => badge_plain.red().bold().to_string(),
        Severity::Medium => badge_plain.yellow().bold().to_string(),
        Severity::Low => badge_plain.cyan().to_string(),
        Severity::Info => badge_plain.green().to_string(),
        Severity::Debug => badge_plain.dimmed().to_string(),
    };

    // ── Title line ────────────────────────────────────────────────────
    let title_plain = format!(
        "{} ALERT -- {} {}",
        icon, alert.technique_id, alert.technique_name
    );
    let title_colored = format!(
        "{} {}",
        icon,
        color_text(
            &format!("ALERT -- {} {}", alert.technique_id, alert.technique_name),
            sev,
        ),
    );

    // Calculate gap between title and badge
    let title_vw = visual_width(&title_plain);
    let badge_vw = visual_width(&badge_plain);
    let gap = INNER_WIDTH.saturating_sub(title_vw + badge_vw);

    let title_line_plain = format!("{}{}{}", title_plain, " ".repeat(gap), badge_plain);
    let title_line_colored = format!("{}{}{}", title_colored, " ".repeat(gap), badge_colored);

    // ── Borders ───────────────────────────────────────────────────────
    let top = color_border(&top_border(), sev);
    let mid = color_border(&mid_border(), sev);
    let bot = color_border(&bot_border(), sev);

    // ── Print ─────────────────────────────────────────────────────────
    println!();
    println!("{}", top);
    box_line(&title_line_plain, &title_line_colored);
    println!("{}", mid);

    // ── Detail fields ─────────────────────────────────────────────────
    let detail_fields: &[(&str, &str)] = &[
        ("Trigger  ", &alert.trigger),
        ("Protocol ", &alert.protocol),
    ];
    for (label, value) in detail_fields {
        let plain = format!("{} : {}", label, value);
        box_line_plain(&plain);
    }

    let src = format!("{}:{}", alert.src_ip, alert.src_port);
    let dst = format!("{}:{}", alert.dst_ip, alert.dst_port);

    box_line_plain(&format!("Source    : {}", src));
    box_line_plain(&format!("Dest      : {}", dst));
    box_line_plain(&format!(
        "Timestamp : {}",
        alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    println!("{}", mid);

    // ── Logic (word-wrapped) ──────────────────────────────────────────
    let logic_prefix = "Logic : ";
    let cont_prefix = "        ";
    let wrap_width = INNER_WIDTH.saturating_sub(visual_width(logic_prefix));
    let logic_lines = wrap_text(&alert.logic, wrap_width);

    for (i, line) in logic_lines.iter().enumerate() {
        if i == 0 {
            box_line_plain(&format!("{}{}", logic_prefix, line));
        } else {
            box_line_plain(&format!("{}{}", cont_prefix, line));
        }
    }

    // ── Metadata ──────────────────────────────────────────────────────
    if !alert.metadata.is_empty() {
        println!("{}", mid);
        box_line_plain("Metadata:");

        for (key, value) in &alert.metadata {
            let entry = format!("  {:<22} = {}", key, value);
            // Truncate if too long
            if visual_width(&entry) > INNER_WIDTH {
                let mut truncated = String::new();
                let mut w = 0;
                for ch in entry.chars() {
                    let cw = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
                    if w + cw >= INNER_WIDTH {
                        truncated.push('…');
                        break;
                    }
                    truncated.push(ch);
                    w += cw;
                }
                box_line_plain(&truncated);
            } else {
                box_line_plain(&entry);
            }
        }
    }

    println!("{}", bot);
}

/// Wrap text to fit within a given width, breaking at word boundaries.
fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 || visual_width(text) <= max_width {
        return vec![text.to_string()];
    }

    let mut lines = Vec::new();
    let mut current_line = String::new();
    let mut current_width = 0;

    for word in text.split_whitespace() {
        let word_width = visual_width(word);
        if current_width == 0 {
            // First word on the line
            current_line = word.to_string();
            current_width = word_width;
        } else if current_width + 1 + word_width <= max_width {
            // Fits on current line
            current_line.push(' ');
            current_line.push_str(word);
            current_width += 1 + word_width;
        } else {
            // Start a new line
            lines.push(current_line);
            current_line = word.to_string();
            current_width = word_width;
        }
    }
    if !current_line.is_empty() {
        lines.push(current_line);
    }

    if lines.is_empty() {
        vec![text.to_string()]
    } else {
        lines
    }
}

// ── Banner & startup ──────────────────────────────────────────────────────

/// Print a colored startup banner.
pub fn print_banner() {
    let border = "═".repeat(BOX_WIDTH - 2);
    println!("{}", format!("╔{}╗", border).bright_blue());

    let title_plain = "MCP Network Sensor -- NDR Pipeline";
    let title_colored = title_plain.bright_blue().bold().to_string();
    let title_vw = visual_width(title_plain);
    let left_pad = (INNER_WIDTH.saturating_sub(title_vw)) / 2;
    let right_pad = INNER_WIDTH.saturating_sub(title_vw + left_pad);

    println!(
        "{}",
        format!(
            "║ {}{}{} ║",
            " ".repeat(left_pad),
            title_colored,
            " ".repeat(right_pad),
        )
        .bright_blue()
    );

    println!("{}", format!("╚{}╝", border).bright_blue());
}

/// Print a colored pipeline status line.
pub fn print_pipeline_config(ring_capacity: usize, sniffer_core: usize, engine_core: usize) {
    println!(
        "  {} Ring buffer: {} packets | Sniffer->Core {} | Engine->Core {}",
        ">>".bright_blue(),
        ring_capacity.to_string().white().bold(),
        sniffer_core.to_string().white().bold(),
        engine_core.to_string().white().bold(),
    );
}

/// Print a colored source info line.
pub fn print_source_info(source_type: &str, source_name: &str) {
    println!(
        "  {} {}: {}",
        ">>".bright_green(),
        source_type.green(),
        source_name.white().bold(),
    );
}

/// Print a colored "ready" message.
pub fn print_ready() {
    println!(
        "  {} {}",
        ">>".green(),
        "All pipeline stages running. Press Ctrl+C to stop.".green().bold(),
    );
    println!();
}

/// Print a colored stage completion message.
pub fn print_stage_done(stage: &str) {
    println!(
        "  {} {} {}",
        "[ok]".green(),
        stage.white(),
        "finished".dimmed(),
    );
}

// ── Shutdown summary ──────────────────────────────────────────────────────

/// Print a single stats line inside the shutdown summary box.
///
/// Each entry is `(label, value, is_ok)`. If `is_ok` is false, the value is
/// printed in red; otherwise in green.
fn print_stat_line(category: &str, entries: &[(&str, &str, bool)]) {
    // Build the plain-text version for width calculation
    let mut parts_plain: Vec<String> = Vec::new();
    let mut parts_colored: Vec<String> = Vec::new();

    for (label, value, is_ok) in entries {
        parts_plain.push(format!("{}: {}", label, value));

        let colored_val = if *is_ok {
            value.green().bold().to_string()
        } else {
            value.red().bold().to_string()
        };
        parts_colored.push(format!("{}: {}", label.dimmed(), colored_val));
    }

    let plain_content = format!("  {} | {}", category, parts_plain.join("  "));
    let colored_content = format!(
        "  {} {} {}",
        category.white().bold(),
        "|".bright_blue(),
        parts_colored.join("  "),
    );

    box_line(&plain_content, &colored_content);
}

/// Print a colored shutdown summary.
pub fn print_shutdown_summary(
    captured: u64,
    dropped: u64,
    analyzed: u64,
    alerts: u64,
    console_writes: u64,
    db_writes: u64,
    db_errors: u64,
    dns_entries: usize,
) {
    let border_top = top_border();
    let border_mid = mid_border();
    let border_bot = bot_border();

    println!();
    println!("{}", border_top.bright_blue());

    // Centered title
    let title_plain = "Pipeline Shutdown Summary";
    let title_colored = title_plain.bright_blue().bold().to_string();
    let title_vw = visual_width(title_plain);
    let left_pad = (INNER_WIDTH.saturating_sub(title_vw)) / 2;
    let right_pad = INNER_WIDTH.saturating_sub(title_vw + left_pad);
    println!(
        "{} {}{}{} {}",
        "║".bright_blue(),
        " ".repeat(left_pad),
        title_colored,
        " ".repeat(right_pad),
        "║".bright_blue(),
    );

    println!("{}", border_mid.bright_blue());

    // Stats lines
    print_stat_line("Sniffer ", &[
        ("Captured", &captured.to_string(), true),
        ("Dropped", &dropped.to_string(), dropped == 0),
    ]);
    print_stat_line("Engine  ", &[
        ("Analyzed", &analyzed.to_string(), true),
        ("Alerts", &alerts.to_string(), true),
    ]);
    print_stat_line("Exporter", &[
        ("Console", &console_writes.to_string(), true),
        ("DB", &db_writes.to_string(), true),
    ]);
    if db_errors > 0 {
        print_stat_line("        ", &[
            ("DB Errors", &db_errors.to_string(), false),
        ]);
    }
    print_stat_line("DNS     ", &[
        ("Cache entries", &dns_entries.to_string(), true),
    ]);

    println!("{}", border_bot.bright_blue());
    println!();
}

// ── Usage / Help ──────────────────────────────────────────────────────────

/// Print the usage/help text with colors.
pub fn print_usage() {
    println!();
    println!("{}", "Usage:".bright_white().bold());
    println!(
        "  {} {}  mcp-network-sensor {}",
        "Live capture".green(),
        "(default):".dimmed(),
        "-i <interface>".white().bold(),
    );
    println!(
        "  {} {}  mcp-network-sensor {}",
        "Read pcap   ".green(),
        "(file):   ".dimmed(),
        "-f <path_to_pcap>".white().bold(),
    );
    println!();
    println!("{}", "Options:".bright_white().bold());
    println!(
        "  {}   {}",
        "-i <interface>".cyan(),
        "Capture live traffic from the specified network interface".white(),
    );
    println!(
        "  {}   {}",
        "-f <file>     ".cyan(),
        "Analyze traffic from a pcap file".white(),
    );
    println!(
        "  {}   {}",
        "-d <db_path>  ".cyan(),
        "SQLite database path (default: alerts.db)".white(),
    );
    println!(
        "  {}   {}",
        "-l            ".cyan(),
        "List available network interfaces".white(),
    );
    println!(
        "  {}   {}",
        "-h, --help    ".cyan(),
        "Show this help message".white(),
    );
    println!();
}

/// Print the interface list with colors.
pub fn print_interfaces(devices: &[pcap::Device]) {
    println!();
    println!("{}", "Available network interfaces:".bright_white().bold());
    for dev in devices {
        let desc = dev.desc.as_deref().unwrap_or("");
        let addrs: Vec<String> = dev.addresses.iter().map(|a| format!("{}", a.addr)).collect();
        let addr_str = if addrs.is_empty() {
            String::from("no addresses")
        } else {
            addrs.join(", ")
        };
        let desc_part = if desc.is_empty() {
            String::new()
        } else {
            format!(" -- {}", desc)
        };
        println!(
            "  {} {} [{}]",
            dev.name.cyan().bold(),
            desc_part.dimmed(),
            addr_str.white(),
        );
    }
    println!();
}
