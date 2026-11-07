//! Console output: plain lines, colored by severity.
//!
//! Each alert is a header line followed by its logic and a few key details:
//!
//! ```text
//! 13:44:15 CRITICAL T1059 Command and Scripting Interpreter [reverse_shell] tcp 127.0.0.1:41092 → 127.0.0.1:4444 conf 95
//!          'bash' (pid 8260) redirected its stdout to a TCP connection with 127.0.0.1:4444
//!          proc_comm=bash proc_pid=8260 proc_exe=/usr/bin/bash
//! ```
//!
//! The complete alert, with all metadata, goes to SQLite and to the OCSF /
//! syslog exports; the console shows what a person scans for.

use colored::{ColoredString, Colorize};

use super::alert::{MitreAlert, Severity};

/// Metadata shown on the console, in this order, when present.
const DETAIL_KEYS: &[&str] = &[
    "proc_comm",
    "proc_pid",
    "proc_exe",
    "proc_cmdline",
    "dns_src",
    "dns_dst",
    "sni",
    "provider",
    "dst_provider",
    "ja3",
    "shell_type",
    "commands",
    "stdio_fd",
    "total_uploaded_mb",
    "ratio",
    "entropy",
    "discovered_mac",
    "previous_mac",
    "conflicting_mac",
    "suppression_reason",
    "ai_suppression",
];

/// Longest metadata value printed before it is cut with "…".
const MAX_VALUE_CHARS: usize = 80;

/// Detail lines line up under the severity column.
const INDENT: &str = "         ";

fn severity_label(severity: Severity) -> ColoredString {
    let text = format!("{:<8}", severity.to_string());
    match severity {
        Severity::Critical => text.bright_red().bold(),
        Severity::High => text.red().bold(),
        Severity::Medium => text.yellow().bold(),
        Severity::Low => text.cyan(),
        Severity::Info => text.green(),
        Severity::Debug => text.dimmed(),
    }
}

/// `ip:port`, `[v6]:port`, or just the address when there is no port (ARP).
fn endpoint(ip: &str, port: u16) -> String {
    match (port, ip.contains(':')) {
        (0, _) => ip.to_string(),
        (_, true) => format!("[{ip}]:{port}"),
        (_, false) => format!("{ip}:{port}"),
    }
}

fn detail_value(value: &str) -> String {
    let mut v: String = value.chars().take(MAX_VALUE_CHARS).collect();
    if value.chars().count() > MAX_VALUE_CHARS {
        v.push('…');
    }
    if v.contains(char::is_whitespace) {
        format!("\"{v}\"")
    } else {
        v
    }
}

/// `key=value` pairs of the metadata worth showing.
fn detail_pairs(alert: &MitreAlert) -> Vec<String> {
    DETAIL_KEYS
        .iter()
        .filter_map(|key| alert.metadata.get(*key).map(|v| format!("{key}={}", detail_value(v))))
        .collect()
}

/// The alert as one uncolored line (for syslog, which adds its own time):
/// `SEVERITY ID name [trigger] proto src -> dst conf=N | logic | details`.
pub fn alert_text(alert: &MitreAlert) -> String {
    let mut text = format!(
        "{} {} {} [{}] {} {} -> {} conf={}",
        alert.severity,
        alert.technique_id,
        alert.technique_name,
        alert.trigger,
        alert.protocol,
        endpoint(&alert.src_ip, alert.src_port),
        endpoint(&alert.dst_ip, alert.dst_port),
        alert.confidence,
    );
    let logic = alert.logic_text();
    if !logic.is_empty() {
        text.push_str(" | ");
        text.push_str(&logic);
    }
    let details = detail_pairs(alert);
    if !details.is_empty() {
        text.push_str(" | ");
        text.push_str(&details.join(" "));
    }
    // A syslog message is a single line.
    text.replace(['\n', '\r'], " ")
}

/// The console lines for one alert.
pub fn alert_lines(alert: &MitreAlert) -> Vec<String> {
    let time = alert.timestamp.with_timezone(&chrono::Local).format("%H:%M:%S").to_string();
    let header = format!(
        "{} {} {} {} {} {} {} {} {} {}",
        time.dimmed(),
        severity_label(alert.severity),
        alert.technique_id.bold(),
        alert.technique_name,
        format!("[{}]", alert.trigger).dimmed(),
        alert.protocol,
        endpoint(&alert.src_ip, alert.src_port),
        "→".dimmed(),
        endpoint(&alert.dst_ip, alert.dst_port),
        format!("conf {}", alert.confidence).dimmed(),
    );
    let mut lines = vec![header];

    let logic = alert.logic_text();
    if !logic.is_empty() {
        lines.push(format!("{INDENT}{logic}"));
    }

    let details = detail_pairs(alert);
    if !details.is_empty() {
        lines.push(format!("{INDENT}{}", details.join(" ").dimmed()));
    }
    lines
}

/// Print an alert to stdout.
pub fn print_alert(alert: &MitreAlert) {
    for line in alert_lines(alert) {
        println!("{line}");
    }
}

// ── Startup ───────────────────────────────────────────────────────────────

pub fn print_banner() {
    println!("{} {}", "mcp-network-sensor".bold(), env!("CARGO_PKG_VERSION").dimmed());
}

/// One `label: value` line of the startup settings.
pub fn print_setting(label: &str, value: &str) {
    println!("  {} {}", format!("{label}:").dimmed(), value);
}

pub fn print_pipeline_config(ring_capacity: usize, sniffer_core: usize, engine_core: usize) {
    print_setting(
        "pipeline",
        &format!("ring buffer {ring_capacity} packets, sniffer on core {sniffer_core}, engine on core {engine_core}"),
    );
}

pub fn print_ready() {
    println!("  {}", "running, Ctrl+C to stop".green());
    println!();
}

pub fn print_stage_done(stage: &str) {
    println!("  {} {}", stage, "stopped".dimmed());
}

// ── Shutdown summary ──────────────────────────────────────────────────────

/// `name value` pairs; a pair marked `false` is a problem and shows in red.
fn print_stat_line(category: &str, entries: &[(&str, u64, bool)]) {
    let parts: Vec<String> = entries
        .iter()
        .map(|(name, value, ok)| {
            let value = if *ok {
                value.to_string().bold()
            } else {
                value.to_string().red().bold()
            };
            format!("{name} {value}")
        })
        .collect();
    println!("  {} {}", format!("{category:<9}").dimmed(), parts.join(", "));
}

#[allow(clippy::too_many_arguments)]
pub fn print_shutdown_summary(
    captured: u64,
    dropped: u64,
    kernel_dropped: u64,
    if_dropped: u64,
    analyzed: u64,
    parse_errors: u64,
    alerts: u64,
    console_writes: u64,
    db_writes: u64,
    db_errors: u64,
    dns_entries: usize,
) {
    println!();
    println!("{}", "summary".bold());

    let mut sniffer = vec![
        ("captured", captured, true),
        ("dropped", dropped, dropped == 0),
        ("kernel drops", kernel_dropped, kernel_dropped == 0),
    ];
    if if_dropped > 0 {
        sniffer.push(("NIC drops", if_dropped, false));
    }
    print_stat_line("sniffer", &sniffer);

    let mut engine = vec![("analyzed", analyzed, true), ("alerts", alerts, true)];
    if parse_errors > 0 {
        engine.push(("parse errors", parse_errors, false));
    }
    print_stat_line("engine", &engine);

    let mut exporter = vec![("console", console_writes, true), ("db", db_writes, true)];
    if db_errors > 0 {
        exporter.push(("db errors", db_errors, false));
    }
    print_stat_line("exporter", &exporter);

    print_stat_line("dns", &[("cache entries", dns_entries as u64, true)]);
    println!();
}

// ── Usage / Help ──────────────────────────────────────────────────────────

pub fn print_usage() {
    let option = |flag: &str, text: &str| println!("  {:<24} {}", flag.cyan(), text);

    println!();
    println!("{} mcp-network-sensor {}", "Usage:".bold(), "-i <interface> [options]".bold());
    println!();
    println!("{}", "Options:".bold());
    option("-i <interface>", "Capture live traffic from this network interface");
    option("-d <db_path>", "SQLite database path (default: alerts.db)");
    option("-l, --list", "List available network interfaces");
    option("--learning-time <min>", "AI learning phase in minutes (default: 10)");
    option("--ocsf-file <path>", "Also append alerts as OCSF JSON lines to this file");
    option("--syslog <target>", "Also send alerts to syslog: local, udp://host[:port], tcp://host[:port]");
    option("--no-ebpf", "Disable eBPF sensing (Linux builds with the ebpf feature)");
    option("-h, --help", "Show this help message");
    println!();
    println!(
        "{}",
        "Anomaly detection: an Isolation Forest learns normal traffic during --learning-time,\n\
         then scores each alert and suppresses those that match normal behavior."
            .dimmed()
    );
    println!();
}

pub fn print_interfaces(devices: &[pcap::Device]) {
    println!();
    println!("{}", "Available network interfaces:".bold());
    for dev in devices {
        let addrs: Vec<String> = dev.addresses.iter().map(|a| a.addr.to_string()).collect();
        let addrs = if addrs.is_empty() {
            "no addresses".to_string()
        } else {
            addrs.join(", ")
        };
        let desc = dev.desc.as_deref().map(|d| format!(" {d}")).unwrap_or_default();
        println!("  {}{} {}", dev.name.cyan().bold(), desc.dimmed(), format!("[{addrs}]").dimmed());
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MitreAlert {
        MitreAlert::new(
            "T1059",
            "Command and Scripting Interpreter",
            Severity::Critical,
            95,
            "127.0.0.1",
            "127.0.0.1",
            41092,
            4444,
            "tcp",
            "reverse_shell",
            "'bash' (pid 8260) redirected its stdout to a TCP connection with 127.0.0.1:4444",
        )
        .with_meta("proc_comm", "bash")
        .with_meta("proc_cmdline", "bash -i")
        .with_meta("flow_iat_mean", "1.0")
    }

    #[test]
    fn alert_renders_as_plain_lines() {
        colored::control::set_override(false);
        let lines = alert_lines(&sample());
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("CRITICAL T1059 Command and Scripting Interpreter [reverse_shell] tcp"));
        assert!(lines[0].contains("127.0.0.1:41092 → 127.0.0.1:4444 conf 95"));
        assert!(lines[1].starts_with(INDENT) && lines[1].contains("redirected its stdout"));
        // Curated keys only, values with spaces quoted.
        assert_eq!(lines[2].trim(), "proc_comm=bash proc_cmdline=\"bash -i\"");
    }

    #[test]
    fn syslog_text_is_one_uncolored_line() {
        let text = alert_text(&sample());
        assert_eq!(
            text,
            "CRITICAL T1059 Command and Scripting Interpreter [reverse_shell] tcp \
             127.0.0.1:41092 -> 127.0.0.1:4444 conf=95 \
             | 'bash' (pid 8260) redirected its stdout to a TCP connection with 127.0.0.1:4444 \
             | proc_comm=bash proc_cmdline=\"bash -i\""
        );
    }

    #[test]
    fn endpoints_without_port_or_with_ipv6() {
        assert_eq!(endpoint("192.168.1.1", 0), "192.168.1.1");
        assert_eq!(endpoint("fd07::1", 9000), "[fd07::1]:9000");
        assert_eq!(endpoint("10.0.0.1", 80), "10.0.0.1:80");
    }

    #[test]
    fn long_values_are_cut() {
        let v = detail_value(&"x".repeat(200));
        assert_eq!(v.chars().count(), MAX_VALUE_CHARS + 1);
        assert!(v.ends_with('…'));
    }
}
