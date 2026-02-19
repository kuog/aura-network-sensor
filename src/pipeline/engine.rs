//! Stage 2: MITRE Analysis Engine Thread — Core-pinned detection pipeline.
//!
//! This thread is pinned to Core 1. It pulls [`RawPacket`]s from the crossbeam
//! ring buffer, runs them through the full detection engine (all MITRE ATT&CK
//! patterns), and emits [`MitreAlert`]s into a `tokio::sync::mpsc` channel
//! that bridges the synchronous analysis world with the async exporter.
//!
//! **No heavy I/O** (println!, DB writes, network calls) happens here — only
//! CPU-bound packet analysis.

use crossbeam_channel::Receiver;
use etherparse::{LinkHeader, NetHeaders, PacketHeaders, TransportHeader, VlanHeader};
use log::{debug, info};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

use crate::analysis::arp_provider::{ArpGuardian, ArpVerdict};
use crate::analysis::enrichment::{self, ScoringInput};
use crate::analysis::protocol_filter::{self, FilterVerdict};
use crate::analysis::reputation::{self, ReputationVerdict};
use crate::l3_defrag::Defragmenter;
use crate::l4_reassembly::Reassembler;
use crate::protocols;
use crate::protocols::arp::parse_arp;
use crate::protocols::dns;
use crate::protocols::scan::ScannerTracker;
use crate::protocols::shell;
use crate::protocols::smb::SmbTracker;
use crate::telemetry;

use super::alert::{MitreAlert, Severity};
use super::pin_to_core;
use super::sniffer::RawPacket;

/// Shared counters for the analysis engine.
pub struct EngineStats {
    /// Total packets analyzed.
    pub analyzed: AtomicU64,
    /// Total alerts generated.
    pub alerts: AtomicU64,
}

impl EngineStats {
    pub fn new() -> Self {
        Self {
            analyzed: AtomicU64::new(0),
            alerts: AtomicU64::new(0),
        }
    }
}

/// Returns `true` if the IP is in a private RFC-1918 range.
fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let o = ipv4.octets();
            (o[0] == 10)
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 172 && (16..=31).contains(&o[1]))
        }
        _ => false,
    }
}

/// Run the analysis engine. Intended to be called inside `std::thread::spawn`.
///
/// # Arguments
/// * `rx`        – Crossbeam receiver (ring buffer consumer).
/// * `alert_tx`  – Tokio unbounded sender for emitting alerts to Stage 3.
/// * `running`   – Shared shutdown flag.
/// * `stats`     – Shared atomic counters.
/// * `core_id`   – Physical core to pin to (typically 1).
pub fn run(
    rx: Receiver<RawPacket>,
    alert_tx: UnboundedSender<MitreAlert>,
    running: Arc<AtomicBool>,
    stats: Arc<EngineStats>,
    core_id: usize,
) {
    // ── Core pinning ──────────────────────────────────────────────────
    pin_to_core("Engine", core_id);

    // ── Per-engine state (not shared — single-threaded) ───────────────
    let mut defrag = Defragmenter::new();
    let mut tcp_reassembler = Reassembler::new(10_000);
    let matrix = protocols::port_anomaly::ExpectationMatrix::new();
    let mut scanner_tracker = ScannerTracker::new(Duration::from_secs(60));
    let arp_guardian = ArpGuardian::new();
    let mut smb_tracker = SmbTracker::new();

    info!("[Engine] Analysis loop started");

    // Helper closure: emit an alert without blocking
    let emit = |alert: MitreAlert, stats: &Arc<EngineStats>| {
        stats.alerts.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = alert_tx.send(alert) {
            debug!("[Engine] Alert channel closed: {}", e);
        }
    };

    // ── Main analysis loop ────────────────────────────────────────────
    loop {
        // Use recv_timeout so we can periodically check the shutdown flag
        let raw = match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(pkt) => pkt,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                debug!("[Engine] Sniffer channel disconnected");
                break;
            }
        };

        stats.analyzed.fetch_add(1, Ordering::Relaxed);

        // ── Parse Ethernet frame ──────────────────────────────────────
        let headers = match PacketHeaders::from_ethernet_slice(&raw.data) {
            Ok(h) => h,
            Err(_) => continue,
        };

        // ── ARP detection (T1557) ─────────────────────────────────────
        let mut is_arp = false;
        if let Some(LinkHeader::Ethernet2(ether)) = &headers.link {
            if ether.ether_type.0 == 0x0806 {
                is_arp = true;
            }
        }
        if let Some(vlan) = headers.vlan() {
            match vlan {
                VlanHeader::Single(s) if s.ether_type.0 == 0x0806 => is_arp = true,
                VlanHeader::Double(d) if d.inner.ether_type.0 == 0x0806 => is_arp = true,
                _ => {}
            }
        }

        if is_arp {
            let payload = if !headers.payload.slice().is_empty() {
                headers.payload.slice()
            } else {
                let mut offset = 14;
                if let Some(vlan) = headers.vlan() {
                    match vlan {
                        VlanHeader::Single(_) => offset += 4,
                        VlanHeader::Double(_) => offset += 8,
                    }
                }
                if raw.data.len() > offset {
                    &raw.data[offset..]
                } else {
                    &[]
                }
            };

            if let Some((opcode, sender_mac, sender_ip, _target_mac, target_ip)) = parse_arp(payload) {
                match arp_guardian.evaluate(sender_mac, sender_ip, opcode) {
                    ArpVerdict::Conflict(conflict) => {
                        // Rule 3: The Red Line — MAC conflict detected
                        let severity = if conflict.is_gateway_attack {
                            Severity::Critical
                        } else {
                            Severity::High
                        };
                        let confidence = if conflict.is_gateway_attack { 95 } else { 85 };

                        let alert = MitreAlert::new(
                            "T1557",
                            "Adversary-in-the-Middle: ARP Spoofing",
                            severity,
                            confidence,
                            sender_ip.to_string(),
                            target_ip.to_string(),
                            0u16,
                            0u16,
                            "arp",
                            "arp_spoofing",
                            serde_json::to_string(&conflict).unwrap_or_default(),
                        )
                        .with_meta("previous_mac", &conflict.previous_mac)
                        .with_meta("conflicting_mac", &conflict.conflicting_mac)
                        .with_meta("is_gateway_attack", conflict.is_gateway_attack.to_string());
                        emit(alert, &stats);
                    }
                    ArpVerdict::NewDevice { ip, mac } => {
                        // Rule 4: New device discovered — INFO event
                        let alert = MitreAlert::new(
                            "T1557",
                            "ARP Discovery: New Device",
                            Severity::Info,
                            10,
                            ip.to_string(),
                            target_ip.to_string(),
                            0u16,
                            0u16,
                            "arp",
                            "new_device",
                            format!("New device discovered: {} → {}", ip, mac),
                        )
                        .with_meta("discovered_mac", &mac);
                        emit(alert, &stats);
                    }
                    ArpVerdict::Legitimate => {
                        // Rule 2: Same MAC — routine heartbeat, no alert
                    }
                }
            }
        }

        // ── IPv4 processing ───────────────────────────────────────────
        if let Some(NetHeaders::Ipv4(ip_hdr, _)) = headers.net {
            let scan_src = IpAddr::V4(ip_hdr.source.into());
            let scan_dst = IpAddr::V4(ip_hdr.destination.into());

            // T1046 Scanning Detection
            if is_local_ip(&scan_src) {
                match &headers.transport {
                    Some(TransportHeader::Tcp(tcp)) => {
                        if tcp.syn && !tcp.ack {
                            if let Some(scan_alert) = scanner_tracker.update(scan_src, scan_dst, tcp.destination_port) {
                                let alert = MitreAlert::new(
                                    "T1046",
                                    "Network Service Discovery",
                                    Severity::Medium,
                                    70,
                                    scan_src.to_string(),
                                    scan_dst.to_string(),
                                    tcp.source_port,
                                    tcp.destination_port,
                                    "tcp",
                                    "port_scan",
                                    serde_json::to_string(&scan_alert).unwrap_or_default(),
                                );
                                emit(alert, &stats);
                            }
                        }
                    }
                    Some(TransportHeader::Udp(udp)) => {
                        if let Some(scan_alert) = scanner_tracker.update(scan_src, scan_dst, udp.destination_port) {
                            let alert = MitreAlert::new(
                                "T1046",
                                "Network Service Discovery",
                                Severity::Medium,
                                70,
                                scan_src.to_string(),
                                scan_dst.to_string(),
                                udp.source_port,
                                udp.destination_port,
                                "udp",
                                "port_scan",
                                serde_json::to_string(&scan_alert).unwrap_or_default(),
                            );
                            emit(alert, &stats);
                        }
                    }
                    _ => {}
                }
            }

            // IP defragmentation
            let ip_payload_bytes = headers.payload.slice();
            if let Some(full_ip_payload) = defrag.process(&ip_hdr, ip_payload_bytes) {
                let src_ip = IpAddr::V4(ip_hdr.source.into());
                let dst_ip = IpAddr::V4(ip_hdr.destination.into());

                match headers.transport {
                    Some(TransportHeader::Tcp(tcp)) => {
                        analyze_tcp(
                            &mut tcp_reassembler,
                            &matrix,
                            &mut smb_tracker,
                            &full_ip_payload,
                            src_ip,
                            dst_ip,
                            &tcp,
                            raw.timestamp,
                            &emit,
                            &stats,
                        );
                    }
                    Some(TransportHeader::Udp(udp)) => {
                        // DNS analysis (T1071.004)
                        if udp.destination_port == 53 || udp.source_port == 53 {
                            let udp_data_offset = 8;
                            if full_ip_payload.len() > udp_data_offset {
                                let dns_data = &full_ip_payload[udp_data_offset..];
                                if let Some(dns_report) = dns::analyze_dns(dns_data) {
                                    let alert = MitreAlert::new(
                                        "T1071.004",
                                        "Application Layer Protocol: DNS",
                                        Severity::High,
                                        80,
                                        src_ip.to_string(),
                                        dst_ip.to_string(),
                                        udp.source_port,
                                        udp.destination_port,
                                        "udp",
                                        "dns_anomaly",
                                        serde_json::to_string(&dns_report).unwrap_or_default(),
                                    );
                                    emit(alert, &stats);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    let total_analyzed = stats.analyzed.load(Ordering::Relaxed);
    let total_alerts = stats.alerts.load(Ordering::Relaxed);
    info!(
        "[Engine] Stopped. Analyzed: {}, Alerts generated: {}",
        total_analyzed, total_alerts
    );
}

/// Full TCP session analysis — extracted to keep the main loop readable.
#[allow(clippy::too_many_arguments)]
fn analyze_tcp(
    tcp_reassembler: &mut Reassembler,
    matrix: &protocols::port_anomaly::ExpectationMatrix,
    smb_tracker: &mut SmbTracker,
    full_ip_payload: &[u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    tcp: &etherparse::TcpHeader,
    _timestamp: f64,
    emit: &impl Fn(MitreAlert, &Arc<EngineStats>),
    stats: &Arc<EngineStats>,
) {
    let is_upload = is_local_ip(&src_ip);
    let packet_len = full_ip_payload.len() as u64;

    // ── Exfiltration detection (T1041) ────────────────────────────────
    if let Some((up, down, ratio)) = tcp_reassembler.update_stats(
        src_ip,
        dst_ip,
        tcp.source_port,
        tcp.destination_port,
        packet_len,
        is_upload,
    ) {
        let alert = MitreAlert::new(
            "T1041",
            "Exfiltration Over C2 Channel",
            Severity::High,
            75,
            src_ip.to_string(),
            dst_ip.to_string(),
            tcp.source_port,
            tcp.destination_port,
            "tcp",
            "exfiltration",
            "Asymmetric outbound flow detected",
        )
        .with_meta("total_uploaded_mb", format!("{:.2}", up as f64 / 1_000_000.0))
        .with_meta("total_downloaded_mb", format!("{:.2}", down as f64 / 1_000_000.0))
        .with_meta("ratio", format!("{:.2}", ratio));
        emit(alert, stats);
    }

    // ── TCP reassembly + deep inspection ──────────────────────────────
    let tcp_data_offset = tcp.header_len() as usize;
    if full_ip_payload.len() <= tcp_data_offset {
        return;
    }
    let app_data = &full_ip_payload[tcp_data_offset..];

    let (session_data, b_score) = match tcp_reassembler.add_segment(
        src_ip,
        dst_ip,
        tcp.source_port,
        tcp.destination_port,
        app_data,
        _timestamp,
    ) {
        Some(result) => result,
        None => return,
    };

    let entropy = telemetry::shannon_entropy(&session_data);
    let port = tcp.destination_port;

    // ── T1059 Interactive Shell ────────────────────────────────────────
    if let Some(shell_result) = shell::detect_interactive_shell(
        &session_data,
        &src_ip.to_string(),
        &dst_ip.to_string(),
        tcp.source_port,
        tcp.destination_port,
    ) {
        // ── Protocol-aware false-positive filter ───────────────────────
        // Inspect the reassembled payload for legitimate multimedia /
        // streaming protocol signatures before emitting a T1059 alert.
        let filter_verdict = protocol_filter::check_payload(
            &session_data,
            tcp.source_port,
            tcp.destination_port,
        );

        match filter_verdict {
            FilterVerdict::Suppress { ref reason } => {
                // Completely suppress the alert — this is legitimate traffic.
                // Optionally: log at TRACE level for debugging.
                debug!(
                    "[Engine] T1059 suppressed: {} ({}:{} → {}:{})",
                    reason,
                    src_ip, tcp.source_port,
                    dst_ip, tcp.destination_port,
                );
            }
            FilterVerdict::Downgrade {
                ref reason,
                suggested_confidence,
            } => {
                // Emit a downgraded alert (INFO severity, low confidence)
                // so the operator can still see it in logs if needed.
                let logic = format!(
                    "Interactive {} session detected (DOWNGRADED). Matched: [{}]. Filter: {}",
                    shell_result.shell_type,
                    shell_result.matched_patterns.join(", "),
                    reason,
                );

                let mut alert = MitreAlert::new(
                    "T1059",
                    "Command and Scripting Interpreter",
                    Severity::Low, // Downgraded to lowest severity
                    suggested_confidence,
                    src_ip.to_string(),
                    dst_ip.to_string(),
                    tcp.source_port,
                    tcp.destination_port,
                    "tcp",
                    "interactive_shell",
                    &logic,
                )
                .with_meta("shell_type", &shell_result.shell_type)
                .with_meta("matched_patterns", shell_result.matched_patterns.join(", "))
                .with_meta("trust_score", shell_result.trust_score.to_string())
                .with_meta("suppression_reason", reason);

                if let Some(meta) = protocol_filter::suppression_metadata(&filter_verdict) {
                    for (k, v) in meta {
                        alert = alert.with_meta(k, v);
                    }
                }

                if !shell_result.payload_snippet.is_empty() {
                    alert = alert.with_meta("payload_snippet", shell_result.payload_snippet);
                }

                emit(alert, stats);
            }
            FilterVerdict::Pass => {
                // No filter matched — emit the alert at full severity.
                let (severity, confidence) = match shell_result.trust_score {
                    0 => (Severity::Low, 20u8),
                    1..=20 => (Severity::Medium, 40u8),
                    21..=50 => (Severity::High, 70u8),
                    _ => (Severity::Critical, 90u8),
                };

                let logic = if shell_result.extracted_commands.is_empty() {
                    format!(
                        "Interactive {} session detected. Matched: [{}]",
                        shell_result.shell_type,
                        shell_result.matched_patterns.join(", "),
                    )
                } else {
                    format!(
                        "Interactive {} session detected. Matched: [{}]. Commands: [{}]",
                        shell_result.shell_type,
                        shell_result.matched_patterns.join(", "),
                        shell_result.extracted_commands.join("; "),
                    )
                };

                let mut alert = MitreAlert::new(
                    "T1059",
                    "Command and Scripting Interpreter",
                    severity,
                    confidence,
                    src_ip.to_string(),
                    dst_ip.to_string(),
                    tcp.source_port,
                    tcp.destination_port,
                    "tcp",
                    "interactive_shell",
                    &logic,
                )
                .with_meta("shell_type", &shell_result.shell_type)
                .with_meta("matched_patterns", shell_result.matched_patterns.join(", "))
                .with_meta("trust_score", shell_result.trust_score.to_string());

                if !shell_result.extracted_commands.is_empty() {
                    alert = alert.with_meta(
                        "commands",
                        shell_result.extracted_commands.join(" | "),
                    );
                    alert = alert.with_meta(
                        "command_count",
                        shell_result.extracted_commands.len().to_string(),
                    );
                }

                if !shell_result.payload_snippet.is_empty() {
                    alert = alert.with_meta("payload_snippet", shell_result.payload_snippet);
                }

                emit(alert, stats);
            }
        }
    }

    // ── T1571 Port Anomaly ────────────────────────────────────────────
    if let Some(anomaly) = matrix.check(port, entropy, &session_data) {
        let alert = MitreAlert::new(
            &anomaly.technique,
            "Non-Standard Port",
            Severity::High,
            80,
            src_ip.to_string(),
            dst_ip.to_string(),
            tcp.source_port,
            tcp.destination_port,
            "tcp",
            "port_anomaly",
            &anomaly.observation,
        )
        .with_meta("entropy", format!("{:.2}", entropy))
        .with_meta("jitter", format!("{:.2}", b_score));
        emit(alert, stats);
    }

    // ── T1001 Obfuscation / Steganography ─────────────────────────────
    // Build context for TLS-padding CDN heuristic (SNI extracted earlier
    // in the enrichment path would be ideal, but we extract it here too
    // to keep the obfuscation module self-contained for the fast path).
    let sni_for_steg = crate::analysis::enrichment::extract_sni(&session_data);
    let steg_ctx = protocols::obfuscation::StegContext {
        sni: sni_for_steg.as_deref(),
        dst_ip: &dst_ip.to_string(),
    };
    if let Some(steg) = protocols::obfuscation::analyze_steganography_with_context(
        &session_data,
        port,
        Some(&steg_ctx),
    ) {
        if steg.is_benign {
            // TLS padding from a known CDN — emit as INFO / BENIGN
            let mut alert = MitreAlert::new(
                &steg.technique_id,
                "Data Obfuscation",
                Severity::Info,
                5, // very low confidence — essentially benign
                src_ip.to_string(),
                dst_ip.to_string(),
                tcp.source_port,
                tcp.destination_port,
                "tcp",
                "obfuscation_benign",
                &steg.reason,
            )
            .with_meta("pattern_type", &steg.pattern_type)
            .with_meta("observed_entropy", format!("{:.2}", steg.observed_entropy))
            .with_meta("verdict", "BENIGN");

            if let Some(ref feature) = steg.protocol_feature {
                alert = alert.with_meta("protocol_feature", feature);
            }
            if let Some(ref cdn) = steg.cdn_provider {
                alert = alert.with_meta("cdn_provider", cdn);
            }
            if let Some(ref sni) = sni_for_steg {
                alert = alert.with_meta("sni", sni);
            }

            emit(alert, stats);
        } else {
            // Genuine obfuscation / steganography — emit at full severity
            let alert = MitreAlert::new(
                &steg.technique_id,
                "Data Obfuscation",
                Severity::High,
                80,
                src_ip.to_string(),
                dst_ip.to_string(),
                tcp.source_port,
                tcp.destination_port,
                "tcp",
                "obfuscation_detected",
                &steg.reason,
            )
            .with_meta("pattern_type", steg.pattern_type)
            .with_meta("observed_entropy", format!("{:.2}", steg.observed_entropy));
            emit(alert, stats);
        }
    }

    // ── T1039 SMB/RPC Anomaly ─────────────────────────────────────────
    if tcp.source_port == 445 || tcp.destination_port == 445 {
        let anomalies = smb_tracker.analyze_smb(
            &session_data,
            &src_ip.to_string(),
            &dst_ip.to_string(),
            tcp.source_port,
            tcp.destination_port,
        );
        for smb_anomaly in anomalies {
            let alert = MitreAlert::new(
                "T1039",
                "Data from Network Shared Drive",
                Severity::High,
                75,
                src_ip.to_string(),
                dst_ip.to_string(),
                tcp.source_port,
                tcp.destination_port,
                "tcp",
                "smb_anomaly",
                serde_json::to_string(&smb_anomaly).unwrap_or_default(),
            );
            emit(alert, stats);
        }
    }

    // ── T1071.001 HTTP Anomaly ────────────────────────────────────────
    if let Some(_http_report) = protocols::http::analyze_http(
        &session_data,
        &src_ip.to_string(),
        &dst_ip.to_string(),
        tcp.source_port,
        tcp.destination_port,
    ) {
        let alert = MitreAlert::new(
            "T1071.001",
            "Application Layer Protocol: Web Protocols",
            Severity::High,
            80,
            src_ip.to_string(),
            dst_ip.to_string(),
            tcp.source_port,
            tcp.destination_port,
            "tcp",
            "http_anomaly",
            "HTTP anomaly detected",
        );
        emit(alert, stats);
    }

    // ── T1562.001 SSL Stripping ───────────────────────────────────────
    if let Some(_stripping_alert) = protocols::stripping::analyze(
        &session_data,
        &src_ip.to_string(),
        &dst_ip.to_string(),
        tcp.source_port,
        tcp.destination_port,
    ) {
        let alert = MitreAlert::new(
            "T1562.001",
            "Impair Defenses: SSL Stripping",
            Severity::High,
            85,
            src_ip.to_string(),
            dst_ip.to_string(),
            tcp.source_port,
            tcp.destination_port,
            "tcp",
            "ssl_stripping",
            "SSL stripping attack detected",
        );
        emit(alert, stats);
    }

    // ── Beaconing + TLS + Enrichment + IP Reputation ─────────────────
    let is_beaconing = b_score < 0.15;
    let mut ja3_hash_str = None;

    if let Some(ja3_hash) = protocols::tls::calculate_ja3(&session_data) {
        ja3_hash_str = Some(ja3_hash.clone());

        // Known malware JA3 (T1573.002)
        if ja3_hash == "a0e9f5d64349fb12a91c13d332612953" {
            let alert = MitreAlert::new(
                "T1573.002",
                "Encrypted Channel: Asymmetric Cryptography",
                Severity::Critical,
                95,
                src_ip.to_string(),
                dst_ip.to_string(),
                tcp.source_port,
                tcp.destination_port,
                "tcp",
                "known_malware_ja3",
                "Known Meterpreter JA3 fingerprint detected",
            )
            .with_meta("ja3", ja3_hash);
            emit(alert, stats);
        }
    }

    // Expand "standard TLS" to include all well-known encrypted ports
    let is_standard_encrypted = reputation::is_expected_encrypted_port(tcp.source_port)
        || reputation::is_expected_encrypted_port(tcp.destination_port);
    let high_entropy_trigger = entropy > 7.5 && !is_standard_encrypted;

    if high_entropy_trigger || ja3_hash_str.is_some() || is_beaconing {
        // ── Step 1: Context Enrichment (SNI + domain reputation) ───────
        let scoring_input = ScoringInput {
            tls_payload: &session_data,
            dst_port: tcp.destination_port,
            is_beaconing,
            session_data: &session_data,
        };
        let enrichment_result = enrichment::enrich(&scoring_input);
        let sni_ref = enrichment_result.enriched_context.sni.as_deref();

        // ── Step 1b: IP Reputation Lookup ─────────────────────────────
        let flow_rep = reputation::evaluate_flow(
            &src_ip.to_string(),
            &dst_ip.to_string(),
            tcp.destination_port,
            sni_ref,
        );

        // ── Step 2: Heuristic Adjustment for T1573 ───────────────────
        if high_entropy_trigger || (entropy > 7.5 && is_standard_encrypted) {
            let verdict = reputation::adjust_t1573(
                &flow_rep,
                tcp.destination_port,
                entropy,
                sni_ref,
            );

            match verdict {
                ReputationVerdict::Suppress { reason } => {
                    // Do NOT emit T1573 — this is trusted encrypted traffic
                    debug!(
                        "[Engine] T1573 suppressed: {} ({}:{} → {}:{})",
                        reason,
                        src_ip, tcp.source_port,
                        dst_ip, tcp.destination_port,
                    );
                }
                ReputationVerdict::Downgrade { reason } => {
                    // Emit as INFO with confidence 0
                    let alert = MitreAlert::new(
                        "T1573",
                        "Encrypted Channel",
                        Severity::Info,
                        0,
                        src_ip.to_string(),
                        dst_ip.to_string(),
                        tcp.source_port,
                        tcp.destination_port,
                        "tcp",
                        "high_entropy",
                        &reason,
                    )
                    .with_meta("entropy", format!("{:.2}", entropy))
                    .with_meta("jitter", format!("{:.2}", b_score))
                    .with_meta("provider", &flow_rep.provider)
                    .with_meta("port_service", &flow_rep.port_service)
                    .with_meta("is_whitelisted", flow_rep.is_whitelisted.to_string())
                    .with_meta(
                        "sni",
                        sni_ref.unwrap_or(""),
                    );
                    emit(alert, stats);
                }
                ReputationVerdict::Adjust {
                    severity_hint,
                    confidence,
                    reason,
                } => {
                    let severity = match severity_hint {
                        "INFO" => Severity::Info,
                        "LOW" => Severity::Low,
                        "MEDIUM" => Severity::Medium,
                        "HIGH" => Severity::High,
                        "CRITICAL" => Severity::Critical,
                        _ => Severity::Medium,
                    };
                    let alert = MitreAlert::new(
                        "T1573",
                        "Encrypted Channel",
                        severity,
                        confidence,
                        src_ip.to_string(),
                        dst_ip.to_string(),
                        tcp.source_port,
                        tcp.destination_port,
                        "tcp",
                        "high_entropy",
                        &reason,
                    )
                    .with_meta("entropy", format!("{:.2}", entropy))
                    .with_meta("jitter", format!("{:.2}", b_score))
                    .with_meta("provider", &flow_rep.provider)
                    .with_meta("port_service", &flow_rep.port_service)
                    .with_meta("is_whitelisted", flow_rep.is_whitelisted.to_string())
                    .with_meta(
                        "sni",
                        sni_ref.unwrap_or(""),
                    );
                    emit(alert, stats);
                }
                ReputationVerdict::NoChange => {
                    // Use original enrichment-based severity
                    let severity = match enrichment_result.confidence_score {
                        0..=39 => Severity::Low,
                        40..=69 => Severity::Medium,
                        70..=89 => Severity::High,
                        _ => Severity::Critical,
                    };
                    let alert = MitreAlert::new(
                        "T1573",
                        "Encrypted Channel",
                        severity,
                        enrichment_result.confidence_score,
                        src_ip.to_string(),
                        dst_ip.to_string(),
                        tcp.source_port,
                        tcp.destination_port,
                        "tcp",
                        "high_entropy",
                        "Encrypted payload on non-standard port",
                    )
                    .with_meta("entropy", format!("{:.2}", entropy))
                    .with_meta("jitter", format!("{:.2}", b_score))
                    .with_meta("provider", &flow_rep.provider)
                    .with_meta("port_service", &flow_rep.port_service)
                    .with_meta("is_whitelisted", flow_rep.is_whitelisted.to_string())
                    .with_meta(
                        "sni",
                        sni_ref.unwrap_or(""),
                    );
                    emit(alert, stats);
                }
            }
        }

        // ── Beaconing detection (T1011) — also enriched with reputation ─
        if is_beaconing {
            let severity = match enrichment_result.confidence_score {
                0..=39 => Severity::Low,
                40..=69 => Severity::Medium,
                70..=89 => Severity::High,
                _ => Severity::Critical,
            };

            let logic = if enrichment_result.confidence_score < 40 {
                format!(
                    "Periodic communication detected — likely legitimate {} traffic (confidence_score: {})",
                    flow_rep.provider,
                    enrichment_result.confidence_score
                )
            } else {
                "Periodic communication detected".to_string()
            };

            let alert = MitreAlert::new(
                "T1011",
                "Exfiltration Over Other Network Medium",
                severity,
                enrichment_result.confidence_score,
                src_ip.to_string(),
                dst_ip.to_string(),
                tcp.source_port,
                tcp.destination_port,
                "tcp",
                "beaconing",
                logic,
            )
            .with_meta("jitter_score", format!("{:.2}", b_score))
            .with_meta("provider", &flow_rep.provider)
            .with_meta("port_service", &flow_rep.port_service)
            .with_meta("is_whitelisted", flow_rep.is_whitelisted.to_string());
            emit(alert, stats);
        }
    }
}
