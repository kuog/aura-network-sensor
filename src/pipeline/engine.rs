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
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;

use crate::analysis::arp_provider::{ArpGuardian, ArpVerdict};
use crate::analysis::dns_tracker::{self, DnsTracker};
use crate::analysis::enrichment::{self, ScoringInput};
use crate::analysis::protocol_filter::{self, FilterVerdict};
use crate::analysis::reputation::{self, ReputationVerdict};
use crate::anomaly::detector::AnomalyDetector;
use crate::anomaly::flow_tracker::FlowAccounting;
use crate::anomaly::types::{FlowKey, Protocol};
use crate::l3_defrag::Defragmenter;
use crate::l4_reassembly::{self, Reassembler};
use crate::protocols;
use crate::protocols::arp::parse_arp;
use crate::protocols::dns;
use crate::protocols::scan::{ConnTracker, ScannerTracker};
use crate::protocols::shell;
use crate::protocols::smb::SmbTracker;
use crate::telemetry;

use super::alert::{MitreAlert, Severity};
use super::pin_to_core;
use super::sniffer::RawPacket;

/// How often T1041 is re-evaluated from out-of-band (kernel) byte counts.
const EXFIL_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Shared counters for the analysis engine.
pub struct EngineStats {
    /// Total packets analyzed.
    pub analyzed: AtomicU64,
    /// Frames the header parser rejected (truncated or malformed).
    pub parse_errors: AtomicU64,
    /// Total alerts generated.
    pub alerts: AtomicU64,
}

impl EngineStats {
    pub fn new() -> Self {
        Self {
            analyzed: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            alerts: AtomicU64::new(0),
        }
    }
}

/// Returns `true` if the IP is in a private/local range.
///
/// For IPv4: RFC-1918 private ranges (10/8, 172.16/12, 192.168/16).
/// For IPv6: link-local (fe80::/10), ULA (fc00::/7), and loopback (::1).
pub(crate) fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let o = ipv4.octets();
            (o[0] == 10)
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 172 && (16..=31).contains(&o[1]))
        }
        IpAddr::V6(ipv6) => {
            let seg0 = ipv6.segments()[0];
            // fe80::/10 — link-local
            (seg0 & 0xffc0) == 0xfe80
            // fc00::/7 — unique local address (ULA)
            || (seg0 & 0xfe00) == 0xfc00
            // ::1 — loopback
            || *ipv6 == std::net::Ipv6Addr::LOCALHOST
        }
    }
}

/// Run the analysis engine. Intended to be called inside `std::thread::spawn`.
///
/// # Arguments
/// * `rx`               – Crossbeam receiver (ring buffer consumer).
/// * `alert_tx`         – Tokio unbounded sender for emitting alerts to Stage 3.
/// * `running`          – Shared shutdown flag.
/// * `stats`            – Shared atomic counters.
/// * `core_id`          – Physical core to pin to (typically 1).
/// * `dns_tracker`      – Shared passive DNS cache for IP→domain resolution.
/// * `flow_tracker`     – Shared flow tracker for anomaly detection.
/// * `anomaly_detector` – Shared anomaly detector (Isolation Forest).
pub fn run(
    rx: Receiver<RawPacket>,
    alert_tx: UnboundedSender<MitreAlert>,
    running: Arc<AtomicBool>,
    stats: Arc<EngineStats>,
    core_id: usize,
    dns_tracker: Arc<DnsTracker>,
    flow_tracker: Arc<dyn FlowAccounting>,
    _anomaly_detector: Arc<AnomalyDetector>,
    arp_guardian: Arc<ArpGuardian>,
) {
    // ── Core pinning ──────────────────────────────────────────────────
    pin_to_core("Engine", core_id);

    // ── Per-engine state (not shared — single-threaded) ───────────────
    let mut defrag = Defragmenter::new();
    let mut tcp_reassembler = Reassembler::new(10_000);
    let matrix = protocols::port_anomaly::ExpectationMatrix::new();
    let mut scanner_tracker = ScannerTracker::new(Duration::from_secs(60));
    let mut conn_tracker = ConnTracker::new(Duration::from_secs(120));
    let mut smb_tracker = SmbTracker::new();

    info!("[Engine] Analysis loop started");

    // Helper closure: enrich alert with flow metrics and emit without blocking
    let emit = |mut alert: MitreAlert, stats: &Arc<EngineStats>| {
        enrich_alert_with_flow_metrics(flow_tracker.as_ref(), &mut alert);
        stats.alerts.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = alert_tx.send(alert) {
            debug!("[Engine] Alert channel closed: {}", e);
        }
    };

    // T1041 from out-of-band byte counts (kernel flow accounting): the engine
    // then only sees each flow's DPI window, so per-packet counting in the
    // reassembler can never reach the threshold.
    let mut exfil_alerted: HashSet<l4_reassembly::FlowKey> = HashSet::new();
    let mut last_exfil_check = Instant::now();

    // ── Main analysis loop ────────────────────────────────────────────
    loop {
        if last_exfil_check.elapsed() >= EXFIL_CHECK_INTERVAL {
            last_exfil_check = Instant::now();
            if let Some(totals) = flow_tracker.take_tcp_payload_totals() {
                for alert in exfil_alerts_from_totals(totals, &mut exfil_alerted, &dns_tracker) {
                    emit(alert, &stats);
                }
            }
        }

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
            Err(e) => {
                let n = stats.parse_errors.fetch_add(1, Ordering::Relaxed) + 1;
                if n == 1 || n % 10_000 == 0 {
                    debug!("[Engine] Unparseable frame ({} so far): {}", n, e);
                }
                continue;
            }
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

        // ── Extract IP-layer source/destination ────────────────────────
        // Unified extraction: works for both IPv4 and IPv6 headers.
        let ip_addrs: Option<(IpAddr, IpAddr)> = match &headers.net {
            Some(NetHeaders::Ipv4(ip_hdr, _)) => Some((
                IpAddr::V4(ip_hdr.source.into()),
                IpAddr::V4(ip_hdr.destination.into()),
            )),
            Some(NetHeaders::Ipv6(ip_hdr, _)) => Some((
                IpAddr::V6(ip_hdr.source.into()),
                IpAddr::V6(ip_hdr.destination.into()),
            )),
            _ => None,
        };

        if let Some((scan_src, scan_dst)) = ip_addrs {
            // ── Flow Tracking for Anomaly Detection ─────────────────────
            // Record every IP packet into the FlowTracker for session aggregation.
            {
                let (src_port, dst_port, protocol, tcp_fin, tcp_rst, payload_data) =
                    match &headers.transport {
                        Some(TransportHeader::Tcp(tcp)) => (
                            tcp.source_port,
                            tcp.destination_port,
                            Protocol::Tcp,
                            tcp.fin,
                            tcp.rst,
                            Some(headers.payload.slice()),
                        ),
                        Some(TransportHeader::Udp(udp)) => (
                            udp.source_port,
                            udp.destination_port,
                            Protocol::Udp,
                            false,
                            false,
                            Some(headers.payload.slice()),
                        ),
                        _ => (0, 0, Protocol::Other(0), false, false, None),
                    };

                flow_tracker.record_packet(
                    scan_src,
                    scan_dst,
                    src_port,
                    dst_port,
                    protocol,
                    raw.data.len() as u64,
                    payload_data,
                    raw.timestamp,
                    tcp_fin,
                    tcp_rst,
                );
            }

            // ── T1046 Scanning Detection (with Connection Tracking) ────────
            //
            // TCP: Only pure SYN packets (connection initiators) are counted.
            // UDP: We maintain a ConnTracker table of outbound flows.  Inbound
            //      packets that match a known outbound flow are classified as
            //      "return traffic" (e.g. DNS responses) and are NOT counted
            //      towards the port-scan heuristic.  Only unsolicited inbound
            //      UDP packets (no matching outbound flow) are treated as
            //      potential scan probes.
            //
            // This eliminates false positives from DNS responses, NTP replies,
            // DHCP answers, etc.

            // ── UDP ConnTracker bookkeeping: record ALL UDP flows ────────
            let mut is_udp_return = false;
            if let Some(TransportHeader::Udp(udp)) = &headers.transport {
                is_udp_return = conn_tracker.is_return_traffic(
                    scan_src,
                    udp.source_port,
                    scan_dst,
                    udp.destination_port,
                );
                // Always record the flow so the reverse direction is seen as return traffic
                conn_tracker.record_flow(
                    scan_src,
                    udp.source_port,
                    scan_dst,
                    udp.destination_port,
                );
            }

            if is_local_ip(&scan_src) {
                let dst_local = is_local_ip(&scan_dst);
                match &headers.transport {
                    Some(TransportHeader::Tcp(tcp)) => {
                        // TCP: only pure SYN = connection initiator
                        if tcp.syn && !tcp.ack {
                            if let Some(scan_alert) = scanner_tracker.update(scan_src, scan_dst, tcp.destination_port, true, dst_local) {
                                // ── Importance-lowering: local-to-local scanning ────
                                let (severity, confidence) = if dst_local {
                                    // Internal network discovery — routine IT activity
                                    (Severity::Low, 30u8)
                                } else {
                                    // Scanning external hosts — more suspicious
                                    (Severity::Medium, 70u8)
                                };

                                let mut alert = MitreAlert::new(
                                    "T1046",
                                    "Network Service Discovery",
                                    severity,
                                    confidence,
                                    scan_src.to_string(),
                                    scan_dst.to_string(),
                                    tcp.source_port,
                                    tcp.destination_port,
                                    "tcp",
                                    "port_scan",
                                    serde_json::to_string(&scan_alert).unwrap_or_default(),
                                )
                                .with_meta("dst_is_local", dst_local.to_string());
                                enrich_alert_with_dns(&dns_tracker, &mut alert, None);
                                emit(alert, &stats);
                            }
                        }
                    }
                    Some(TransportHeader::Udp(udp)) => {
                        // UDP: check ConnTracker — is this an unsolicited packet?
                        if !is_udp_return {
                            let is_initiator = true;
                            if let Some(scan_alert) = scanner_tracker.update(scan_src, scan_dst, udp.destination_port, is_initiator, dst_local) {
                                // ── Importance-lowering: local-to-local scanning ────
                                let (severity, confidence) = if dst_local {
                                    (Severity::Low, 30u8)
                                } else {
                                    (Severity::Medium, 70u8)
                                };

                                let mut alert = MitreAlert::new(
                                    "T1046",
                                    "Network Service Discovery",
                                    severity,
                                    confidence,
                                    scan_src.to_string(),
                                    scan_dst.to_string(),
                                    udp.source_port,
                                    udp.destination_port,
                                    "udp",
                                    "port_scan",
                                    serde_json::to_string(&scan_alert).unwrap_or_default(),
                                )
                                .with_meta("dst_is_local", dst_local.to_string());
                                enrich_alert_with_dns(&dns_tracker, &mut alert, None);
                                emit(alert, &stats);
                            }
                        }
                    }
                    _ => {}
                }
            }

            // ── Inbound scan detection (remote → local, unsolicited) ────
            // Detect external hosts scanning our local machine.
            if !is_local_ip(&scan_src) && is_local_ip(&scan_dst) {
                match &headers.transport {
                    Some(TransportHeader::Tcp(tcp)) => {
                        // Inbound TCP SYN = someone scanning us
                        if tcp.syn && !tcp.ack {
                            if let Some(scan_alert) = scanner_tracker.update(scan_src, scan_dst, tcp.destination_port, true, true) {
                                let mut alert = MitreAlert::new(
                                    "T1046",
                                    "Network Service Discovery",
                                    Severity::High,
                                    80u8,
                                    scan_src.to_string(),
                                    scan_dst.to_string(),
                                    tcp.source_port,
                                    tcp.destination_port,
                                    "tcp",
                                    "port_scan",
                                    serde_json::to_string(&scan_alert).unwrap_or_default(),
                                )
                                .with_meta("direction", "inbound");
                                enrich_alert_with_dns(&dns_tracker, &mut alert, None);
                                emit(alert, &stats);
                            }
                        }
                    }
                    Some(TransportHeader::Udp(udp)) => {
                        // Inbound UDP: only count if NOT return traffic
                        if !is_udp_return {
                            // Unsolicited inbound UDP — potential scan
                            if let Some(scan_alert) = scanner_tracker.update(scan_src, scan_dst, udp.destination_port, true, true) {
                                let mut alert = MitreAlert::new(
                                    "T1046",
                                    "Network Service Discovery",
                                    Severity::High,
                                    80u8,
                                    scan_src.to_string(),
                                    scan_dst.to_string(),
                                    udp.source_port,
                                    udp.destination_port,
                                    "udp",
                                    "port_scan",
                                    serde_json::to_string(&scan_alert).unwrap_or_default(),
                                )
                                .with_meta("direction", "inbound");
                                enrich_alert_with_dns(&dns_tracker, &mut alert, None);
                                emit(alert, &stats);
                            }
                        }
                        // If is_return, this is a response (e.g. DNS reply) — skip scan counting
                    }
                    _ => {}
                }
            }

            // ── Application payload extraction (IPv4/IPv6 defrag) ─────────
            // etherparse's `headers.payload` is the data AFTER all parsed
            // headers (link + network + transport), i.e. the application-layer
            // payload. For fragmented packets, the transport header may be
            // missing, so `headers.payload` is the IP fragment payload which
            // must be reassembled.
            let app_payload: Option<Vec<u8>> = match &headers.net {
                Some(NetHeaders::Ipv4(ip_hdr, _)) => {
                    let ip_payload_bytes = headers.payload.slice();
                    defrag.process(ip_hdr, ip_payload_bytes)
                }
                Some(NetHeaders::Ipv6(ip_hdr, exts)) => {
                    let ip_payload_bytes = headers.payload.slice();
                    defrag.process_ipv6(ip_hdr, exts.fragment.as_ref(), ip_payload_bytes)
                }
                _ => None,
            };

            if let Some(app_payload) = app_payload {
                let src_ip = scan_src;
                let dst_ip = scan_dst;

                match headers.transport {
                    Some(TransportHeader::Tcp(tcp)) => {
                        analyze_tcp(
                            &mut tcp_reassembler,
                            &matrix,
                            &mut smb_tracker,
                            &app_payload,
                            src_ip,
                            dst_ip,
                            &tcp,
                            raw.timestamp,
                            &emit,
                            &stats,
                            &dns_tracker,
                        );
                    }
                    Some(TransportHeader::Udp(udp)) => {
                        // DNS analysis (T1071.004) + Passive DNS tracking
                        if udp.destination_port == 53 || udp.source_port == 53 {
                            let dns_data = &app_payload;
                            if !dns_data.is_empty() {

                                // ── Passive DNS: ingest responses into the tracker ──
                                if udp.source_port == 53 {
                                    dns_tracker::ingest_dns_response(dns_data, &dns_tracker);
                                }

                                // ── T1071.004: DNS tunneling / anomaly detection ────
                                if let Some(dns_report) = dns::analyze_dns(dns_data) {
                                    // Normalize direction for alert: local = src, remote = dst
                                    let (alert_src, alert_dst, alert_sp, alert_dp) =
                                        normalize_alert_direction(
                                            src_ip, dst_ip,
                                            udp.source_port, udp.destination_port,
                                        );

                                    // ── Importance-lowering: known DNS resolver ──────
                                    // DNS queries to well-known public resolvers
                                    // (Google, Cloudflare, etc.) on standard port 53
                                    // are far less likely to be tunneling.
                                    let dst_rep = reputation::lookup_ip(&alert_dst);
                                    let is_standard_dns = alert_dp == 53;
                                    let (severity, confidence) = if dst_rep.is_trusted && is_standard_dns {
                                        // Known resolver on standard port — likely benign
                                        (Severity::Low, 20u8)
                                    } else if dst_rep.is_trusted {
                                        // Known resolver on non-standard port — mild suspicion
                                        (Severity::Medium, 45u8)
                                    } else {
                                        // Unknown resolver — full severity
                                        (Severity::High, 80u8)
                                    };

                                    let mut alert = MitreAlert::new(
                                        "T1071.004",
                                        "Application Layer Protocol: DNS",
                                        severity,
                                        confidence,
                                        alert_src.to_string(),
                                        alert_dst.to_string(),
                                        alert_sp,
                                        alert_dp,
                                        "udp",
                                        "dns_anomaly",
                                        serde_json::to_string(&dns_report).unwrap_or_default(),
                                    )
                                    .with_meta("dst_provider", &dst_rep.provider);

                                    // Enrich with DNS names for src/dst IPs
                                    enrich_alert_with_dns(&dns_tracker, &mut alert, None);

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

/// Normalize packet direction for alert display.
///
/// Raw packet src/dst reflects the wire direction, which for response packets
/// is remote→local.  For alerts we always want the *connection initiator*
/// (our local machine) as Source and the remote server as Destination.
///
/// Returns `(src_ip, dst_ip, src_port, dst_port)` in normalized order.
fn normalize_alert_direction(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
) -> (IpAddr, IpAddr, u16, u16) {
    if !is_local_ip(&src_ip) && is_local_ip(&dst_ip) {
        // Response packet (remote→local): swap to show local→remote
        (dst_ip, src_ip, dst_port, src_port)
    } else {
        // Outbound packet or both-local/both-remote: keep as-is
        (src_ip, dst_ip, src_port, dst_port)
    }
}

/// Full TCP session analysis — extracted to keep the main loop readable.
#[allow(clippy::too_many_arguments)]
fn analyze_tcp(
    tcp_reassembler: &mut Reassembler,
    matrix: &protocols::port_anomaly::ExpectationMatrix,
    smb_tracker: &mut SmbTracker,
    app_payload: &[u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    tcp: &etherparse::TcpHeader,
    _timestamp: f64,
    emit: &impl Fn(MitreAlert, &Arc<EngineStats>),
    stats: &Arc<EngineStats>,
    dns_tracker: &DnsTracker,
) {
    let is_upload = is_local_ip(&src_ip);
    let packet_len = app_payload.len() as u64;

    // ── Normalized direction for alerts ─────────────────────────────────
    // The raw `src_ip`/`dst_ip` and `tcp.source_port`/`tcp.destination_port`
    // reflect the wire direction of whichever packet triggered analysis.
    // For alert display, we normalize so local IP = source, remote = dest.
    let (alert_src, alert_dst, alert_sp, alert_dp) =
        normalize_alert_direction(src_ip, dst_ip, tcp.source_port, tcp.destination_port);

    // ── Exfiltration detection (T1041) ────────────────────────────────
    // Per-packet byte counting; with kernel flow accounting the engine only
    // sees the DPI window and T1041 comes from `exfil_alerts_from_totals`.
    if let Some((up, down, ratio)) = tcp_reassembler.update_stats(
        src_ip,
        dst_ip,
        tcp.source_port,
        tcp.destination_port,
        packet_len,
        is_upload,
    ) {
        emit(
            exfil_alert(alert_src, alert_dst, alert_sp, alert_dp, up, down, ratio, dns_tracker),
            stats,
        );
    }

    // ── TCP reassembly + deep inspection ──────────────────────────────
    // NOTE: `full_ip_payload` is already the application-layer data
    // (etherparse's `headers.payload` excludes link/net/transport headers),
    // so we must NOT skip tcp.header_len() again.
    let app_data = app_payload;
    if app_data.is_empty() {
        return;
    }

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
    let port = alert_dp;

    // ── T1059 Interactive Shell ────────────────────────────────────────
    if let Some(shell_result) = shell::detect_interactive_shell(
        &session_data,
        &alert_src.to_string(),
        &alert_dst.to_string(),
        alert_sp,
        alert_dp,
    ) {
        // ── Protocol-aware false-positive filter ───────────────────────
        // Inspect the reassembled payload for legitimate multimedia /
        // streaming protocol signatures before emitting a T1059 alert.
        let filter_verdict = protocol_filter::check_payload(
            &session_data,
            alert_sp,
            alert_dp,
        );

        match filter_verdict {
            FilterVerdict::Suppress { ref reason } => {
                // Completely suppress the alert — this is legitimate traffic.
                // Optionally: log at TRACE level for debugging.
                debug!(
                    "[Engine] T1059 suppressed: {} ({}:{} → {}:{})",
                    reason,
                    alert_src, alert_sp,
                    alert_dst, alert_dp,
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
                    alert_src.to_string(),
                    alert_dst.to_string(),
                    alert_sp,
                    alert_dp,
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
                    alert_src.to_string(),
                    alert_dst.to_string(),
                    alert_sp,
                    alert_dp,
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
        // ── Importance-lowering: known provider → downgrade ─────────────
        let dst_rep = reputation::lookup_ip(&alert_dst);
        let (severity, confidence) = if dst_rep.is_trusted {
            // Trusted provider — port anomaly is likely benign protocol variation
            (Severity::Low, 20u8)
        } else {
            // Unknown provider — keep original severity
            (Severity::High, 80u8)
        };

        let mut alert = MitreAlert::new(
            &anomaly.technique,
            "Non-Standard Port",
            severity,
            confidence,
            alert_src.to_string(),
            alert_dst.to_string(),
            alert_sp,
            alert_dp,
            "tcp",
            "port_anomaly",
            &anomaly.observation,
        )
        .with_meta("entropy", format!("{:.2}", entropy))
        .with_meta("jitter", format!("{:.2}", b_score))
        .with_meta("dst_provider", &dst_rep.provider);
        enrich_alert_with_dns(dns_tracker, &mut alert, Some(entropy));
        emit(alert, stats);
    }

    // ── T1001 Obfuscation / Steganography ─────────────────────────────
    // Build context for TLS-padding CDN heuristic (SNI extracted earlier
    // in the enrichment path would be ideal, but we extract it here too
    // to keep the obfuscation module self-contained for the fast path).
    let sni_for_steg = crate::analysis::enrichment::extract_sni(&session_data);
    let alert_dst_str = alert_dst.to_string();
    let steg_ctx = protocols::obfuscation::StegContext {
        sni: sni_for_steg.as_deref(),
        dst_ip: &alert_dst_str,
    };
    if let Some(steg) = protocols::obfuscation::analyze_steganography_with_context(
        &session_data,
        port,
        Some(&steg_ctx),
    ) {
        // ── Reputation Engine: Contextual Scoring ──────────────────────
        // Use the new reputation_engine to compute contextual confidence
        // with cloud provider CIDR matching, TLS 1.3 awareness, and SNI trust.
        let is_tls13 = crate::analysis::context::looks_like_tls_1_3(&session_data);
        let rep_score = crate::analysis::reputation_engine::compute_contextual_score(
            100,
            &alert_dst_str,
            port,
            sni_for_steg.as_deref(),
            &steg.pattern_type,
            is_tls13,
        );

        if steg.is_benign {
            // ── Context-aware confidence scoring ───────────────────────
            // Use the context module for legacy flow classification, plus
            // the new reputation engine for contextual scoring.
            let ctx_verdict = crate::analysis::context::evaluate_t1001_context(
                &session_data,
                &alert_dst_str,
                port,
                sni_for_steg.as_deref(),
                steg.observed_entropy,
            );

            // Determine suppression: use reputation engine OR context verdict
            let should_suppress = rep_score.suppress || ctx_verdict.suppress;

            if should_suppress {
                // Fully suppress — log to suppressed.log for audit
                crate::analysis::context::log_suppressed(
                    &steg.technique_id,
                    &alert_src.to_string(),
                    &alert_dst_str,
                    port,
                    ctx_verdict.suppression_reason.as_deref().unwrap_or("Known CDN behavior"),
                    steg.cdn_provider.as_deref(),
                    sni_for_steg.as_deref(),
                );
                debug!(
                    "[Engine] T1001 suppressed: {} ({}:{} → {}:{}) [rep_confidence={}, is_standard_tls={}]",
                    ctx_verdict.suppression_reason.as_deref().unwrap_or("CDN"),
                    alert_src, alert_sp,
                    alert_dst, alert_dp,
                    rep_score.confidence,
                    rep_score.is_standard_tls_feature,
                );
            } else {
                // Downgraded with enriched metadata
                let severity = match rep_score.severity {
                    "DEBUG" => Severity::Debug,
                    "INFO" => Severity::Info,
                    "LOW" => Severity::Low,
                    "MEDIUM" => Severity::Medium,
                    _ => Severity::Info,
                };

                let mut alert = MitreAlert::new(
                    &steg.technique_id,
                    "Data Obfuscation",
                    severity,
                    rep_score.confidence,
                    alert_src.to_string(),
                    alert_dst.to_string(),
                    alert_sp,
                    alert_dp,
                    "tcp",
                    "obfuscation_benign",
                    &steg.reason,
                )
                .with_meta("pattern_type", &steg.pattern_type)
                .with_meta("observed_entropy", format!("{:.2}", steg.observed_entropy))
                .with_meta("verdict", "BENIGN")
                // New metadata fields from reputation engine
                .with_meta("provider_name", rep_score.provider_name)
                .with_meta("is_standard_tls_feature", rep_score.is_standard_tls_feature.to_string())
                .with_meta("flow_trust", rep_score.flow_trust);

                // Data Enrichment: cdn_provider, protocol_feature, suppression_reason
                if let Some(ref cdn) = steg.cdn_provider {
                    alert = alert.with_meta("cdn_provider", cdn);
                } else if let Some(ref cdn) = ctx_verdict.cdn_provider {
                    alert = alert.with_meta("cdn_provider", cdn);
                }
                if let Some(ref feature) = steg.protocol_feature {
                    alert = alert.with_meta("protocol_feature", feature);
                } else if let Some(ref feature) = ctx_verdict.protocol_feature {
                    alert = alert.with_meta("protocol_feature", feature);
                }
                if let Some(ref reason) = steg.suppression_reason {
                    alert = alert.with_meta("suppression_reason", reason);
                } else if let Some(ref reason) = ctx_verdict.suppression_reason {
                    alert = alert.with_meta("suppression_reason", reason);
                }
                if let Some(ref sni) = sni_for_steg {
                    alert = alert.with_meta("sni", sni);
                }

                emit(alert, stats);
            }
        } else {
            // ── Non-benign detection: apply contextual scoring ─────────
            // Even for non-benign detections, run the confidence scoring
            // to see if relief factors should reduce severity.
            let ctx_verdict = crate::analysis::context::evaluate_t1001_context(
                &session_data,
                &alert_dst_str,
                port,
                sni_for_steg.as_deref(),
                steg.observed_entropy,
            );

            // Use the reputation engine score as primary, with context as fallback
            let effective_confidence = rep_score.confidence.min(ctx_verdict.confidence);

            // Updated severity thresholds:
            // - confidence < 30 → DEBUG (suppress if reputation/protocol checks caused it)
            // - confidence > 75 → HIGH
            let (severity, confidence) = if effective_confidence < 30 {
                (Severity::Debug, effective_confidence)
            } else if effective_confidence < 50 {
                (Severity::Low, effective_confidence)
            } else if effective_confidence <= 75 {
                (Severity::Medium, effective_confidence)
            } else {
                (Severity::High, effective_confidence)
            };

            // If confidence fell below 30 due to reputation/protocol checks, suppress
            if effective_confidence < 30 && rep_score.dst_identity.is_known_provider() {
                crate::analysis::context::log_suppressed(
                    &steg.technique_id,
                    &alert_src.to_string(),
                    &alert_dst_str,
                    port,
                    &format!("Reputation-adjusted confidence {} < 30 for {}", effective_confidence, rep_score.provider_name),
                    Some(rep_score.dst_identity.provider),
                    sni_for_steg.as_deref(),
                );
                debug!(
                    "[Engine] T1001 suppressed (reputation): confidence={} provider={} ({}:{} → {}:{})",
                    effective_confidence,
                    rep_score.provider_name,
                    alert_src, alert_sp,
                    alert_dst, alert_dp,
                );
                // Don't emit — suppressed entirely
            } else {
                let mut alert = MitreAlert::new(
                    &steg.technique_id,
                    "Data Obfuscation",
                    severity,
                    confidence,
                    alert_src.to_string(),
                    alert_dst.to_string(),
                    alert_sp,
                    alert_dp,
                    "tcp",
                    "obfuscation_detected",
                    &steg.reason,
                )
                .with_meta("pattern_type", &steg.pattern_type)
                .with_meta("observed_entropy", format!("{:.2}", steg.observed_entropy))
                // New metadata fields from reputation engine
                .with_meta("provider_name", rep_score.provider_name)
                .with_meta("is_standard_tls_feature", rep_score.is_standard_tls_feature.to_string())
                .with_meta("flow_trust", rep_score.flow_trust);

                if let Some(ref cdn) = ctx_verdict.cdn_provider {
                    alert = alert.with_meta("cdn_provider", cdn);
                }
                if let Some(ref feature) = ctx_verdict.protocol_feature {
                    alert = alert.with_meta("protocol_feature", feature);
                }
                if let Some(ref reason) = ctx_verdict.suppression_reason {
                    alert = alert.with_meta("suppression_reason", reason);
                }

                emit(alert, stats);
            }
        }
    }

    // ── T1039 SMB/RPC Anomaly ─────────────────────────────────────────
    if alert_sp == 445 || alert_dp == 445 {
        let anomalies = smb_tracker.analyze_smb(
            &session_data,
            &alert_src.to_string(),
            &alert_dst.to_string(),
            alert_sp,
            alert_dp,
        );
        for smb_anomaly in anomalies {
            // ── Importance-lowering: local-to-local SMB on standard port ──
            let both_local = is_local_ip(&src_ip) && is_local_ip(&dst_ip);
            let (severity, confidence) = if both_local {
                // Internal file sharing on standard SMB port — routine traffic
                (Severity::Low, 20u8)
            } else {
                // SMB to/from external IP — much more suspicious
                (Severity::High, 75u8)
            };

            let mut alert = MitreAlert::new(
                "T1039",
                "Data from Network Shared Drive",
                severity,
                confidence,
                alert_src.to_string(),
                alert_dst.to_string(),
                alert_sp,
                alert_dp,
                "tcp",
                "smb_anomaly",
                serde_json::to_string(&smb_anomaly).unwrap_or_default(),
            )
            .with_meta("both_local", both_local.to_string());
            enrich_alert_with_dns(dns_tracker, &mut alert, None);
            emit(alert, stats);
        }
    }

    // ── T1071.001 HTTP Anomaly ────────────────────────────────────────
    if let Some(_http_report) = protocols::http::analyze_http(
        &session_data,
        &alert_src.to_string(),
        &alert_dst.to_string(),
        alert_sp,
        alert_dp,
    ) {
        // ── Importance-lowering ─────────────────────────────────────────
        let both_local = is_local_ip(&src_ip) && is_local_ip(&dst_ip);
        let dst_rep = reputation::lookup_ip(&alert_dst);
        let is_standard_http = matches!(alert_dp, 80 | 443 | 8080 | 8443);

        let (severity, confidence) = if both_local {
            // Local-to-local HTTP (AirPlay, mDNS-SD, IoT, etc.) — almost
            // always benign; devices often omit User-Agent or use short ones.
            (Severity::Low, 10u8)
        } else if dst_rep.is_trusted && is_standard_http {
            // Trusted provider on standard HTTP port — likely benign
            (Severity::Low, 15u8)
        } else if dst_rep.is_trusted {
            // Trusted provider on non-standard port — mild suspicion
            (Severity::Medium, 40u8)
        } else {
            // Unknown provider — full severity
            (Severity::High, 80u8)
        };

        let mut alert = MitreAlert::new(
            "T1071.001",
            "Application Layer Protocol: Web Protocols",
            severity,
            confidence,
            alert_src.to_string(),
            alert_dst.to_string(),
            alert_sp,
            alert_dp,
            "tcp",
            "http_anomaly",
            "HTTP anomaly detected",
        )
        .with_meta("dst_provider", &dst_rep.provider)
        .with_meta("both_local", both_local.to_string());
        enrich_alert_with_dns(dns_tracker, &mut alert, None);
        emit(alert, stats);
    }

    // ── T1562.001 SSL Stripping ───────────────────────────────────────
    if let Some(_stripping_alert) = protocols::stripping::analyze(
        &session_data,
        &alert_src.to_string(),
        &alert_dst.to_string(),
        alert_sp,
        alert_dp,
    ) {
        // ── Importance-lowering: known provider + standard port ─────────
        // SSL stripping from a trusted CDN/cloud provider on port 80/443
        // is almost certainly a legitimate HTTP→HTTPS redirect, not an attack.
        let dst_rep = reputation::lookup_ip(&alert_dst);
        let src_rep = reputation::lookup_ip(&alert_src);
        let is_standard_http = matches!(alert_dp, 80 | 443 | 8080 | 8443)
            || matches!(alert_sp, 80 | 443 | 8080 | 8443);
        let either_trusted = dst_rep.is_trusted || src_rep.is_trusted;
        let (severity, confidence) = if either_trusted && is_standard_http {
            // Trusted provider on standard HTTP port — likely legitimate redirect
            (Severity::Low, 15u8)
        } else if either_trusted {
            // Trusted provider on non-standard port — mild suspicion
            (Severity::Medium, 45u8)
        } else {
            // Unknown provider — full severity
            (Severity::High, 85u8)
        };

        let mut alert = MitreAlert::new(
            "T1562.001",
            "Impair Defenses: SSL Stripping",
            severity,
            confidence,
            alert_src.to_string(),
            alert_dst.to_string(),
            alert_sp,
            alert_dp,
            "tcp",
            "ssl_stripping",
            "SSL stripping attack detected",
        )
        .with_meta("dst_provider", &dst_rep.provider)
        .with_meta("src_provider", &src_rep.provider);
        enrich_alert_with_dns(dns_tracker, &mut alert, None);
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
                alert_src.to_string(),
                alert_dst.to_string(),
                alert_sp,
                alert_dp,
                "tcp",
                "known_malware_ja3",
                "Known Meterpreter JA3 fingerprint detected",
            )
            .with_meta("ja3", ja3_hash);
            emit(alert, stats);
        }
    }

    // Expand "standard TLS" to include all well-known encrypted ports
    let is_standard_encrypted = reputation::is_expected_encrypted_port(alert_sp)
        || reputation::is_expected_encrypted_port(alert_dp);
    let high_entropy_trigger = entropy > 7.5 && !is_standard_encrypted;

    if high_entropy_trigger || ja3_hash_str.is_some() || is_beaconing {
        // ── Step 1: Context Enrichment (SNI + domain reputation) ───────
        let scoring_input = ScoringInput {
            tls_payload: &session_data,
            dst_port: alert_dp,
            is_beaconing,
            session_data: &session_data,
        };
        let enrichment_result = enrichment::enrich(&scoring_input);
        let sni_ref = enrichment_result.enriched_context.sni.as_deref();

        // ── Step 1b: IP Reputation Lookup ─────────────────────────────
        let flow_rep = reputation::evaluate_flow(
            &alert_src.to_string(),
            &alert_dst.to_string(),
            alert_dp,
            sni_ref,
        );

        // ── Step 2: Heuristic Adjustment for T1573 ───────────────────
        // Also compute reputation engine score for enriched metadata
        let t1573_rep_score = crate::analysis::reputation_engine::compute_contextual_score(
            100,
            &alert_dst.to_string(),
            alert_dp,
            sni_ref,
            "encrypted_channel",
            crate::analysis::context::looks_like_tls_1_3(&session_data),
        );

        if high_entropy_trigger || (entropy > 7.5 && is_standard_encrypted) {
            let verdict = reputation::adjust_t1573(
                &flow_rep,
                alert_dp,
                entropy,
                sni_ref,
            );

            match verdict {
                ReputationVerdict::Suppress { reason } => {
                    // Do NOT emit T1573 — this is trusted encrypted traffic
                    debug!(
                        "[Engine] T1573 suppressed: {} ({}:{} → {}:{})",
                        reason,
                        alert_src, alert_sp,
                        alert_dst, alert_dp,
                    );
                }
                ReputationVerdict::Downgrade { reason } => {
                    // If confidence < 30 due to reputation, use DEBUG severity
                    let severity = if t1573_rep_score.confidence < 30 {
                        Severity::Debug
                    } else {
                        Severity::Info
                    };
                    let alert = MitreAlert::new(
                        "T1573",
                        "Encrypted Channel",
                        severity,
                        0,
                        alert_src.to_string(),
                        alert_dst.to_string(),
                        alert_sp,
                        alert_dp,
                        "tcp",
                        "high_entropy",
                        &reason,
                    )
                    .with_meta("entropy", format!("{:.2}", entropy))
                    .with_meta("jitter", format!("{:.2}", b_score))
                    .with_meta("provider", &flow_rep.provider)
                    .with_meta("port_service", &flow_rep.port_service)
                    .with_meta("is_whitelisted", flow_rep.is_whitelisted.to_string())
                    .with_meta("provider_name", t1573_rep_score.provider_name)
                    .with_meta("is_standard_tls_feature", t1573_rep_score.is_standard_tls_feature.to_string())
                    .with_meta("flow_trust", t1573_rep_score.flow_trust)
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
                    // Updated severity mapping: HIGH only if confidence > 75
                    let severity = match severity_hint {
                        "DEBUG" => Severity::Debug,
                        "INFO" => Severity::Info,
                        "LOW" => Severity::Low,
                        "MEDIUM" => Severity::Medium,
                        "HIGH" if confidence > 75 => Severity::High,
                        "HIGH" => Severity::Medium, // Downgrade if confidence <= 75
                        "CRITICAL" => Severity::Critical,
                        _ => Severity::Medium,
                    };
                    let alert = MitreAlert::new(
                        "T1573",
                        "Encrypted Channel",
                        severity,
                        confidence,
                        alert_src.to_string(),
                        alert_dst.to_string(),
                        alert_sp,
                        alert_dp,
                        "tcp",
                        "high_entropy",
                        &reason,
                    )
                    .with_meta("entropy", format!("{:.2}", entropy))
                    .with_meta("jitter", format!("{:.2}", b_score))
                    .with_meta("provider", &flow_rep.provider)
                    .with_meta("port_service", &flow_rep.port_service)
                    .with_meta("is_whitelisted", flow_rep.is_whitelisted.to_string())
                    .with_meta("provider_name", t1573_rep_score.provider_name)
                    .with_meta("is_standard_tls_feature", t1573_rep_score.is_standard_tls_feature.to_string())
                    .with_meta("flow_trust", t1573_rep_score.flow_trust)
                    .with_meta(
                        "sni",
                        sni_ref.unwrap_or(""),
                    );
                    emit(alert, stats);
                }
                ReputationVerdict::NoChange => {
                    // Use original enrichment-based severity with updated thresholds:
                    // HIGH only if confidence > 75 (was >= 70)
                    let severity = match enrichment_result.confidence_score {
                        0..=29 => Severity::Debug,
                        30..=49 => Severity::Low,
                        50..=75 => Severity::Medium,
                        76..=89 => Severity::High,
                        _ => Severity::Critical,
                    };
                    let is_standard = reputation::is_expected_encrypted_port(alert_dp);
                    let logic_desc = if is_standard {
                        format!(
                            "High-entropy encrypted payload to unknown provider on port {} ({})",
                            alert_dp, flow_rep.port_service,
                        )
                    } else {
                        format!(
                            "Encrypted payload on non-standard port {}",
                            alert_dp,
                        )
                    };
                    let mut alert = MitreAlert::new(
                        "T1573",
                        "Encrypted Channel",
                        severity,
                        enrichment_result.confidence_score,
                        alert_src.to_string(),
                        alert_dst.to_string(),
                        alert_sp,
                        alert_dp,
                        "tcp",
                        "high_entropy",
                        &logic_desc,
                    )
                    .with_meta("entropy", format!("{:.2}", entropy))
                    .with_meta("jitter", format!("{:.2}", b_score))
                    .with_meta("provider", &flow_rep.provider)
                    .with_meta("port_service", &flow_rep.port_service)
                    .with_meta("is_whitelisted", flow_rep.is_whitelisted.to_string())
                    .with_meta("provider_name", t1573_rep_score.provider_name)
                    .with_meta("is_standard_tls_feature", t1573_rep_score.is_standard_tls_feature.to_string())
                    .with_meta("flow_trust", t1573_rep_score.flow_trust)
                    .with_meta(
                        "sni",
                        sni_ref.unwrap_or(""),
                    );
                    enrich_alert_with_dns(dns_tracker, &mut alert, Some(entropy));
                    emit(alert, stats);
                }
            }
        }

        // ── Beaconing detection (T1011) — also enriched with reputation ─
        if is_beaconing {
            // ── Importance-lowering: trusted provider + standard port ───
            // Beaconing to known cloud/CDN on standard encrypted ports is
            // almost always legitimate keep-alive / polling traffic.
            let is_standard_port = reputation::is_expected_encrypted_port(alert_dp)
                || matches!(alert_dp, 80 | 8080 | 8443);
            let effective_confidence = if flow_rep.is_whitelisted {
                // Whitelisted flow (trusted IP + expected port, or trusted SNI on 443)
                enrichment_result.confidence_score.min(10)
            } else if flow_rep.dst_reputation.is_trusted && is_standard_port {
                // Trusted provider on standard port — cap confidence
                enrichment_result.confidence_score.min(20)
            } else if flow_rep.dst_reputation.is_trusted {
                // Trusted provider on non-standard port — moderate cap
                enrichment_result.confidence_score.min(45)
            } else {
                enrichment_result.confidence_score
            };

            // Updated severity thresholds: HIGH only if confidence > 75
            let severity = match effective_confidence {
                0..=29 => Severity::Debug,
                30..=49 => Severity::Low,
                50..=75 => Severity::Medium,
                76..=89 => Severity::High,
                _ => Severity::Critical,
            };

            let logic = if effective_confidence < 40 {
                format!(
                    "Periodic communication detected — likely legitimate {} traffic (confidence_score: {})",
                    flow_rep.provider,
                    effective_confidence
                )
            } else {
                "Periodic communication detected".to_string()
            };

            let mut alert = MitreAlert::new(
                "T1011",
                "Exfiltration Over Other Network Medium",
                severity,
                effective_confidence,
                alert_src.to_string(),
                alert_dst.to_string(),
                alert_sp,
                alert_dp,
                "tcp",
                "beaconing",
                logic,
            )
            .with_meta("jitter_score", format!("{:.2}", b_score))
            .with_meta("provider", &flow_rep.provider)
            .with_meta("port_service", &flow_rep.port_service)
            .with_meta("is_whitelisted", flow_rep.is_whitelisted.to_string());
            enrich_alert_with_dns(dns_tracker, &mut alert, Some(entropy));
            emit(alert, stats);
        }
    }
}

// ── Exfiltration (T1041) ───────────────────────────────────────────────────

/// T1041 alert for a TCP connection whose upload crossed the thresholds.
/// `local`/`remote` are already normalized (local = source).
#[allow(clippy::too_many_arguments)]
fn exfil_alert(
    local: IpAddr,
    remote: IpAddr,
    local_port: u16,
    remote_port: u16,
    uploaded: u64,
    downloaded: u64,
    ratio: f64,
    dns_tracker: &DnsTracker,
) -> MitreAlert {
    // ── Importance-lowering: known provider + standard port ─────────
    let dst_rep = reputation::lookup_ip(&remote);
    let is_standard_port = reputation::is_expected_encrypted_port(remote_port)
        || matches!(remote_port, 80 | 443 | 8080 | 8443);
    let (severity, confidence) = if dst_rep.is_trusted && is_standard_port {
        // Trusted cloud/CDN on standard port — very likely backup/sync
        (Severity::Low, 15u8)
    } else if dst_rep.is_trusted {
        // Trusted provider but unusual port — still suspicious
        (Severity::Medium, 40u8)
    } else if is_standard_port {
        // Standard port but unknown provider — moderate suspicion
        (Severity::Medium, 55u8)
    } else {
        // Unknown provider + non-standard port — full severity
        (Severity::High, 75u8)
    };

    let mut alert = MitreAlert::new(
        "T1041",
        "Exfiltration Over C2 Channel",
        severity,
        confidence,
        local.to_string(),
        remote.to_string(),
        local_port,
        remote_port,
        "tcp",
        "exfiltration",
        "Asymmetric outbound flow detected",
    )
    .with_meta("total_uploaded_mb", format!("{:.2}", uploaded as f64 / 1_000_000.0))
    .with_meta("total_downloaded_mb", format!("{:.2}", downloaded as f64 / 1_000_000.0))
    .with_meta("ratio", format!("{:.2}", ratio))
    .with_meta("dst_provider", &dst_rep.provider);
    enrich_alert_with_dns(dns_tracker, &mut alert, None);
    alert
}

/// T1041 from per-direction payload totals of live TCP flows (kernel flow
/// accounting). Directions are paired into connections the same way the
/// reassembler does; each connection alerts at most once while it lives.
fn exfil_alerts_from_totals(
    totals: Vec<(FlowKey, u64)>,
    alerted: &mut HashSet<l4_reassembly::FlowKey>,
    dns_tracker: &DnsTracker,
) -> Vec<MitreAlert> {
    #[derive(Default)]
    struct Conn {
        uploaded: u64,
        downloaded: u64,
        /// (local, remote, local port, remote port) of the largest upload
        /// direction — both directions count as uploads when both ends are local.
        upload_side: Option<(IpAddr, IpAddr, u16, u16)>,
        upload_side_bytes: u64,
    }

    let mut conns: HashMap<l4_reassembly::FlowKey, Conn> = HashMap::new();
    for (key, bytes) in totals {
        let (canonical, _) = l4_reassembly::FlowKey::canonical(
            key.src_ip, key.dst_ip, key.src_port, key.dst_port,
        );
        let conn = conns.entry(canonical).or_default();
        if is_local_ip(&key.src_ip) {
            conn.uploaded += bytes;
            if conn.upload_side.is_none() || bytes > conn.upload_side_bytes {
                conn.upload_side = Some((key.src_ip, key.dst_ip, key.src_port, key.dst_port));
                conn.upload_side_bytes = bytes;
            }
        } else {
            conn.downloaded += bytes;
        }
    }

    // Forget connections that ended, so a reused tuple can alert again.
    alerted.retain(|key| conns.contains_key(key));

    let mut alerts = Vec::new();
    for (key, conn) in conns {
        let Some((local, remote, local_port, remote_port)) = conn.upload_side else {
            continue;
        };
        if alerted.contains(&key) {
            continue;
        }
        if let Some(ratio) = l4_reassembly::exfil_ratio(conn.uploaded, conn.downloaded) {
            alerted.insert(key);
            alerts.push(exfil_alert(
                local, remote, local_port, remote_port,
                conn.uploaded, conn.downloaded, ratio, dns_tracker,
            ));
        }
    }
    alerts
}

// ── DNS Enrichment Helper ──────────────────────────────────────────────────

/// Enrich a [`MitreAlert`] with DNS-resolved domain names and adjust confidence.
///
/// Looks up both `src_ip` and `dst_ip` in the passive DNS cache. If found,
/// adds `dns_src` / `dns_dst` metadata fields. Also applies confidence
/// adjustments based on the security scoring logic in [`dns_tracker`].
///
/// Additionally, if the `provider` metadata is currently "Unknown" and the
/// DNS-resolved hostname matches a known provider (via [`enrichment::identify_provider`]),
/// the `provider` and `provider_name` metadata fields are updated.
///
/// # Arguments
/// Enrich an alert with real flow metrics from the FlowTracker.
///
/// Looks up the active flow by 5-tuple and attaches real metrics as metadata
/// keys prefixed with `flow_`. These are used by the anomaly detector in the
/// exporter to score the alert with real data instead of hardcoded defaults.
fn enrich_alert_with_flow_metrics(
    flow_tracker: &dyn FlowAccounting,
    alert: &mut MitreAlert,
) {
    let src_ip: Option<IpAddr> = alert.src_ip.parse().ok();
    let dst_ip: Option<IpAddr> = alert.dst_ip.parse().ok();

    if let (Some(src), Some(dst)) = (src_ip, dst_ip) {
        let protocol = match alert.protocol.as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            "icmp" => Protocol::Icmp,
            _ => return,
        };

        // Try both directions since alert IPs are normalized (local=src)
        // but the flow may have been recorded with the raw packet direction.
        let metrics_opt = flow_tracker
            .peek_metrics(src, dst, alert.src_port, alert.dst_port, protocol)
            .or_else(|| {
                flow_tracker.peek_metrics(
                    dst, src, alert.dst_port, alert.src_port, protocol,
                )
            });

        if let Some(metrics) = metrics_opt {
            alert.metadata.insert("flow_entropy".to_string(), format!("{:.4}", metrics.entropy));
            alert.metadata.insert("flow_duration_ms".to_string(), metrics.duration_ms.to_string());
            alert.metadata.insert("flow_packet_count".to_string(), metrics.packet_count.to_string());
            alert.metadata.insert("flow_bytes_count".to_string(), metrics.bytes_count.to_string());
            alert.metadata.insert("flow_iat_mean".to_string(), format!("{:.4}", metrics.iat_mean));
            alert.metadata.insert("flow_bytes_per_packet".to_string(), format!("{:.4}", metrics.bytes_per_packet));
            alert.metadata.insert("flow_pkt_size_variance".to_string(), format!("{:.4}", metrics.pkt_size_variance));
            alert.metadata.insert("flow_iat_std".to_string(), format!("{:.4}", metrics.iat_std));
            alert.metadata.insert("flow_payload_ratio".to_string(), format!("{:.4}", metrics.payload_ratio));
        }
    }
}

/// Enrich an alert with DNS information from the passive DNS tracker.
///
/// # Arguments
/// * `tracker`  – The shared DNS tracker.
/// * `alert`    – The alert to enrich (mutated in place).
/// * `entropy`  – Optional Shannon entropy of the traffic for dark-traffic scoring.
fn enrich_alert_with_dns(
    tracker: &DnsTracker,
    alert: &mut MitreAlert,
    entropy: Option<f64>,
) {
    let src_ip: Option<IpAddr> = alert.src_ip.parse().ok();
    let dst_ip: Option<IpAddr> = alert.dst_ip.parse().ok();

    // Enrich source IP
    if let Some(ref ip) = src_ip {
        if let Some(name) = tracker.get_name(ip) {
            alert.metadata.insert("dns_src".to_string(), name);
        }
    }

    // Enrich destination IP + apply confidence adjustment
    if let Some(ref ip) = dst_ip {
        let adj = dns_tracker::adjust_confidence(tracker, ip, alert.confidence, entropy);
        if let Some(ref domain) = adj.domain {
            alert.metadata.insert("dns_dst".to_string(), domain.clone());

            // If provider is still "Unknown", try to identify from DNS hostname
            let current_provider = alert.metadata.get("provider").map(|s| s.as_str());
            if current_provider == Some("Unknown") || current_provider.is_none() {
                if let Some(dns_provider) = enrichment::identify_provider(domain) {
                    alert.metadata.insert("provider".to_string(), dns_provider.clone());
                    alert.metadata.insert("provider_name".to_string(), dns_provider);
                }
            }
        }
        if adj.confidence != alert.confidence {
            alert
                .metadata
                .insert("dns_confidence_reason".to_string(), adj.reason.clone());
            alert.confidence = adj.confidence;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const MIB: u64 = 1024 * 1024;

    fn tcp(src: [u8; 4], src_port: u16, dst: [u8; 4], dst_port: u16) -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::from(src)),
            dst_ip: IpAddr::V4(Ipv4Addr::from(dst)),
            src_port,
            dst_port,
            protocol: Protocol::Tcp,
        }
    }

    #[test]
    fn kernel_totals_raise_t1041_once_per_connection() {
        let dns = DnsTracker::new();
        let mut alerted = HashSet::new();
        let (local, remote) = ([192, 168, 1, 10], [203, 0, 113, 5]);
        let totals = vec![
            (tcp(local, 40000, remote, 9000), 60 * MIB),
            (tcp(remote, 9000, local, 40000), 1000),
        ];

        let alerts = exfil_alerts_from_totals(totals.clone(), &mut alerted, &dns);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].technique_id, "T1041");
        assert_eq!((alerts[0].src_ip.as_str(), alerts[0].dst_port), ("192.168.1.10", 9000));

        // The same connection in the next snapshot does not alert again...
        assert!(exfil_alerts_from_totals(totals.clone(), &mut alerted, &dns).is_empty());
        // ...until it is gone and the tuple comes back.
        assert!(exfil_alerts_from_totals(Vec::new(), &mut alerted, &dns).is_empty());
        assert_eq!(exfil_alerts_from_totals(totals, &mut alerted, &dns).len(), 1);
    }

    #[test]
    fn kernel_totals_below_thresholds_do_not_alert() {
        let dns = DnsTracker::new();
        let mut alerted = HashSet::new();
        let (local, remote) = ([192, 168, 1, 10], [203, 0, 113, 5]);
        let balanced = vec![
            (tcp(local, 40000, remote, 443), 60 * MIB),
            (tcp(remote, 443, local, 40000), 10 * MIB), // ratio 6
        ];
        let small = vec![(tcp(local, 40001, remote, 443), 10 * MIB)];
        assert!(exfil_alerts_from_totals(balanced, &mut alerted, &dns).is_empty());
        assert!(exfil_alerts_from_totals(small, &mut alerted, &dns).is_empty());
    }

    #[test]
    fn both_ends_local_uses_the_larger_direction() {
        let dns = DnsTracker::new();
        let mut alerted = HashSet::new();
        let (a, b) = ([10, 0, 0, 1], [10, 0, 0, 2]);
        let totals = vec![(tcp(a, 5000, b, 9000), 1000), (tcp(b, 9000, a, 5000), 60 * MIB)];
        let alerts = exfil_alerts_from_totals(totals, &mut alerted, &dns);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].src_ip, "10.0.0.2");
    }
}
