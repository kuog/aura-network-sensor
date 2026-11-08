//! Alerts as OCSF "Detection Finding" events (class 2004, category Findings).
//!
//! Schema: <https://schema.ocsf.io/1.9.0/classes/detection_finding>. ATT&CK
//! data goes to `finding_info.attacks`, the connection and the owning process
//! to `evidences`, and metadata without an OCSF home to `unmapped`.

use std::net::IpAddr;

use serde_json::{json, Map, Value};

use super::alert::{MitreAlert, Severity};
use super::engine::is_local_ip;

pub const OCSF_VERSION: &str = "1.9.0";

const PRODUCT: &str = "aura-network-sensor";

/// Alert metadata that lands in `evidences.process` rather than `unmapped`.
const PROCESS_KEYS: &[&str] = &["proc_pid", "proc_ppid", "proc_uid", "proc_comm", "proc_exe", "proc_cmdline"];

/// The sensor that produced the event.
pub struct Producer {
    pub hostname: String,
}

/// OCSF Detection Finding for `alert`; `uid` must be unique per finding.
pub fn detection_finding(alert: &MitreAlert, producer: &Producer, uid: &str) -> Value {
    let time = alert.timestamp.timestamp_millis();
    let summary = alert.logic_text();
    let (severity_id, severity) = severity(alert.severity);
    let (confidence_id, confidence) = confidence(alert.confidence);

    let mut event = json!({
        "activity_id": 1,
        "activity_name": "Create",
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "type_uid": 200401,
        "type_name": "Detection Finding: Create",
        "time": time,
        "timezone_offset": 0,
        "severity_id": severity_id,
        "severity": severity,
        "confidence_id": confidence_id,
        "confidence": confidence,
        "confidence_score": alert.confidence,
        "status_id": 1,
        "status": "New",
        "is_alert": alert.severity >= Severity::Low,
        "message": summary,
        "metadata": {
            "version": OCSF_VERSION,
            "log_name": "alerts",
            "product": {
                "name": PRODUCT,
                "vendor_name": PRODUCT,
                "version": env!("CARGO_PKG_VERSION"),
            },
        },
        "device": {
            "hostname": producer.hostname,
            "type_id": 0,
            "type": "Unknown",
        },
        "finding_info": {
            "uid": uid,
            "title": alert.technique_name,
            "desc": summary,
            "types": [alert.trigger],
            "created_time": time,
            "analytic": { "name": alert.trigger, "type_id": 1, "type": "Rule" },
            "attacks": attacks(&alert.technique_id, &alert.technique_name),
        },
        "evidences": [evidence(alert)],
    });

    let mut unmapped: Map<String, Value> = alert
        .metadata
        .iter()
        .filter(|(k, _)| !PROCESS_KEYS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    // Detectors that report JSON in `logic`: keep the structure, not just the text.
    if let Some(report) = alert.logic_report() {
        unmapped.insert("logic_report".into(), Value::Object(report));
    }
    if !unmapped.is_empty() {
        event["unmapped"] = Value::Object(unmapped);
    }
    event
}

fn severity(severity: Severity) -> (u8, &'static str) {
    match severity {
        Severity::Debug | Severity::Info => (1, "Informational"),
        Severity::Low => (2, "Low"),
        Severity::Medium => (3, "Medium"),
        Severity::High => (4, "High"),
        Severity::Critical => (5, "Critical"),
    }
}

fn confidence(score: u8) -> (u8, &'static str) {
    match score {
        0..=39 => (1, "Low"),
        40..=74 => (2, "Medium"),
        _ => (3, "High"),
    }
}

// ── ATT&CK ────────────────────────────────────────────────────────────────

type Tactic = (&'static str, &'static str);

const EXECUTION: Tactic = ("TA0002", "Execution");
const DEFENSE_EVASION: Tactic = ("TA0005", "Defense Evasion");
const CREDENTIAL_ACCESS: Tactic = ("TA0006", "Credential Access");
const DISCOVERY: Tactic = ("TA0007", "Discovery");
const COLLECTION: Tactic = ("TA0009", "Collection");
const EXFILTRATION: Tactic = ("TA0010", "Exfiltration");
const COMMAND_AND_CONTROL: Tactic = ("TA0011", "Command and Control");

/// Techniques the engine emits: (id, ATT&CK name, tactics).
const TECHNIQUES: &[(&str, &str, &[Tactic])] = &[
    ("T1001", "Data Obfuscation", &[COMMAND_AND_CONTROL]),
    ("T1011", "Exfiltration Over Other Network Medium", &[EXFILTRATION]),
    ("T1039", "Data from Network Shared Drive", &[COLLECTION]),
    ("T1041", "Exfiltration Over C2 Channel", &[EXFILTRATION]),
    ("T1046", "Network Service Discovery", &[DISCOVERY]),
    ("T1059", "Command and Scripting Interpreter", &[EXECUTION]),
    ("T1071", "Application Layer Protocol", &[COMMAND_AND_CONTROL]),
    ("T1557", "Adversary-in-the-Middle", &[CREDENTIAL_ACCESS, COLLECTION]),
    ("T1562", "Impair Defenses", &[DEFENSE_EVASION]),
    ("T1571", "Non-Standard Port", &[COMMAND_AND_CONTROL]),
    ("T1573", "Encrypted Channel", &[COMMAND_AND_CONTROL]),
];

const SUB_TECHNIQUES: &[(&str, &str)] = &[
    ("T1071.001", "Web Protocols"),
    ("T1071.004", "DNS"),
    ("T1562.001", "Disable or Modify Tools"),
    ("T1573.002", "Asymmetric Cryptography"),
];

/// The ATT&CK id at the start of `raw` ("T1571: Non-Standard Port" → "T1571").
pub(crate) fn technique_uid(raw: &str) -> &str {
    let end = raw
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.'))
        .unwrap_or(raw.len());
    &raw[..end]
}

fn attacks(technique_id: &str, label: &str) -> Vec<Value> {
    let uid = technique_uid(technique_id);
    let (base, sub) = match uid.split_once('.') {
        Some((base, _)) => (base, Some(uid)),
        None => (uid, None),
    };
    let known = TECHNIQUES.iter().find(|(id, _, _)| *id == base);
    // Unknown technique: the engine's label up to its first colon.
    let name = known.map_or_else(|| label.split(':').next().unwrap_or(label).trim(), |t| t.1);

    let mut attack = json!({ "technique": { "uid": base, "name": name } });
    if let Some(sub) = sub {
        attack["sub_technique"] = match SUB_TECHNIQUES.iter().find(|(id, _)| *id == sub) {
            Some((_, name)) => json!({ "uid": sub, "name": name }),
            None => json!({ "uid": sub }),
        };
    }

    match known.map(|t| t.2).filter(|tactics| !tactics.is_empty()) {
        // One attack entry per tactic the technique serves.
        Some(tactics) => tactics
            .iter()
            .map(|(tactic_uid, tactic_name)| {
                let mut a = attack.clone();
                a["tactic"] = json!({ "uid": tactic_uid, "name": tactic_name });
                a
            })
            .collect(),
        None => vec![attack],
    }
}

// ── Evidence ──────────────────────────────────────────────────────────────

fn evidence(alert: &MitreAlert) -> Value {
    let src = alert.src_ip.parse::<IpAddr>().ok();
    let dst = alert.dst_ip.parse::<IpAddr>().ok();

    let mut evidence = Map::new();
    if let Some(e) = endpoint(src, alert.src_port) {
        evidence.insert("src_endpoint".into(), e);
    }
    if let Some(e) = endpoint(dst, alert.dst_port) {
        evidence.insert("dst_endpoint".into(), e);
    }
    evidence.insert("connection_info".into(), connection_info(&alert.protocol, src, dst));
    if let Some(p) = process(alert) {
        evidence.insert("process".into(), p);
    }
    Value::Object(evidence)
}

fn endpoint(ip: Option<IpAddr>, port: u16) -> Option<Value> {
    let mut e = json!({ "ip": ip?.to_string() });
    if port != 0 {
        e["port"] = json!(port);
    }
    Some(e)
}

fn connection_info(protocol: &str, src: Option<IpAddr>, dst: Option<IpAddr>) -> Value {
    // Alerts are normalized so the local host is the source.
    let (direction_id, direction) = match (src.map(|ip| is_local_ip(&ip)), dst.map(|ip| is_local_ip(&ip))) {
        (Some(true), Some(false)) => (2, "Outbound"),
        (Some(false), Some(true)) => (1, "Inbound"),
        (Some(true), Some(true)) => (3, "Lateral"),
        _ => (0, "Unknown"),
    };
    let mut info = json!({
        "protocol_name": protocol,
        "direction_id": direction_id,
        "direction": direction,
    });
    let protocol_num = match protocol {
        "icmp" => Some(1),
        "tcp" => Some(6),
        "udp" => Some(17),
        _ => None,
    };
    if let Some(num) = protocol_num {
        info["protocol_num"] = json!(num);
    }
    if let Some(ip) = src.or(dst) {
        info["protocol_ver_id"] = json!(if ip.is_ipv4() { 4 } else { 6 });
    }
    info
}

/// `evidences.process` from the eBPF `proc_*` metadata.
fn process(alert: &MitreAlert) -> Option<Value> {
    let meta = &alert.metadata;
    let pid: u32 = meta.get("proc_pid")?.parse().ok()?;
    let mut process = json!({ "pid": pid });
    if let Some(name) = meta.get("proc_comm") {
        process["name"] = json!(name);
    }
    if let Some(cmd_line) = meta.get("proc_cmdline") {
        process["cmd_line"] = json!(cmd_line);
    }
    if let Some(exe) = meta.get("proc_exe") {
        let name = exe.rsplit('/').next().unwrap_or(exe);
        process["file"] = json!({ "name": name, "path": exe, "type_id": 1, "type": "Regular File" });
    }
    if let Some(uid) = meta.get("proc_uid") {
        process["user"] = json!({ "uid": uid });
    }
    if let Some(ppid) = meta.get("proc_ppid").and_then(|v| v.parse::<u32>().ok()) {
        process["parent_process"] = json!({ "pid": ppid });
    }
    Some(process)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn producer() -> Producer {
        Producer { hostname: "sensor-1".into() }
    }

    fn reverse_shell() -> MitreAlert {
        MitreAlert::new(
            "T1059",
            "Command and Scripting Interpreter",
            Severity::Critical,
            95,
            "192.168.1.10",
            "203.0.113.5",
            41092,
            4444,
            "tcp",
            "reverse_shell",
            "'bash' redirected its stdout to a TCP connection",
        )
        .with_meta("proc_pid", "8260")
        .with_meta("proc_ppid", "8250")
        .with_meta("proc_uid", "1000")
        .with_meta("proc_comm", "bash")
        .with_meta("proc_exe", "/usr/bin/bash")
        .with_meta("proc_cmdline", "bash -i")
        .with_meta("stdio_fd", "stdout")
    }

    #[test]
    fn detection_finding_core_fields() {
        let e = detection_finding(&reverse_shell(), &producer(), "uid-1");
        assert_eq!(e["class_uid"], 2004);
        assert_eq!(e["category_uid"], 2);
        assert_eq!(e["type_uid"], 200401);
        assert_eq!(e["severity_id"], 5);
        assert_eq!(e["confidence_id"], 3);
        assert_eq!(e["confidence_score"], 95);
        assert_eq!(e["is_alert"], true);
        assert_eq!(e["metadata"]["version"], OCSF_VERSION);
        assert_eq!(e["metadata"]["product"]["name"], PRODUCT);
        assert_eq!(e["device"]["hostname"], "sensor-1");
        assert_eq!(e["finding_info"]["uid"], "uid-1");
        assert_eq!(e["finding_info"]["analytic"]["name"], "reverse_shell");

        let attack = &e["finding_info"]["attacks"][0];
        assert_eq!(attack["technique"]["uid"], "T1059");
        assert_eq!(attack["tactic"]["uid"], "TA0002");
    }

    #[test]
    fn evidence_has_connection_and_process() {
        let e = detection_finding(&reverse_shell(), &producer(), "uid-1");
        let ev = &e["evidences"][0];
        assert_eq!(ev["src_endpoint"]["ip"], "192.168.1.10");
        assert_eq!(ev["dst_endpoint"]["port"], 4444);
        assert_eq!(ev["connection_info"]["protocol_num"], 6);
        assert_eq!(ev["connection_info"]["direction_id"], 2); // outbound
        assert_eq!(ev["connection_info"]["protocol_ver_id"], 4);
        assert_eq!(ev["process"]["pid"], 8260);
        assert_eq!(ev["process"]["cmd_line"], "bash -i");
        assert_eq!(ev["process"]["file"]["name"], "bash");
        assert_eq!(ev["process"]["parent_process"]["pid"], 8250);
        // Mapped keys leave `unmapped`; the rest stays.
        assert!(e["unmapped"].get("proc_pid").is_none());
        assert_eq!(e["unmapped"]["stdio_fd"], "stdout");
    }

    #[test]
    fn sub_techniques_and_raw_ids() {
        let a = attacks("T1071.004", "Application Layer Protocol: DNS");
        assert_eq!(a[0]["technique"]["uid"], "T1071");
        assert_eq!(a[0]["sub_technique"]["uid"], "T1071.004");
        assert_eq!(a[0]["sub_technique"]["name"], "DNS");

        // The port-anomaly detector puts the name into the id.
        let a = attacks("T1571: Non-Standard Port", "Non-Standard Port");
        assert_eq!(a[0]["technique"]["uid"], "T1571");

        // A technique serving two tactics yields two attack entries.
        assert_eq!(attacks("T1557", "Adversary-in-the-Middle: ARP Spoofing").len(), 2);

        // Unknown technique: no tactic, name from the label.
        let a = attacks("T9999", "Something New: detail");
        assert_eq!(a[0]["technique"]["name"], "Something New");
        assert!(a[0].get("tactic").is_none());
    }

    #[test]
    fn arp_alert_has_no_ports() {
        let alert = MitreAlert::new(
            "T1557", "ARP Discovery: New Device", Severity::Info, 10,
            "192.168.1.20", "192.168.1.1", 0, 0, "arp", "new_device", "New device",
        );
        let e = detection_finding(&alert, &producer(), "u");
        let ev = &e["evidences"][0];
        assert!(ev["src_endpoint"].get("port").is_none());
        assert_eq!(ev["connection_info"]["direction_id"], 3); // both local
        assert!(ev.get("process").is_none());
        assert_eq!(e["is_alert"], false);
    }
}

#[cfg(test)]
mod report_tests {
    use super::*;

    #[test]
    fn json_logic_is_summarized_and_kept_structured() {
        let alert = MitreAlert::new(
            "T1046", "Network Service Discovery", Severity::Low, 30,
            "10.0.0.1", "10.0.0.2", 40000, 22, "tcp", "port_scan",
            r#"{"scanner_ip":"10.0.0.1","unique_ports_count":21,"trigger_reason":"Vertical Scan: 21 ports on 10.0.0.2"}"#,
        );
        let e = detection_finding(&alert, &Producer { hostname: "h".into() }, "u");
        assert_eq!(e["message"], "Vertical Scan: 21 ports on 10.0.0.2 (scanner_ip=10.0.0.1 unique_ports_count=21)");
        assert_eq!(e["finding_info"]["desc"], e["message"]);
        assert_eq!(e["unmapped"]["logic_report"]["unique_ports_count"], 21);
    }
}
