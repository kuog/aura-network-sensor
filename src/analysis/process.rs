//! Process context for network alerts.
//!
//! The lookup itself is platform-specific (eBPF on Linux, see
//! `crate::ebpf::procmon`); this module only defines what an alert gets.

use std::net::IpAddr;

use crate::pipeline::alert::MitreAlert;

/// The process that owns a connection, as seen when it was opened.
#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    /// `pid` belongs to the sensor's own pid namespace, so the /proc-derived
    /// fields below describe this process. Otherwise only `comm`/`uid` are known.
    pub pid_in_ns: bool,
    pub ppid: Option<u32>,
    pub uid: u32,
    pub comm: String,
    pub exe: Option<String>,
    pub cmdline: Option<String>,
}

impl ProcInfo {
    /// Attach the `proc_*` metadata fields to an alert.
    pub fn annotate(&self, alert: &mut MitreAlert) {
        let meta = &mut alert.metadata;
        meta.insert("proc_pid".into(), self.pid.to_string());
        if !self.pid_in_ns {
            meta.insert("proc_pid_ns".into(), "other".into());
        }
        if let Some(ppid) = self.ppid {
            meta.insert("proc_ppid".into(), ppid.to_string());
        }
        meta.insert("proc_uid".into(), self.uid.to_string());
        meta.insert("proc_comm".into(), self.comm.clone());
        if let Some(exe) = &self.exe {
            meta.insert("proc_exe".into(), exe.clone());
        }
        if let Some(cmdline) = &self.cmdline {
            meta.insert("proc_cmdline".into(), cmdline.clone());
        }
    }
}

/// Finds the process behind a TCP connection.
pub trait ProcessLookup: Send + Sync {
    /// Process owning the TCP connection between the two endpoints, in
    /// either orientation.
    fn lookup(&self, a: IpAddr, a_port: u16, b: IpAddr, b_port: u16) -> Option<ProcInfo>;
}

/// Add process metadata to a TCP alert when the owning process is known.
pub fn enrich_alert(lookup: &dyn ProcessLookup, alert: &mut MitreAlert) {
    if alert.protocol != "tcp" || alert.metadata.contains_key("proc_pid") {
        return;
    }
    let (Ok(src), Ok(dst)) = (alert.src_ip.parse::<IpAddr>(), alert.dst_ip.parse::<IpAddr>()) else {
        return;
    };
    if let Some(info) = lookup.lookup(src, alert.src_port, dst, alert.dst_port) {
        info.annotate(alert);
    }
}
