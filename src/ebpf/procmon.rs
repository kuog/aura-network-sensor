//! Process attribution and reverse-shell detection (`src/bpf/procmon.bpf.c`).
//!
//! Kernel probes report TCP connects and accepts with the owning process,
//! and TCP sockets dup'ed onto stdin/stdout/stderr. Connections fill a
//! [`ProcessCache`] that the exporter uses to add `proc_*` metadata to
//! alerts; a socket on stdio raises a T1059 alert directly.

use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{ErrorKind, Link, RingBufferBuilder};
use log::warn;
use lru::LruCache;
use tokio::sync::mpsc::UnboundedSender;

use super::skel::procmon::{types, ProcmonSkelBuilder};
use super::{from_bytes, ip_from_bytes, namespace_id};
use crate::analysis::process::{ProcInfo, ProcessLookup};
use crate::pipeline::alert::{MitreAlert, Severity};

// Must match `enum mcp_proc_event_kind` in common.h.
const EV_CONNECT: u32 = 1;
const EV_ACCEPT: u32 = 2;
const EV_STDIO_SOCKET: u32 = 3;

const AF_INET: u16 = 2;

const CONNECTION_CACHE: usize = 65_536;
const PROC_DETAILS_CACHE: usize = 4_096;
/// /proc details are re-read after this long (pids get reused).
const PROC_DETAILS_TTL: Duration = Duration::from_secs(10);
/// A shell redirecting fds 0, 1 and 2 to the same socket is one alert.
const SHELL_ALERT_DEDUP: Duration = Duration::from_secs(10);
const POLL_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_CMDLINE_CHARS: usize = 256;

/// Programs whose stdio on a TCP socket is the classic reverse shell.
const INTERPRETERS: &[&str] = &[
    "bash", "sh", "dash", "zsh", "ksh", "mksh", "fish", "csh", "tcsh", "ash", "busybox",
    "python", "perl", "ruby", "php", "node", "lua", "pwsh", "awk", "gawk", "mawk",
    "nc", "ncat", "netcat", "socat", "telnet",
];

/// `python3.12`, `php8.3` and `nc.openbsd` count as their base name.
fn is_interpreter(comm: &str) -> bool {
    let base = comm.split('.').next().unwrap_or(comm);
    INTERPRETERS.contains(&base.trim_end_matches(|c: char| c.is_ascii_digit()))
}

/// (local ip, local port, remote ip, remote port)
type ConnKey = (IpAddr, u16, IpAddr, u16);

/// TCP connection → owning process, filled from kernel events.
pub struct ProcessCache {
    conns: Mutex<LruCache<ConnKey, ProcInfo>>,
}

impl ProcessCache {
    fn new() -> Self {
        let capacity = NonZeroUsize::new(CONNECTION_CACHE).expect("non-zero capacity");
        Self { conns: Mutex::new(LruCache::new(capacity)) }
    }

    fn insert(&self, key: ConnKey, info: ProcInfo) {
        self.conns.lock().unwrap_or_else(|e| e.into_inner()).put(key, info);
    }
}

impl ProcessLookup for ProcessCache {
    fn lookup(&self, a: IpAddr, a_port: u16, b: IpAddr, b_port: u16) -> Option<ProcInfo> {
        let mut conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(info) = conns.get(&(a, a_port, b, b_port)) {
            return Some(info.clone());
        }
        conns.get(&(b, b_port, a, a_port)).cloned()
    }
}

/// Load the probes and start the event thread. Returns once the probes are
/// attached, with the names of those that are.
pub fn spawn(
    alert_tx: UnboundedSender<MitreAlert>,
    running: Arc<AtomicBool>,
) -> Result<(Arc<ProcessCache>, JoinHandle<()>, Vec<&'static str>)> {
    let cache = Arc::new(ProcessCache::new());
    let thread_cache = cache.clone();
    let (ready_tx, ready_rx) = mpsc::channel();

    let handle = std::thread::Builder::new()
        .name("procmon".to_string())
        .spawn(move || {
            if let Err(e) = run(&thread_cache, &alert_tx, &running, &ready_tx) {
                // Before startup completes this goes to spawn(); later, to the log.
                if let Err(mpsc::SendError(Err(e))) = ready_tx.send(Err(e)) {
                    warn!("[Procmon] Stopped: {e:#}");
                }
            }
        })
        .context("failed to spawn the procmon thread")?;

    match ready_rx.recv() {
        Ok(Ok(probes)) => Ok((cache, handle, probes)),
        Ok(Err(e)) => {
            let _ = handle.join();
            Err(e)
        }
        Err(_) => {
            let _ = handle.join();
            bail!("procmon thread exited during startup")
        }
    }
}

fn run(
    cache: &ProcessCache,
    alert_tx: &UnboundedSender<MitreAlert>,
    running: &AtomicBool,
    ready: &mpsc::Sender<Result<Vec<&'static str>>>,
) -> Result<()> {
    let (pidns_dev, pidns_ino) = namespace_id("/proc/self/ns/pid").context("reading the pid namespace")?;
    let (_, netns_ino) = namespace_id("/proc/self/ns/net").context("reading the network namespace")?;

    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = ProcmonSkelBuilder::default()
        .open(&mut open_object)
        .context("failed to open the procmon BPF object")?;
    if let Some(rodata) = open_skel.maps.rodata_data.as_deref_mut() {
        rodata.target_netns_ino = netns_ino as u32;
        rodata.pidns_dev = pidns_dev;
        rodata.pidns_ino = pidns_ino;
        rodata.self_tgid = std::process::id();
    }
    // dup2(2) is a syscall of its own only on some architectures.
    let has_dup2 = cfg!(target_arch = "x86_64");
    open_skel.progs.handle_dup2.set_autoload(has_dup2);
    let skel = open_skel.load().context("failed to load procmon")?;

    let mut probes = vec![
        ("tcp_connect", &skel.progs.handle_tcp_connect),
        ("inet_csk_accept", &skel.progs.handle_inet_csk_accept),
        ("dup3", &skel.progs.handle_dup3),
    ];
    if has_dup2 {
        probes.push(("dup2", &skel.progs.handle_dup2));
    }

    let mut links: Vec<Link> = Vec::new();
    let mut attached = Vec::new();
    for (name, prog) in probes {
        match prog.attach() {
            Ok(link) => {
                links.push(link);
                attached.push(name);
            }
            Err(e) => warn!("[Procmon] Probe {name} not attached: {e}"),
        }
    }
    if links.is_empty() {
        bail!("none of the procmon probes could be attached");
    }
    let _ = ready.send(Ok(attached));

    let mut handler = EventHandler::new(cache, alert_tx);
    let mut builder = RingBufferBuilder::new();
    builder.add(&skel.maps.events, |data: &[u8]| {
        handler.handle(data);
        0
    })?;
    let ring = builder.build()?;

    while running.load(Ordering::Relaxed) {
        if let Err(e) = ring.poll(POLL_TIMEOUT) {
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(e).context("ring buffer poll failed");
        }
    }
    drop(ring);
    drop(links);
    Ok(())
}

/// /proc data of a process, read when its event arrives (it may exit soon).
struct ProcDetails {
    comm: String,
    exe: Option<String>,
    cmdline: Option<String>,
    ppid: Option<u32>,
    read_at: Instant,
}

struct EventHandler<'a> {
    cache: &'a ProcessCache,
    alert_tx: &'a UnboundedSender<MitreAlert>,
    /// Scanners open many connections from one process: read /proc once.
    details: LruCache<u32, ProcDetails>,
    /// Recent reverse-shell alerts by (pid, local, local port, remote, remote port).
    shell_alerts: HashMap<(u32, IpAddr, u16, IpAddr, u16), Instant>,
}

impl<'a> EventHandler<'a> {
    fn new(cache: &'a ProcessCache, alert_tx: &'a UnboundedSender<MitreAlert>) -> Self {
        let capacity = NonZeroUsize::new(PROC_DETAILS_CACHE).expect("non-zero capacity");
        Self { cache, alert_tx, details: LruCache::new(capacity), shell_alerts: HashMap::new() }
    }

    fn handle(&mut self, data: &[u8]) {
        let Some(ev) = from_bytes::<types::mcp_proc_event>(data) else {
            return;
        };
        let v4 = ev.family == AF_INET;
        // Dual-stack sockets talk to IPv4 peers through IPv4-mapped addresses.
        let local = ip_from_bytes(v4, &ev.laddr).to_canonical();
        let remote = ip_from_bytes(v4, &ev.raddr).to_canonical();
        let key = (local, ev.lport, remote, ev.rport);

        match ev.kind {
            EV_CONNECT | EV_ACCEPT => {
                let info = self.proc_info(&ev);
                self.cache.insert(key, info);
            }
            EV_STDIO_SOCKET => {
                let info = self.proc_info(&ev);
                self.cache.insert(key, info.clone());
                self.reverse_shell(&ev, info, local, remote);
            }
            _ => {}
        }
    }

    fn proc_info(&mut self, ev: &types::mcp_proc_event) -> ProcInfo {
        let comm = comm_string(&ev.comm);
        let pid_in_ns = ev.pid_in_ns != 0;
        let (exe, cmdline, ppid) = if pid_in_ns {
            let d = self.details(ev.pid, &comm);
            (d.exe.clone(), d.cmdline.clone(), d.ppid)
        } else {
            // Outside our pid namespace: /proc here would describe another process.
            (None, None, None)
        };
        ProcInfo { pid: ev.pid, pid_in_ns, ppid, uid: ev.uid, comm, exe, cmdline }
    }

    fn details(&mut self, pid: u32, comm: &str) -> &ProcDetails {
        let fresh = self
            .details
            .peek(&pid)
            .is_some_and(|d| d.comm == comm && d.read_at.elapsed() < PROC_DETAILS_TTL);
        if !fresh {
            self.details.put(pid, read_proc(pid, comm));
        }
        self.details.get(&pid).expect("entry was just ensured")
    }

    fn reverse_shell(&mut self, ev: &types::mcp_proc_event, info: ProcInfo, local: IpAddr, remote: IpAddr) {
        let now = Instant::now();
        self.shell_alerts.retain(|_, at| now.duration_since(*at) < SHELL_ALERT_DEDUP);
        let key = (ev.pid, local, ev.lport, remote, ev.rport);
        if self.shell_alerts.insert(key, now).is_some() {
            return;
        }

        let interpreter = is_interpreter(&info.comm);
        let (severity, confidence) = if interpreter {
            (Severity::Critical, 95)
        } else {
            (Severity::High, 75)
        };
        let stream = match ev.fd {
            0 => "stdin",
            1 => "stdout",
            _ => "stderr",
        };
        let logic = format!(
            "'{}' (pid {}) redirected its {} to a TCP connection with {}:{}",
            info.comm, info.pid, stream, remote, ev.rport,
        );

        let mut alert = MitreAlert::new(
            "T1059",
            "Command and Scripting Interpreter",
            severity,
            confidence,
            local.to_string(),
            remote.to_string(),
            ev.lport,
            ev.rport,
            "tcp",
            "reverse_shell",
            logic,
        )
        .with_meta("stdio_fd", stream)
        .with_meta("interpreter", interpreter.to_string());
        info.annotate(&mut alert);

        // Fails only once the exporter is gone, i.e. during shutdown.
        let _ = self.alert_tx.send(alert);
    }
}

fn comm_string(raw: &[i8]) -> String {
    let bytes: Vec<u8> = raw.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn read_proc(pid: u32, comm: &str) -> ProcDetails {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok().and_then(|raw| {
        let args: Vec<_> = raw
            .split(|&b| b == 0)
            .filter(|arg| !arg.is_empty())
            .map(String::from_utf8_lossy)
            .collect();
        let line = args.join(" ");
        (!line.is_empty()).then(|| line.chars().take(MAX_CMDLINE_CHARS).collect())
    });
    let ppid = std::fs::read_to_string(format!("/proc/{pid}/status")).ok().and_then(|status| {
        status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|v| v.trim().parse().ok())
    });
    ProcDetails { comm: comm.to_string(), exe, cmdline, ppid, read_at: Instant::now() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpreter_names() {
        for comm in ["bash", "sh", "python3", "python3.12", "php8.3", "nc", "nc.openbsd", "perl"] {
            assert!(is_interpreter(comm), "{comm}");
        }
        for comm in ["sshd", "systemd", "nginx", "curl", "bashful"] {
            assert!(!is_interpreter(comm), "{comm}");
        }
    }

    #[test]
    fn comm_stops_at_nul() {
        let mut raw = [0i8; 16];
        for (dst, src) in raw.iter_mut().zip(b"bash") {
            *dst = *src as i8;
        }
        assert_eq!(comm_string(&raw), "bash");
    }
}
