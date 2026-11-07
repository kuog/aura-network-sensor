//! Syslog output.
//!
//! - `local`: the local syslog socket (`/dev/log` on Linux, `/var/run/syslog`
//!   on macOS), RFC 3164 framing as local daemons expect.
//! - `udp://host[:port]`, `tcp://host[:port]`: RFC 5424; TCP frames use
//!   octet counting (RFC 6587). The default port is 514.
//!
//! Messages use facility local0; the severity follows the alert's.

use std::fmt;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::unix::net::UnixDatagram;
use std::time::{Duration, Instant};

use chrono::{DateTime, Local, SecondsFormat, Utc};

use super::alert::Severity;

const APP_NAME: &str = "mcp-network-sensor";
const FACILITY_LOCAL0: u8 = 16;
const DEFAULT_PORT: u16 = 514;
const TCP_TIMEOUT: Duration = Duration::from_secs(3);
/// After a failure, don't try to reconnect more often than this.
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

#[cfg(target_os = "macos")]
const LOCAL_SOCKET: &str = "/var/run/syslog";
#[cfg(not(target_os = "macos"))]
const LOCAL_SOCKET: &str = "/dev/log";

/// Where syslog messages go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Local,
    Udp(String),
    Tcp(String),
}

impl std::str::FromStr for Target {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "local" {
            return Ok(Target::Local);
        }
        let usage = || format!("expected local, udp://host[:port] or tcp://host[:port], got '{s}'");
        let (scheme, addr) = s.split_once("://").ok_or_else(usage)?;
        if addr.is_empty() {
            return Err(usage());
        }
        let has_port = match addr.strip_prefix('[') {
            Some(v6) => v6.contains("]:"),
            None => addr.contains(':'),
        };
        let addr = if has_port {
            addr.to_string()
        } else {
            format!("{addr}:{DEFAULT_PORT}")
        };
        match scheme {
            "udp" => Ok(Target::Udp(addr)),
            "tcp" => Ok(Target::Tcp(addr)),
            _ => Err(usage()),
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Local => write!(f, "local ({LOCAL_SOCKET})"),
            Target::Udp(addr) => write!(f, "udp://{addr}"),
            Target::Tcp(addr) => write!(f, "tcp://{addr}"),
        }
    }
}

enum Conn {
    Unix(UnixDatagram),
    Udp(UdpSocket),
    Tcp(TcpStream),
}

/// A syslog client that connects lazily and reconnects after failures.
pub struct Syslog {
    target: Target,
    hostname: String,
    pid: u32,
    conn: Option<Conn>,
    retry_at: Option<Instant>,
}

impl Syslog {
    pub fn new(target: Target, hostname: &str) -> Self {
        // RFC 5424 HOSTNAME is printable ASCII without spaces.
        let hostname: String = hostname.chars().filter(|c| c.is_ascii_graphic()).collect();
        Self {
            target,
            hostname: if hostname.is_empty() { "-".into() } else { hostname },
            pid: std::process::id(),
            conn: None,
            retry_at: None,
        }
    }

    /// Send one message; `msgid` is a short tag such as the technique id.
    pub fn send(&mut self, severity: Severity, msgid: &str, msg: &str, time: DateTime<Utc>) -> io::Result<()> {
        let frame = match self.target {
            Target::Local => format_rfc3164(severity, time.with_timezone(&Local), self.pid, msg),
            _ => format_rfc5424(severity, time, &self.hostname, self.pid, msgid, msg),
        };
        let result = self.connection().and_then(|conn| match conn {
            Conn::Unix(sock) => sock.send_to(frame.as_bytes(), LOCAL_SOCKET).map(drop),
            Conn::Udp(sock) => sock.send(frame.as_bytes()).map(drop),
            Conn::Tcp(stream) => stream.write_all(format!("{} {}", frame.len(), frame).as_bytes()),
        });
        if result.is_err() {
            self.conn = None;
            self.retry_at = Some(Instant::now() + RETRY_INTERVAL);
        }
        result
    }

    fn connection(&mut self) -> io::Result<&mut Conn> {
        if self.conn.is_none() {
            if self.retry_at.is_some_and(|at| Instant::now() < at) {
                return Err(io::Error::new(io::ErrorKind::NotConnected, "syslog unavailable, retrying later"));
            }
            self.conn = Some(self.connect()?);
            self.retry_at = None;
        }
        Ok(self.conn.as_mut().expect("connected above"))
    }

    fn connect(&self) -> io::Result<Conn> {
        match &self.target {
            Target::Local => Ok(Conn::Unix(UnixDatagram::unbound()?)),
            Target::Udp(addr) => {
                let addr = resolve(addr)?;
                let any: SocketAddr = if addr.is_ipv4() {
                    "0.0.0.0:0".parse().expect("valid address")
                } else {
                    "[::]:0".parse().expect("valid address")
                };
                let sock = UdpSocket::bind(any)?;
                sock.connect(addr)?;
                Ok(Conn::Udp(sock))
            }
            Target::Tcp(addr) => {
                let stream = TcpStream::connect_timeout(&resolve(addr)?, TCP_TIMEOUT)?;
                stream.set_write_timeout(Some(TCP_TIMEOUT))?;
                Ok(Conn::Tcp(stream))
            }
        }
    }
}

fn resolve(addr: &str) -> io::Result<SocketAddr> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve {addr}")))
}

fn priority(severity: Severity) -> u8 {
    let code = match severity {
        Severity::Critical => 2, // crit
        Severity::High => 3,     // err
        Severity::Medium => 4,   // warning
        Severity::Low => 5,      // notice
        Severity::Info => 6,     // info
        Severity::Debug => 7,    // debug
    };
    FACILITY_LOCAL0 * 8 + code
}

/// `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG`
fn format_rfc5424(severity: Severity, time: DateTime<Utc>, hostname: &str, pid: u32, msgid: &str, msg: &str) -> String {
    let msgid: String = msgid.chars().filter(|c| c.is_ascii_graphic()).take(32).collect();
    format!(
        "<{}>1 {} {} {} {} {} - {}",
        priority(severity),
        time.to_rfc3339_opts(SecondsFormat::Millis, true),
        hostname,
        APP_NAME,
        pid,
        if msgid.is_empty() { "-" } else { &msgid },
        msg,
    )
}

/// `<PRI>Mmm dd hh:mm:ss APP[PID]: MSG` — the local daemon adds the hostname.
fn format_rfc3164(severity: Severity, time: DateTime<Local>, pid: u32, msg: &str) -> String {
    format!("<{}>{} {}[{}]: {}", priority(severity), time.format("%b %e %H:%M:%S"), APP_NAME, pid, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::net::UdpSocket;

    #[test]
    fn targets() {
        assert_eq!("local".parse::<Target>(), Ok(Target::Local));
        assert_eq!("udp://10.0.0.5".parse::<Target>(), Ok(Target::Udp("10.0.0.5:514".into())));
        assert_eq!("tcp://siem:6514".parse::<Target>(), Ok(Target::Tcp("siem:6514".into())));
        assert_eq!("udp://[::1]".parse::<Target>(), Ok(Target::Udp("[::1]:514".into())));
        assert_eq!("udp://[::1]:5514".parse::<Target>(), Ok(Target::Udp("[::1]:5514".into())));
        assert!("syslog.example.com".parse::<Target>().is_err());
        assert!("http://x".parse::<Target>().is_err());
        assert!("udp://".parse::<Target>().is_err());
    }

    #[test]
    fn rfc5424_header() {
        let time = Utc.with_ymd_and_hms(2026, 11, 7, 13, 44, 15).unwrap();
        let line = format_rfc5424(Severity::Critical, time, "sensor-1", 42, "T1059", "CRITICAL T1059 ...");
        // local0 (16) * 8 + crit (2) = 130
        assert_eq!(line, "<130>1 2026-11-07T13:44:15.000Z sensor-1 mcp-network-sensor 42 T1059 - CRITICAL T1059 ...");
    }

    #[test]
    fn rfc3164_header() {
        let time = Local.with_ymd_and_hms(2026, 11, 7, 9, 5, 1).unwrap();
        let line = format_rfc3164(Severity::Info, time, 42, "msg");
        assert_eq!(line, "<134>Nov  7 09:05:01 mcp-network-sensor[42]: msg");
    }

    #[test]
    fn sends_over_udp() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = Target::Udp(server.local_addr().unwrap().to_string());
        let mut syslog = Syslog::new(target, "sensor 1");
        syslog.send(Severity::High, "T1046", "hello", Utc::now()).unwrap();

        let mut buf = [0u8; 512];
        let n = server.recv(&mut buf).unwrap();
        let got = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(got.starts_with("<131>1 "), "{got}");
        assert!(got.contains(" sensor1 mcp-network-sensor "), "{got}");
        assert!(got.ends_with(" T1046 - hello"), "{got}");
    }
}
