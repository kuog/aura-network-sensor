//! Engine benchmark and alert snapshot. Both run on demand:
//!
//! ```bash
//! cargo test --release engine_throughput -- --ignored --nocapture
//! ALERT_SNAPSHOT=alerts.jsonl cargo test --release alert_snapshot -- --ignored --nocapture
//! ```
//!
//! They feed synthetic Ethernet frames through the real [`engine::run`].
//! `alert_snapshot` records the alerts for a fixed traffic mix, without their
//! wall-clock timestamps: two builds that agree on detection write identical
//! files.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::DateTime;
use etherparse::{IpHeaders, PacketBuilder, PacketBuilderStep, VlanId};

use super::alert::MitreAlert;
use super::engine::{self, EngineStats};
use super::sniffer::RawPacket;
use crate::analysis::arp_provider::ArpGuardian;
use crate::analysis::dns_tracker::DnsTracker;
use crate::anomaly::detector::AnomalyDetector;
use crate::anomaly::flow_tracker::{FlowAccounting, FlowTracker};

const MAC_A: [u8; 6] = [2, 0, 0, 0, 0, 1];
const MAC_B: [u8; 6] = [2, 0, 0, 0, 0, 2];

const CLIENT: &str = "192.168.1.10";
const LAN: &str = "192.168.1.20";
const UNKNOWN: &str = "203.0.113.5";
const CLOUDFLARE: &str = "104.16.0.1";
const AWS: &str = "52.0.0.1";
const GOOGLE: &str = "216.58.192.14";
const MICROSOFT: &str = "40.76.4.15";

const BROWSER_GET: &[u8] =
    b"GET / HTTP/1.1\r\nHost: example.org\r\nUser-Agent: Mozilla/5.0 (X11) Gecko Firefox/120.0\r\n\r\n";

type Endpoint = (IpAddr, u16);

fn ep(ip: &str, port: u16) -> Endpoint {
    (ip.parse().unwrap(), port)
}

/// Deterministic pseudo-random bytes, independent of any crate's generator.
struct Prng(u64);

impl Prng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next() >> 24) as u8).collect()
    }

    fn base62(&mut self, len: usize) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..len)
            .map(|_| ALPHABET[(self.next() >> 24) as usize % ALPHABET.len()] as char)
            .collect()
    }
}

#[derive(Clone, Copy)]
enum Tcp {
    Syn,
    SynAck,
    Ack,
    Data,
    Fin,
}

fn ip_step(src: IpAddr, dst: IpAddr) -> PacketBuilderStep<IpHeaders> {
    let ethernet = PacketBuilder::ethernet2(MAC_A, MAC_B);
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => ethernet.ipv4(s.octets(), d.octets(), 64),
        (IpAddr::V6(s), IpAddr::V6(d)) => ethernet.ipv6(s.octets(), d.octets(), 64),
        _ => panic!("mixed address families"),
    }
}

fn tcp_frame_on(step: PacketBuilderStep<IpHeaders>, src: Endpoint, dst: Endpoint, kind: Tcp, payload: &[u8]) -> Vec<u8> {
    let step = step.tcp(src.1, dst.1, 1, 64_240);
    let step = match kind {
        Tcp::Syn => step.syn(),
        Tcp::SynAck => step.syn().ack(1),
        Tcp::Ack => step.ack(1),
        Tcp::Data => step.psh().ack(1),
        Tcp::Fin => step.fin().ack(1),
    };
    let mut frame = Vec::with_capacity(step.size(payload.len()));
    step.write(&mut frame, payload).unwrap();
    frame
}

fn tcp_frame(src: Endpoint, dst: Endpoint, kind: Tcp, payload: &[u8]) -> Vec<u8> {
    tcp_frame_on(ip_step(src.0, dst.0), src, dst, kind, payload)
}

fn udp_frame(src: Endpoint, dst: Endpoint, payload: &[u8]) -> Vec<u8> {
    let step = ip_step(src.0, dst.0).udp(src.1, dst.1);
    let mut frame = Vec::with_capacity(step.size(payload.len()));
    step.write(&mut frame, payload).unwrap();
    frame
}

fn arp_frame(vlan_tags: usize, opcode: u16, mac: [u8; 6], ip: [u8; 4], target: [u8; 4]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend([0xff; 6]);
    frame.extend(mac);
    for tag in 0..vlan_tags {
        frame.extend(if vlan_tags == 2 && tag == 0 { [0x88, 0xa8] } else { [0x81, 0x00] });
        frame.extend([0x00, 0x0a + tag as u8]);
    }
    frame.extend([0x08, 0x06]);
    frame.extend([0, 1, 8, 0, 6, 4]);
    frame.extend(opcode.to_be_bytes());
    frame.extend(mac);
    frame.extend(ip);
    frame.extend([0; 6]);
    frame.extend(target);
    frame
}

fn dns_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in name.split('.') {
        encoded.push(label.len() as u8);
        encoded.extend(label.as_bytes());
    }
    encoded.push(0);
    encoded
}

fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend(id.to_be_bytes());
    msg.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    msg.extend(dns_name(name));
    msg.extend([0, 1, 0, 1]);
    msg
}

fn dns_response(id: u16, name: &str, a: &[[u8; 4]], aaaa: &[[u8; 16]], ttl: u32) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend(id.to_be_bytes());
    msg.extend([0x81, 0x80, 0, 1]);
    msg.extend(((a.len() + aaaa.len()) as u16).to_be_bytes());
    msg.extend([0, 0, 0, 0]);
    msg.extend(dns_name(name));
    msg.extend([0, 1, 0, 1]);
    let mut answer = |rtype: u16, rdata: &[u8]| {
        msg.extend([0xc0, 0x0c]);
        msg.extend(rtype.to_be_bytes());
        msg.extend([0, 1]);
        msg.extend(ttl.to_be_bytes());
        msg.extend((rdata.len() as u16).to_be_bytes());
        msg.extend(rdata);
    };
    for addr in a {
        answer(1, addr);
    }
    for addr in aaaa {
        answer(28, addr);
    }
    msg
}

/// A TLS record with a Client Hello. `broken_tail` adds an extension whose
/// length overruns the block, which only the manual SNI parser tolerates.
fn client_hello(sni: &str, padding: usize, tls13: bool, broken_tail: bool) -> Vec<u8> {
    fn u16be(out: &mut Vec<u8>, value: usize) {
        out.extend((value as u16).to_be_bytes());
    }

    let mut exts = Vec::new();
    if !sni.is_empty() {
        u16be(&mut exts, 0x0000);
        u16be(&mut exts, sni.len() + 5);
        u16be(&mut exts, sni.len() + 3);
        exts.push(0);
        u16be(&mut exts, sni.len());
        exts.extend(sni.as_bytes());
    }
    u16be(&mut exts, 0x000a);
    u16be(&mut exts, 6);
    u16be(&mut exts, 4);
    u16be(&mut exts, 0x001d);
    u16be(&mut exts, 0x0017);
    u16be(&mut exts, 0x000b);
    u16be(&mut exts, 2);
    exts.extend([1, 0]);
    if tls13 {
        u16be(&mut exts, 0x002b);
        u16be(&mut exts, 3);
        exts.push(2);
        u16be(&mut exts, 0x0304);
    }
    if padding > 0 {
        u16be(&mut exts, 0x0015);
        u16be(&mut exts, padding);
        exts.resize(exts.len() + padding, 0);
    }
    if broken_tail {
        exts.extend([0xff, 0xff, 0xff, 0xff]);
    }

    let mut hello = Vec::new();
    u16be(&mut hello, 0x0303);
    hello.extend([0x11; 32]);
    hello.push(0);
    u16be(&mut hello, 4);
    u16be(&mut hello, 0x1301);
    u16be(&mut hello, 0xc02f);
    hello.extend([1, 0]);
    u16be(&mut hello, exts.len());
    hello.extend(exts);

    let mut handshake = vec![0x01];
    handshake.extend(&(hello.len() as u32).to_be_bytes()[1..]);
    handshake.extend(hello);

    let mut record = vec![0x16, 0x03, 0x01];
    u16be(&mut record, handshake.len());
    record.extend(handshake);
    record
}

fn smb_header(command: u16, flags: u32) -> Vec<u8> {
    let mut header = vec![0u8; 64];
    header[..4].copy_from_slice(b"\xFESMB");
    header[12..14].copy_from_slice(&command.to_le_bytes());
    header[16..20].copy_from_slice(&flags.to_le_bytes());
    header
}

fn smb_create(name: &str) -> Vec<u8> {
    const BODY: usize = 56;
    let utf16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut message = smb_header(5, 0);
    message.resize(64 + BODY, 0);
    message[68..70].copy_from_slice(&((64 + BODY) as u16).to_le_bytes());
    message[70..72].copy_from_slice(&(utf16.len() as u16).to_le_bytes());
    message.extend(utf16);
    message.extend(b"\r\n\r\n");
    message
}

fn smb_read(length: u32) -> Vec<u8> {
    let mut message = smb_header(8, 0);
    message.resize(80, 0);
    message[68..72].copy_from_slice(&length.to_le_bytes());
    message.extend(b"\r\n\r\n");
    message
}

/// Builds a capture: frames with strictly increasing capture timestamps.
struct Traffic {
    frames: Vec<RawPacket>,
    clock: f64,
    next_port: u16,
}

impl Traffic {
    fn new() -> Self {
        Self { frames: Vec::new(), clock: 1_700_000_000.0, next_port: 40_000 }
    }

    fn frame(&mut self, data: Vec<u8>) {
        self.frames.push(RawPacket { timestamp: self.clock, data });
        self.clock += 0.000_1;
    }

    fn advance(&mut self, seconds: f64) {
        self.clock += seconds;
    }

    fn client(&mut self, ip: &str) -> Endpoint {
        self.client_ip(ip.parse().unwrap())
    }

    fn client_ip(&mut self, ip: IpAddr) -> Endpoint {
        self.next_port = if self.next_port >= 60_000 { 40_000 } else { self.next_port + 1 };
        (ip, self.next_port)
    }

    fn tcp(&mut self, src: Endpoint, dst: Endpoint, kind: Tcp, payload: &[u8]) {
        self.frame(tcp_frame(src, dst, kind, payload));
    }

    fn udp(&mut self, src: Endpoint, dst: Endpoint, payload: &[u8]) {
        self.frame(udp_frame(src, dst, payload));
    }

    fn open(&mut self, client: Endpoint, server: Endpoint) {
        self.tcp(client, server, Tcp::Syn, b"");
        self.tcp(server, client, Tcp::SynAck, b"");
        self.tcp(client, server, Tcp::Ack, b"");
    }

    /// A short TCP session; empty messages are skipped.
    fn exchange(&mut self, client: Endpoint, server: Endpoint, request: &[u8], response: &[u8]) {
        self.open(client, server);
        if !request.is_empty() {
            self.tcp(client, server, Tcp::Data, request);
            self.tcp(server, client, Tcp::Ack, b"");
        }
        if !response.is_empty() {
            self.tcp(server, client, Tcp::Data, response);
            self.tcp(client, server, Tcp::Ack, b"");
        }
        self.tcp(client, server, Tcp::Fin, b"");
    }

    /// A TLS session with enough ciphertext in each direction for deep inspection.
    fn tls_session(&mut self, prng: &mut Prng, client: Endpoint, server: Endpoint, hello: &[u8]) {
        self.open(client, server);
        self.tcp(client, server, Tcp::Data, hello);
        for _ in 0..8 {
            let up = prng.bytes(1460);
            self.tcp(client, server, Tcp::Data, &up);
            let down = prng.bytes(1460);
            self.tcp(server, client, Tcp::Data, &down);
        }
        self.tcp(client, server, Tcp::Fin, b"");
    }
}

// ── Snapshot traffic ─────────────────────────────────────────────────────────

fn http_scene(t: &mut Traffic) {
    const REQUESTS: &[&[u8]] = &[
        BROWSER_GET,
        b"GET / HTTP/1.1\r\nHost: example.org\r\nUser-Agent: curl/8.4.0\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.org\r\nUser-Agent: python-requests/2.31\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.org\r\nUser-Agent: sqlmap/1.7\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.org\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.org\r\nUser-Agent: abc\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.org\r\nUser-Agent:\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: curl/8.4.0\r\n\r\n",
        b"get / http/1.1\r\nhost: example.org\r\n\r\n",
        b"GET / HTTP/1.1\r\nhost: www.microsoft.com\r\nuser-agent: Wget/1.21\r\n\r\n",
        b"GET / HTTP/1.1\r\nHOST: example.org\r\nUSER-AGENT: Wget/1.21\r\nCOOKIE: session=1\r\n\r\n",
        b"\tGET / HTTP/1.1\r\nHost: example.org\r\n\r\n",
        b"  POST /a HTTP/1.1\r\nHost: example.org\r\nUser-Agent: Go-http-client/1.1\r\n\r\nuser=bob&password=x",
        b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        b"TRACE / HTTP/1.1\r\n\r\n",
        b"PATCH / HTTP/1.1\r\n\r\n",
        b"OPTIONS * HTTP/1.1\r\n\r\n",
        b"DELETE /x HTTP/1.1\r\n\r\n",
        b"HEAD / HTTP/1.1\r\n\r\n",
        b"PUT /x HTTP/1.1\r\n\r\n",
        b"GET /login?password=hunter2 HTTP/1.1\r\nHost: example.org\r\nUser-Agent: Mozilla/5.0 (X11) Firefox\r\n\r\n",
        b"GET /?token=abc HTTP/1.1\r\nHost: example.org\r\nUser-Agent: Mozilla/5.0 (X11) Firefox\r\n\r\n",
        b"GET /?auth=abc HTTP/1.1\r\nHost: example.org\r\nUser-Agent: Mozilla/5.0 (X11) Firefox\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: accounts.google.com\r\nCookie: session=abc\r\nUser-Agent: Mozilla/5.0 (X11) Firefox\r\n\r\n",
        b"POST /login HTTP/1.1\r\nHost: example.org\r\nUser-Agent: Mozilla/5.0 (X11) Firefox\r\n\r\nlogin=bob",
        b"FOO /x?password=1 BAR\r\n\r\n",
        b"HELLO token=abc\r\n\r\n",
        b"not http at all\r\ncookie: auth=1\r\n\r\n",
        b"NOOP\r\n\r\nuser=alice",
        b"NOOP\r\n\r\nnothing here",
    ];
    const RESPONSES: &[&[u8]] = &[
        b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 301 Moved\r\nLocation: http://www.paypal.com/\r\n\r\n",
        b"HTTP/1.1 302 Found\r\nlocation: http://login.example.org/\r\n\r\n",
        b"HTTP/1.1 302 Found\r\nLOCATION: https://www.paypal.com/\r\n\r\n",
        b"HTTP/1.1 301 Moved\r\nLocation: http://example.org/\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nSet-Cookie: session_id=1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nset-cookie: token=1; Secure\r\n\r\n",
        b"HTTP/1.1\r\n\r\n",
    ];

    for server in [ep(UNKNOWN, 80), ep(CLOUDFLARE, 80), ep(LAN, 8080), ep("2001:db8::5", 80)] {
        let client_ip = if server.0.is_ipv6() { "fd00::10" } else { CLIENT };
        for request in REQUESTS {
            let client = t.client(client_ip);
            t.exchange(client, server, request, b"");
        }
        for response in RESPONSES {
            let client = t.client(client_ip);
            t.exchange(client, server, BROWSER_GET, response);
        }
    }
}

fn tls_scene(t: &mut Traffic, prng: &mut Prng) {
    let servers = [
        (UNKNOWN, 443, "evil.example"),
        (CLOUDFLARE, 443, "www.example.com"),
        (AWS, 443, "x.s3.amazonaws.com"),
        (GOOGLE, 443, "www.google.com"),
        (UNKNOWN, 8443, "a.example"),
        (UNKNOWN, 4444, "a.example"),
        (UNKNOWN, 993, ""),
        (MICROSOFT, 993, "outlook.office365.com"),
        (CLOUDFLARE, 853, "dns.example"),
    ];
    for (ip, port, sni) in servers {
        for padding in [0, 64] {
            for tls13 in [false, true] {
                let hello = client_hello(sni, padding, tls13, false);
                let client = t.client(CLIENT);
                t.tls_session(prng, client, ep(ip, port), &hello);
            }
        }
    }

    // SNI that only the manual parser can reach.
    let hello = client_hello("manual.example", 0, true, true);
    let client = t.client(CLIENT);
    t.tls_session(prng, client, ep(UNKNOWN, 443), &hello);

    // TLS over IPv6.
    let hello = client_hello("www.example.com", 0, true, false);
    let client = t.client("fd00::10");
    t.tls_session(prng, client, ep("2606:4700::1111", 443), &hello);
}

fn shell_scene(t: &mut Traffic) {
    const SESSIONS: &[&[u8]] = &[
        b"root@victim:~# whoami\nroot\nroot@victim:~# uname -a\nLinux victim 6.1\n\r\n\r\n",
        b"PS C:\\> ipconfig\r\nWindows IP Configuration\r\n\r\n",
        b"Microsoft Windows [Version] 10.0\r\nC:\\Windows\\System32>hostname\r\n\r\n",
        b"\x1b[?1049h\x1b[2Jtop - 10:00\r\n\r\n",
        b"\x1b[?1hsome terminal output\r\n\r\n",
        b"/bin/bash -i\r\nLast login: Mon\r\n\r\n",
        b"/bin/sh\r\n$ ls -la\r\n\r\n",
        b"net user admin /add\r\n\r\n",
        b"admin$ share listing\r\n\r\n",
        b"plain text with dir and set words\r\n\r\n",
        b"RTSP/1.0 200 OK\r\nServer: AirTunes/366.0\r\n\r\nwhoami",
        b"HTTPX\r\nContent-Type: video/mp4\r\n\r\nroot@ whoami",
        b"bplist00whoami root@\r\n\r\n",
        b"GET /whoami HTTP/1.1\r\nHost: root@example\r\n\r\n",
    ];
    for server in [ep(UNKNOWN, 4444), ep(MICROSOFT, 443), ep(LAN, 7000)] {
        for session in SESSIONS {
            let client = t.client(CLIENT);
            t.exchange(client, server, session, b"");
        }
    }
}

fn port_anomaly_scene(t: &mut Traffic, prng: &mut Prng) {
    let binary = prng.bytes(11_000);
    let mut ssh_like = b"SSH-2.0-x ".to_vec();
    ssh_like.extend(&binary);
    let messages: &[(&str, u16, &[u8])] = &[
        (UNKNOWN, 80, b"\x00\x01\x02 binary on web port\r\n\r\n"),
        (UNKNOWN, 80, &binary),
        (UNKNOWN, 443, b"hello in the clear on 443\r\n\r\n"),
        (CLOUDFLARE, 443, b"hello in the clear on 443\r\n\r\n"),
        (UNKNOWN, 22, b"SSH-2.0-OpenSSH_9.6\r\n\r\n"),
        (UNKNOWN, 22, &ssh_like),
        (UNKNOWN, 22, &binary),
        (UNKNOWN, 53, b"tcp dns text\r\n\r\n"),
        (UNKNOWN, 53, &binary),
    ];
    for (ip, port, message) in messages {
        let client = t.client(CLIENT);
        t.exchange(client, ep(ip, *port), message, b"");
    }
}

fn obfuscation_scene(t: &mut Traffic, prng: &mut Prng) {
    let mut png = vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    png.extend(b"aaaa".repeat(30));
    png.extend(b"\r\n\r\n");
    let client = t.client(CLIENT);
    t.exchange(client, ep(UNKNOWN, 9000), &png, b"");

    for server in [ep(UNKNOWN, 443), ep(CLOUDFLARE, 443), ep(UNKNOWN, 9443), ep(AWS, 443)] {
        for prefix in [&[][..], &[0x17, 0x03, 0x03][..], &[0x16, 0x03, 0x03, 0x00, 0x2b][..]] {
            let mut padded = prefix.to_vec();
            padded.extend(prng.bytes(4000));
            padded.extend([0u8; 64]);
            padded.extend(prng.bytes(8000));
            let client = t.client(CLIENT);
            t.exchange(client, server, &padded, b"");
        }
    }

    let strings = b"admin password list root secret ".repeat(400);
    for server in [ep(UNKNOWN, 443), ep(UNKNOWN, 993), ep(UNKNOWN, 22)] {
        let client = t.client(CLIENT);
        t.exchange(client, server, &strings, b"");
    }
}

fn smb_scene(t: &mut Traffic) {
    let server = ep(LAN, 445);
    let external = ep(UNKNOWN, 445);
    for name in ["docs\\password.txt", "report.docx", "backups\\wallet.kdbx"] {
        let create = smb_create(name);
        let mut netbios = vec![0, 0, 0, create.len() as u8];
        netbios.extend(&create);
        for target in [server, external] {
            let client = t.client(CLIENT);
            t.exchange(client, target, &create, b"");
            let client = t.client(CLIENT);
            t.exchange(client, target, &netbios, b"");
        }
    }

    let mut tree_connect = smb_header(3, 0);
    tree_connect.extend(b"\r\n\r\n");
    for _ in 0..12 {
        let client = t.client("192.168.1.30");
        t.exchange(client, server, &tree_connect, b"");
    }

    let client = t.client("192.168.1.31");
    t.exchange(client, server, &smb_read(200 * 1024 * 1024), b"");

    let mut response = smb_header(5, 1);
    response.extend(b"\r\n\r\n");
    let client = t.client("192.168.1.32");
    t.exchange(client, server, &response, b"");

    let client = t.client("192.168.1.33");
    t.exchange(client, server, b"not smb at all\r\n\r\n", b"");
}

fn reassembly_scene(t: &mut Traffic, prng: &mut Prng) {
    let server = ep(UNKNOWN, 8000);
    let request = b"GET /split HTTP/1.1\r\nHost: example.org\r\nUser-Agent: curl/8.4.0\r\n\r\n";
    for cut in 1..=3 {
        let (head, tail) = request.split_at(request.len() - cut);
        let client = t.client(CLIENT);
        t.open(client, server);
        t.tcp(client, server, Tcp::Data, head);
        t.tcp(client, server, Tcp::Data, tail);
        t.tcp(client, server, Tcp::Data, b"data after the analysis point");
        t.tcp(server, client, Tcp::Data, b"HTTP/1.1 200 OK\r\n\r\n");
        t.tcp(server, client, Tcp::Data, b"more data after the analysis point");
    }

    // No terminator: inspected once the buffer passes 10 KiB.
    let client = t.client(CLIENT);
    t.open(client, server);
    for _ in 0..12 {
        t.tcp(client, server, Tcp::Data, &b"x".repeat(1000));
        t.tcp(server, client, Tcp::Ack, b"");
    }

    // One oversized segment.
    let client = t.client(CLIENT);
    t.open(client, server);
    let large = prng.bytes(20_000);
    t.tcp(client, server, Tcp::Data, &large);

    // The server speaks first.
    let client = t.client(CLIENT);
    t.open(client, ep(UNKNOWN, 2222));
    t.tcp(ep(UNKNOWN, 2222), client, Tcp::Data, b"SSH-2.0-banner\r\n\r\n");
    t.tcp(client, ep(UNKNOWN, 2222), Tcp::Data, b"client text\r\n\r\n");
}

fn beacon_scene(t: &mut Traffic) {
    let cases = [(ep(UNKNOWN, 8088), false), (ep(GOOGLE, 443), false), (ep(UNKNOWN, 8443), true)];
    for (server, with_acks) in cases {
        let client = t.client(CLIENT);
        t.open(client, server);
        for _ in 0..8 {
            t.advance(5.0);
            t.tcp(client, server, Tcp::Data, b"ping");
            if with_acks {
                t.tcp(client, server, Tcp::Ack, b"");
                t.tcp(server, client, Tcp::Ack, b"");
            }
        }
        t.advance(5.0);
        t.tcp(client, server, Tcp::Data, b"done\r\n\r\n");
    }
}

fn exfil_scene(t: &mut Traffic, prng: &mut Prng) {
    let chunk = prng.bytes(65_495);
    let client = t.client(CLIENT);
    let server = ep(UNKNOWN, 9000);
    t.open(client, server);
    for _ in 0..802 {
        t.tcp(client, server, Tcp::Data, &chunk);
    }
    t.tcp(server, client, Tcp::Data, b"ok\r\n\r\n");
}

fn scan_scene(t: &mut Traffic) {
    let syn_scan = |t: &mut Traffic, src: &str, targets: &[String], ports: std::ops::Range<u16>| {
        for target in targets {
            for port in ports.clone() {
                let source = ep(src, 50_000);
                t.tcp(source, ep(target, port), Tcp::Syn, b"");
            }
        }
    };
    let external = |count: u8| -> Vec<String> { (1..=count).map(|i| format!("198.51.100.{i}")).collect() };
    let local = |count: u8| -> Vec<String> { (1..=count).map(|i| format!("192.168.2.{i}")).collect() };

    syn_scan(t, CLIENT, &[LAN.to_string()], 1000..1026);
    syn_scan(t, "192.168.1.11", &[UNKNOWN.to_string()], 2000..2026);
    let mut mixed = external(10);
    mixed.extend(local(10));
    syn_scan(t, "192.168.1.12", &mixed, 7777..7778);
    syn_scan(t, "192.168.1.13", &external(60), 7777..7778);
    syn_scan(t, "192.168.1.14", &local(14), 3000..3008);
    syn_scan(t, "192.168.1.15", &external(60), 443..444);
    let mut browsing = external(5);
    browsing.push(LAN.to_string());
    syn_scan(t, "192.168.1.16", &browsing, 443..444);
    syn_scan(t, "192.168.1.16", &external(1), 7777..7778);
    syn_scan(t, "198.51.100.200", &[CLIENT.to_string()], 3000..3026);
    syn_scan(t, "fd00::10", &["2001:db8::5".to_string()], 4000..4026);
    syn_scan(t, "2001:db8::9", &["fd00::10".to_string()], 4000..4026);

    // SYN-ACKs are not connection attempts.
    for port in 5000..5030 {
        t.tcp(ep(LAN, port), ep(CLIENT, 50_001), Tcp::SynAck, b"");
    }
}

fn udp_scene(t: &mut Traffic) {
    for port in 5000..5026 {
        t.udp(ep("192.168.1.17", 50_000), ep(UNKNOWN, port), b"probe");
    }
    for port in 6000..6026 {
        t.udp(ep("198.51.100.201", 50_000), ep(CLIENT, port), b"probe");
    }
    // Replies to our own traffic are not scans.
    for port in 7000..7026 {
        t.udp(ep(CLIENT, 51_000), ep(UNKNOWN, port), b"request");
        t.udp(ep(UNKNOWN, port), ep(CLIENT, 51_000), b"response");
    }
}

fn dns_scene(t: &mut Traffic, prng: &mut Prng) {
    let tunnel = format!("{}.{}.tunnel.example", prng.base62(55), prng.base62(55));
    let names = ["example.org", tunnel.as_str(), "a.microsoft.com", "www.google.com"];
    for resolver in [ep("8.8.8.8", 53), ep("9.9.9.9", 53), ep("192.168.1.1", 53), ep(UNKNOWN, 5300), ep(UNKNOWN, 53)] {
        for (id, name) in names.iter().enumerate() {
            let client = t.client(CLIENT);
            t.udp(client, resolver, &dns_query(id as u16, name));
            t.udp(resolver, client, &dns_response(id as u16, name, &[[198, 51, 100, 77]], &[], 300));
        }
    }

    // Names the detectors later find in the passive DNS cache.
    let resolver = ep("192.168.1.1", 53);
    let records: &[(&str, [u8; 4])] = &[
        ("app.evil.example", [203, 0, 113, 9]),
        ("mail.example.com", [203, 0, 113, 10]),
        ("cdn.amazonaws.com", [203, 0, 113, 11]),
    ];
    for (id, (name, addr)) in records.iter().enumerate() {
        let client = t.client(CLIENT);
        t.udp(resolver, client, &dns_response(id as u16, name, &[*addr], &[[0x20; 16]], 600));
        let client = t.client(CLIENT);
        let server = (IpAddr::V4(Ipv4Addr::from(*addr)), 80);
        t.exchange(client, server, b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8.4.0\r\n\r\n", b"");
        for port in 1000..1026 {
            t.tcp(ep("192.168.1.18", 50_000), (server.0, port), Tcp::Syn, b"");
        }
    }

    t.udp(ep(CLIENT, 51_001), ep("8.8.8.8", 53), b"short");
    t.udp(ep(CLIENT, 51_002), ep("8.8.8.8", 53), b"");
}

fn arp_scene(t: &mut Traffic) {
    let (first, second) = ([2, 0, 0, 0, 1, 1], [2, 0, 0, 0, 1, 2]);
    t.frame(arp_frame(0, 2, first, [192, 168, 1, 1], [192, 168, 1, 10]));
    t.frame(arp_frame(0, 1, first, [192, 168, 1, 50], [192, 168, 1, 1]));
    t.frame(arp_frame(0, 2, first, [192, 168, 1, 50], [192, 168, 1, 1]));
    t.frame(arp_frame(0, 2, second, [192, 168, 1, 50], [192, 168, 1, 1]));
    t.frame(arp_frame(0, 2, second, [192, 168, 1, 1], [192, 168, 1, 10]));
    t.frame(arp_frame(1, 1, first, [192, 168, 1, 60], [192, 168, 1, 1]));
    t.frame(arp_frame(2, 1, first, [192, 168, 1, 61], [192, 168, 1, 1]));
}

fn misc_scene(t: &mut Traffic) {
    // ICMP.
    let step = ip_step(CLIENT.parse().unwrap(), UNKNOWN.parse().unwrap()).icmpv4_echo_request(1, 1);
    let mut icmp = Vec::with_capacity(step.size(8));
    step.write(&mut icmp, &[0u8; 8]).unwrap();
    t.frame(icmp);

    // A frame the parser does not understand beyond Ethernet, and a truncated one.
    let mut lldp = vec![0xff; 12];
    lldp.extend([0x88, 0xcc, 1, 2, 3, 4]);
    t.frame(lldp);
    let mut truncated = tcp_frame(ep(CLIENT, 50_002), ep(UNKNOWN, 80), Tcp::Data, b"cut short");
    truncated.truncate(truncated.len() - 5);
    t.frame(truncated);

    // VLAN-tagged TCP.
    let (src, dst) = (ep(CLIENT, 50_003), ep(UNKNOWN, 80));
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.0, dst.0) else { unreachable!() };
    let single = PacketBuilder::ethernet2(MAC_A, MAC_B)
        .single_vlan(VlanId::try_new(10).unwrap())
        .ipv4(s.octets(), d.octets(), 64);
    let request = b"GET / HTTP/1.1\r\nHost: vlan.example\r\nUser-Agent: curl/8.4.0\r\n\r\n";
    t.frame(tcp_frame_on(single, src, dst, Tcp::Data, request));
    let double = PacketBuilder::ethernet2(MAC_A, MAC_B)
        .double_vlan(VlanId::try_new(10).unwrap(), VlanId::try_new(20).unwrap())
        .ipv4(s.octets(), d.octets(), 64);
    t.frame(tcp_frame_on(double, ep(CLIENT, 50_004), dst, Tcp::Data, request));
}

fn snapshot_traffic() -> Vec<RawPacket> {
    let mut t = Traffic::new();
    let mut prng = Prng(0x1234_5678_9abc_def1);
    http_scene(&mut t);
    tls_scene(&mut t, &mut prng);
    shell_scene(&mut t);
    port_anomaly_scene(&mut t, &mut prng);
    obfuscation_scene(&mut t, &mut prng);
    smb_scene(&mut t);
    reassembly_scene(&mut t, &mut prng);
    beacon_scene(&mut t);
    exfil_scene(&mut t, &mut prng);
    scan_scene(&mut t);
    udp_scene(&mut t);
    dns_scene(&mut t, &mut prng);
    arp_scene(&mut t);
    misc_scene(&mut t);
    t.frames
}

// ── Throughput traffic ───────────────────────────────────────────────────────

fn lan_ip(index: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 1, (index >> 8) as u8, index as u8))
}

/// An address from the benchmarking range, in no provider list.
fn wan_ip(index: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 18, (index >> 8) as u8, index as u8))
}

/// Long-lived flows: almost every packet is past the inspection point.
fn tcp_bulk() -> Traffic {
    let mut t = Traffic::new();
    let mut prng = Prng(1);
    let payload = prng.bytes(1460);
    for flow in 0..8 {
        let (client, server) = ((lan_ip(flow), 40_000), (wan_ip(flow), 443));
        t.open(client, server);
        for _ in 0..2500 {
            t.tcp(client, server, Tcp::Data, &payload);
            t.tcp(server, client, Tcp::Ack, b"");
        }
    }
    t
}

/// TLS sessions that each reach deep inspection in both directions.
fn tls_short() -> Traffic {
    let mut t = Traffic::new();
    let mut prng = Prng(2);
    let hello = client_hello("www.example.com", 64, true, false);
    for session in 0..3000 {
        let client = t.client_ip(lan_ip(session % 500));
        t.tls_session(&mut prng, client, (wan_ip(session), 443), &hello);
    }
    t
}

fn http_short() -> Traffic {
    let mut t = Traffic::new();
    for session in 0..20_000 {
        let client = t.client_ip(lan_ip(session % 500));
        t.exchange(client, (wan_ip(session), 80), BROWSER_GET, b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n");
    }
    t
}

/// Connection attempts that look like browsing: no alerts, only tracker work.
fn syn_browsing() -> Traffic {
    let mut t = Traffic::new();
    for host in 0..200 {
        for target in 0..40 {
            for port in [80, 443] {
                t.tcp((lan_ip(host), 50_000), (wan_ip(target), port), Tcp::Syn, b"");
            }
        }
    }
    t
}

fn syn_scan() -> Traffic {
    let mut t = Traffic::new();
    for target in 0..254 {
        for port in 1..=1000 {
            t.tcp((lan_ip(1), 50_000), (lan_ip(1000 + target), port), Tcp::Syn, b"");
        }
    }
    t
}

/// Spoofed sources: the UDP connection table sits at capacity.
fn udp_flood() -> Traffic {
    let mut t = Traffic::new();
    let mut prng = Prng(3);
    for _ in 0..300_000 {
        let source = IpAddr::V4(Ipv4Addr::from(prng.next() as u32 | 0x0100_0000));
        let source_port = prng.next() as u16;
        let destination_port = prng.next() as u16;
        t.udp((source, source_port), (lan_ip(1), destination_port), b"flood");
    }
    t
}

fn udp_quic() -> Traffic {
    let mut t = Traffic::new();
    let mut prng = Prng(4);
    let payload = prng.bytes(1200);
    for flow in 0..500 {
        let (client, server) = ((lan_ip(flow), 40_000), (wan_ip(flow), 443));
        for _ in 0..100 {
            t.udp(client, server, &payload);
            t.udp(server, client, &payload);
        }
    }
    t
}

fn dns_traffic() -> Traffic {
    let mut t = Traffic::new();
    let resolver = (lan_ip(1), 53);
    for id in 0..20_000u32 {
        let name = format!("host{}.example.org", id % 1000);
        let client = (lan_ip(2 + id % 200), 40_000 + (id % 1000) as u16);
        t.udp(client, resolver, &dns_query(id as u16, &name));
        let addr = [198, 18, (id >> 8) as u8, id as u8];
        t.udp(resolver, client, &dns_response(id as u16, &name, &[addr], &[], 300));
    }
    t
}

// ── Running the engine ───────────────────────────────────────────────────────

struct Outcome {
    alerts: Vec<MitreAlert>,
    elapsed: Duration,
    parse_errors: u64,
}

/// Feed `frames` through the engine `rounds` times. Each frame is cloned on
/// the feeding thread and freed on the engine thread, as in live capture.
fn run_engine(frames: &[RawPacket], rounds: usize) -> Outcome {
    let (pkt_tx, pkt_rx) = crossbeam_channel::bounded(10_000);
    let (alert_tx, mut alert_rx) = tokio::sync::mpsc::unbounded_channel();
    let stats = Arc::new(EngineStats::new());
    let flow_tracker: Arc<dyn FlowAccounting> = FlowTracker::shared();

    let collector = std::thread::spawn(move || {
        let mut alerts = Vec::new();
        while let Some(alert) = alert_rx.blocking_recv() {
            alerts.push(alert);
        }
        alerts
    });

    let engine_stats = stats.clone();
    let engine = std::thread::spawn(move || {
        engine::run(
            pkt_rx,
            alert_tx,
            Arc::new(AtomicBool::new(true)),
            engine_stats,
            1,
            DnsTracker::shared(),
            flow_tracker,
            AnomalyDetector::shared(10, None),
            Arc::new(ArpGuardian::new()),
        );
    });

    let start = Instant::now();
    for _ in 0..rounds {
        for frame in frames {
            pkt_tx.send(frame.clone()).unwrap();
        }
    }
    drop(pkt_tx);
    engine.join().unwrap();
    let elapsed = start.elapsed();

    Outcome {
        alerts: collector.join().unwrap(),
        elapsed,
        parse_errors: stats.parse_errors.load(Ordering::Relaxed),
    }
}

// ── A packet must never stop the engine ──────────────────────────────────────

/// One frame that completes a session, so deep inspection runs on `payload`.
fn inspected_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> RawPacket {
    RawPacket {
        timestamp: 1_700_000_000.0,
        data: tcp_frame(ep(CLIENT, src_port), ep(UNKNOWN, dst_port), Tcp::Data, payload),
    }
}

#[test]
fn short_smb_payload_does_not_stop_the_engine() {
    run_engine(&[inspected_frame(40_000, 445, b"\r\n\r\nX")], 1);
}

#[test]
fn odd_smb_name_length_does_not_stop_the_engine() {
    let mut create = smb_create("password.txt");
    create[70] = 3;
    run_engine(&[inspected_frame(40_000, 445, &create)], 1);
}

#[test]
fn multibyte_char_across_byte_16_does_not_stop_the_engine() {
    run_engine(&[inspected_frame(40_000, 4444, b"AAAAAAAAAAAAAAA\xFF\r\n\r\n")], 1);
    run_engine(&[inspected_frame(40_000, 4444, "AAAAAAAAAAAAAAAЯ text\r\n\r\n".as_bytes())], 1);
}

#[test]
fn client_hello_without_handshake_header_does_not_stop_the_engine() {
    run_engine(&[inspected_frame(40_000, 443, b"\x16\x03\x01\x00\x01\x01\r\n\r\n")], 1);
}

#[test]
fn random_payloads_do_not_stop_the_engine() {
    let mut prng = Prng(0xfeed_beef_cafe_f00d);
    let mut frames = Vec::new();
    let mut src_port = 1024u16;
    for round in 0..4000 {
        let len = (prng.next() >> 40) as usize % 96;
        let mut payload = match round % 6 {
            0 => prng.bytes(len),
            // TLS record with a short or inconsistent handshake.
            1 => {
                let mut record = vec![0x16, 0x03, 0x01, 0x00, (len % 8) as u8, 0x01];
                record.extend(prng.bytes(len));
                record
            }
            // SMB with attacker-chosen name offset and length.
            2 => {
                let mut smb = smb_header(5, 0);
                smb.resize(72 + len, 0);
                let tail = prng.bytes(8);
                smb[68..72].copy_from_slice(&tail[..4]);
                smb[71] = 0;
                smb[69] = 0;
                smb
            }
            3 => {
                let mut smb = vec![0, 0, 0, 0];
                smb.extend(b"\xFESMB");
                smb.truncate(4 + len % 5);
                smb
            }
            // Multibyte text at every alignment.
            4 => {
                let mut text = "A".repeat(len % 32).into_bytes();
                text.extend("ЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯ".as_bytes());
                text.extend(b"ascii tail so the payload is not binary, ascii tail");
                text
            }
            _ => {
                let mut text = b"GET ".to_vec();
                text.extend(prng.bytes(len));
                text
            }
        };
        payload.extend(b"\r\n\r\n");

        for dst_port in [445, 443, 80, 4444] {
            src_port = if src_port == u16::MAX { 1024 } else { src_port + 1 };
            frames.push(inspected_frame(src_port, dst_port, &payload));
        }
        let client = ep(CLIENT, src_port);
        frames.push(RawPacket { timestamp: 1_700_000_000.0, data: udp_frame(client, ep(UNKNOWN, 53), &payload) });
        frames.push(RawPacket { timestamp: 1_700_000_000.0, data: udp_frame(ep(UNKNOWN, 53), client, &payload) });
    }
    run_engine(&frames, 1);
}

// ── Fragmented traffic is analyzed ───────────────────────────────────────────

const ETHERNET_AND_IPV4: usize = 14 + 20;

/// The IP payload (transport header included) of a frame built without options.
fn ip_payload(frame: Vec<u8>) -> Vec<u8> {
    frame[ETHERNET_AND_IPV4..].to_vec()
}

fn ipv4_fragment(src: [u8; 4], dst: [u8; 4], id: u16, protocol: u8, offset: usize, more: bool, payload: &[u8]) -> RawPacket {
    let mut frame = Vec::new();
    frame.extend(MAC_A);
    frame.extend(MAC_B);
    frame.extend([0x08, 0x00, 0x45, 0x00]);
    frame.extend(((20 + payload.len()) as u16).to_be_bytes());
    frame.extend(id.to_be_bytes());
    frame.extend((u16::from(more) << 13 | (offset / 8) as u16).to_be_bytes());
    frame.extend([64, protocol, 0, 0]);
    frame.extend(src);
    frame.extend(dst);
    frame.extend(payload);
    RawPacket { timestamp: 1_700_000_000.0, data: frame }
}

/// Split an IP payload into fragments carrying `chunk` bytes each.
fn fragmented(src: [u8; 4], dst: [u8; 4], id: u16, protocol: u8, datagram: &[u8], chunk: usize) -> Vec<RawPacket> {
    assert_eq!(chunk % 8, 0);
    let pieces: Vec<&[u8]> = datagram.chunks(chunk).collect();
    pieces
        .iter()
        .enumerate()
        .map(|(i, piece)| ipv4_fragment(src, dst, id, protocol, i * chunk, i + 1 < pieces.len(), piece))
        .collect()
}

fn normalized(mut alerts: Vec<MitreAlert>) -> Vec<String> {
    for alert in &mut alerts {
        alert.timestamp = DateTime::UNIX_EPOCH;
        // Flow features are tracked per captured packet, so they differ.
        alert.metadata.retain(|key, _| !key.starts_with("flow_"));
    }
    alerts.iter().map(|alert| serde_json::to_string(alert).unwrap()).collect()
}

#[test]
fn fragmented_session_raises_the_same_alerts_as_a_whole_one() {
    let (src, dst) = ([192, 168, 1, 10], [203, 0, 113, 5]);
    let (client, server) = (ep(CLIENT, 40_000), ep(UNKNOWN, 80));
    let request = b"GET / HTTP/1.1\r\nHost: example.org\r\nUser-Agent: curl/8.4.0\r\n\r\n";

    let frame = tcp_frame(client, server, Tcp::Data, request);
    let whole = run_engine(&[RawPacket { timestamp: 1_700_000_000.0, data: frame.clone() }], 1);
    assert!(!whole.alerts.is_empty());

    let frames = fragmented(src, dst, 7, 6, &ip_payload(frame), 24);
    assert!(frames.len() > 1);
    let reassembled = run_engine(&frames, 1);

    assert_eq!(normalized(whole.alerts), normalized(reassembled.alerts));
}

#[test]
fn fragmented_syn_scan_is_detected() {
    let (src, dst) = ([192, 168, 1, 10], [192, 168, 1, 20]);
    let mut frames = Vec::new();
    for (id, port) in (1000..1026).enumerate() {
        let syn = tcp_frame(ep(CLIENT, 50_000), ep(LAN, port), Tcp::Syn, b"");
        // As `nmap -f`: the TCP header itself is split.
        frames.extend(fragmented(src, dst, id as u16, 6, &ip_payload(syn), 8));
    }
    let outcome = run_engine(&frames, 1);
    assert!(outcome.alerts.iter().any(|alert| alert.technique_id == "T1046"));
}

#[test]
fn fragmented_dns_is_analyzed() {
    let mut prng = Prng(9);
    let name = format!("{}.{}.tunnel.example", prng.base62(55), prng.base62(55));
    let query = udp_frame(ep(CLIENT, 40_000), ep(UNKNOWN, 53), &dns_query(1, &name));
    let frames = fragmented([192, 168, 1, 10], [203, 0, 113, 5], 9, 17, &ip_payload(query), 32);
    let outcome = run_engine(&frames, 1);
    assert!(outcome.alerts.iter().any(|alert| alert.technique_id == "T1071.004"));
}

#[test]
fn hostile_fragments_do_not_stop_the_engine() {
    let (src, dst) = ([192, 168, 1, 10], [203, 0, 113, 5]);
    let mut frames = vec![
        // Past the IP limit, with duplicates adding up to the claimed end.
        ipv4_fragment(src, dst, 1, 6, 65_528, false, &[0; 16]),
        ipv4_fragment(src, dst, 1, 6, 0, true, &[0; 65_480]),
        ipv4_fragment(src, dst, 1, 6, 0, true, &[0; 64]),
        // Reassembles to something too short for a TCP header.
        ipv4_fragment(src, dst, 2, 6, 0, true, &[0; 8]),
        ipv4_fragment(src, dst, 2, 6, 8, false, &[0; 4]),
        // Unknown protocol.
        ipv4_fragment(src, dst, 3, 47, 0, true, &[0; 8]),
        ipv4_fragment(src, dst, 3, 47, 8, false, &[0; 8]),
    ];
    let mut prng = Prng(11);
    for id in 100..2000 {
        let offset = (prng.next() >> 20) as usize % 8192 * 8;
        let len = (prng.next() >> 20) as usize % 2000;
        let payload = prng.bytes(len);
        frames.push(ipv4_fragment(src, dst, id % 8, 6, offset, prng.next() & 1 == 0, &payload));
    }
    run_engine(&frames, 1);
}

#[test]
#[ignore = "benchmark, run with --release --ignored --nocapture"]
fn engine_throughput() {
    let scenarios: [(&str, fn() -> Traffic, usize); 8] = [
        ("tcp_bulk", tcp_bulk, 5),
        ("tls_short", tls_short, 1),
        ("http_short", http_short, 1),
        ("syn_browsing", syn_browsing, 20),
        ("syn_scan", syn_scan, 1),
        ("udp_flood", udp_flood, 1),
        ("udp_quic", udp_quic, 3),
        ("dns", dns_traffic, 5),
    ];

    println!("{:<14}{:>12}{:>10}{:>10}", "scenario", "pps (best)", "frames", "alerts");
    for (name, build, rounds) in scenarios {
        let frames = build().frames;
        let mut best = Duration::MAX;
        let mut alerts = 0;
        for _ in 0..3 {
            let outcome = run_engine(&frames, rounds);
            best = best.min(outcome.elapsed);
            alerts = outcome.alerts.len();
        }
        let total = frames.len() * rounds;
        println!("{:<14}{:>12.0}{:>10}{:>10}", name, total as f64 / best.as_secs_f64(), total, alerts);
    }
}

#[test]
#[ignore = "writes an alert snapshot to $ALERT_SNAPSHOT"]
fn alert_snapshot() {
    let frames = snapshot_traffic();
    let outcome = run_engine(&frames, 1);

    // Time-window logic must not depend on how fast this build runs.
    assert!(outcome.elapsed < Duration::from_secs(4), "too slow to be deterministic: {:?}", outcome.elapsed);

    let mut lines = String::new();
    let mut per_trigger: BTreeMap<(String, String), usize> = BTreeMap::new();
    for mut alert in outcome.alerts {
        *per_trigger.entry((alert.technique_id.clone(), alert.trigger.clone())).or_default() += 1;
        alert.timestamp = DateTime::UNIX_EPOCH;
        lines.push_str(&serde_json::to_string(&alert).unwrap());
        lines.push('\n');
    }

    println!("frames: {}, parse errors: {}, elapsed: {:?}", frames.len(), outcome.parse_errors, outcome.elapsed);
    for ((technique, trigger), count) in &per_trigger {
        println!("{technique:<12}{trigger:<24}{count:>6}");
    }

    if let Ok(path) = std::env::var("ALERT_SNAPSHOT") {
        std::fs::write(&path, lines).unwrap();
        println!("written to {path}");
    }
}
