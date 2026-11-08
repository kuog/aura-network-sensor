# MCP Network Sensor

A passive network detection sensor written in Rust. It watches live traffic on
an interface, reports suspicious activity as alerts mapped to MITRE ATT&CK
techniques, and learns what is normal for the network to reduce routine noise.

Only run it on networks and hosts you are authorized to monitor.

## Features

- **Live capture** through libpcap on Linux and macOS, with IP defragmentation
  and TCP reassembly.
- **Protocol detections** for the techniques listed below.
- **Anomaly-based suppression.** An Isolation Forest model trains on your
  traffic during a learning phase (10 minutes by default), then lowers the
  severity of alerts on flows it considers normal.
- **eBPF sensing** (optional, Linux only): process attribution for TCP
  connections, reverse-shell detection when a socket is duplicated onto
  stdin, stdout or stderr, and in-kernel flow accounting.
- **Exports:** SQLite by default, plus optional OCSF JSON lines and syslog
  (local, UDP or TCP).

## Detection coverage

| ATT&CK | Looks for |
| --- | --- |
| T1001 Data Obfuscation | Obfuscated payloads |
| T1011, T1041 Exfiltration | Beaconing and large outbound transfers |
| T1039 Data from Network Shared Drive | Access to sensitive files over SMB |
| T1046 Network Service Discovery | Port scans |
| T1059 Command and Scripting Interpreter | Reverse shells and PowerShell activity |
| T1071 Application Layer Protocol | Known C2 frameworks, scripted clients, suspicious DNS, protocol mismatches |
| T1105 Ingress Tool Transfer | Download tools identified by User-Agent |
| T1505 Server Software Component | SQL injection tools |
| T1557 Adversary-in-the-Middle | ARP spoofing |
| T1562.001 Impair Defenses | SSL stripping |
| T1567.002 Exfiltration to Cloud Storage | Cloud storage command-line tools |
| T1571 Non-Standard Port | Protocols on unexpected ports |
| T1573 Encrypted Channel | TLS analysis using JA3 fingerprints |
| T1595 Active Scanning | Web scanners and fuzzers |

## Quick start

Building needs Rust with edition 2024 support and libpcap. See
[docs/build.md](docs/build.md) for platform dependencies, the eBPF build and
export details.

```bash
cargo build --release
sudo ./target/release/mcp-network-sensor -l
sudo ./target/release/mcp-network-sensor -i eth0
```

| Option | Description |
| --- | --- |
| `-i <interface>` | Interface to capture from (required) |
| `-l`, `--list` | List available interfaces |
| `-d <path>` | SQLite database path (default: `alerts.db`) |
| `--learning-time <minutes>` | Length of the learning phase (default: 10) |
| `--ocsf-file <path>` | Also append alerts as OCSF Detection Finding JSON lines |
| `--syslog <target>` | Also send alerts to `local`, `udp://host[:port]` or `tcp://host[:port]` |
| `--no-ebpf` | Disable eBPF sensing (only in builds with `--features ebpf`) |

## Data handling

The sensor writes `alerts.db`, `alerts_features.db`, `suppressed.log` and
`anomaly_model.bin` to the working directory. These files describe real
traffic, so keep them out of version control and shared locations.

To enrich alerts, the sensor sends reverse DNS (PTR) queries for observed IP
addresses to Google Public DNS.

## License

MIT, see [LICENSE](LICENSE). The eBPF programs in `src/bpf/` are licensed under
LGPL-2.1 or BSD-2-Clause, as stated in their headers.
