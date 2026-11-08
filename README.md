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

## Build and run

Building needs Rust with edition 2024 support. Both platforms capture through
libpcap (Linux: PACKET_MMAP ring, macOS: BPF device).

### macOS

```bash
cargo build --release
sudo ./target/release/mcp-network-sensor -i en0
```

### Linux

Build dependencies (Debian/Ubuntu):

```bash
sudo apt install -y build-essential pkg-config libpcap-dev
```

```bash
cargo build --release
sudo ./target/release/mcp-network-sensor -i eth0
```

### eBPF sensing (`--features ebpf`, Linux only)

Adds three things on top of the pcap pipeline:

- **Process attribution** — alerts on TCP connections get `proc_pid`, `proc_ppid`,
  `proc_uid`, `proc_comm`, `proc_exe`, `proc_cmdline` (kprobes on `tcp_connect`
  and `inet_csk_accept`).
- **Reverse-shell detection** — a TCP socket dup'ed onto stdin/stdout/stderr
  (`dup2`/`dup3`) raises T1059, regardless of what the traffic contains.
- **In-kernel flow accounting** — an eBPF socket filter on the capture socket
  counts every frame per flow; userspace only receives the first 16 KiB of each
  flow direction (the DPI window), plus DNS, ARP and TCP SYNs. Flow features
  and T1041 byte totals stay exact even when userspace cannot keep up.

Requirements: kernel 5.8+ with BTF (`/sys/kernel/btf/vmlinux`), run as root
(or with CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN and CAP_NET_RAW). Extra build
dependencies: clang, libelf and zlib.

```bash
sudo apt install -y clang llvm libelf-dev zlib1g-dev
cargo build --release --features ebpf
sudo ./target/release/mcp-network-sensor -i eth0              # eBPF on
sudo ./target/release/mcp-network-sensor -i eth0 --no-ebpf    # pcap only (A/B)
```

Without BTF, or if the programs fail to load, the sensor logs a warning and
runs without eBPF. Switching flow accounting between kernel and userspace
changes the anomaly features slightly: delete `anomaly_model.bin` so the
model retrains.

### Options

| Option | Description |
| --- | --- |
| `-i <interface>` | Interface to capture from (required) |
| `-l`, `--list` | List available interfaces |
| `-d <path>` | SQLite database path (default: `alerts.db`) |
| `--learning-time <minutes>` | Length of the learning phase (default: 10) |
| `--ocsf-file <path>` | Also append alerts as OCSF Detection Finding JSON lines |
| `--syslog <target>` | Also send alerts to `local`, `udp://host[:port]` or `tcp://host[:port]` |
| `--no-ebpf` | Disable eBPF sensing (only in builds with `--features ebpf`) |

## Alert output

Every alert is printed to the console and stored in SQLite (`-d`, default
`alerts.db`). The console shows a header line, the detection's explanation and
a few key details, colored by severity:

```text
15:57:52 LOW      T1046 Network Service Discovery [port_scan] tcp 192.168.139.161:59136 → 192.168.139.1:41 conf 30
         Vertical Scan: 21 ports on 192.168.139.1 (scanner_ip=192.168.139.161 unique_ports_count=21 unique_targets_count=1)
         proc_comm=nmap proc_pid=11137 proc_exe=/usr/bin/nmap
```

Two optional exports run alongside, on their own thread:

- `--ocsf-file <path>` appends each alert to the file as an
  [OCSF](https://schema.ocsf.io) Detection Finding (class 2004, schema 1.9.0),
  one JSON object per line, for SIEM and data-lake pipelines (Vector, Fluent
  Bit, Filebeat). ATT&CK technique and tactic are in `finding_info.attacks`;
  the connection and the owning process are in `evidences`; any other metadata
  is in `unmapped`.
- `--syslog <target>` sends each alert as one text line (the console content
  without color), facility local0, severity taken from the alert:
  - `local`: the local syslog socket (`/dev/log`; on macOS `/var/run/syslog`);
  - `udp://host[:port]` or `tcp://host[:port]`: RFC 5424 to a remote
    collector (TCP uses octet counting), port 514 by default.

Debug-level alerts (suppressed by reputation or by the anomaly model) are only
printed and stored, not exported.

```bash
sudo ./target/release/mcp-network-sensor -i eth0 --ocsf-file /var/log/mcp-sensor/alerts.ocsf.jsonl --syslog local
```

```bash
journalctl -t mcp-network-sensor
```

## Data handling

The sensor writes `alerts.db`, `alerts_features.db`, `suppressed.log` and
`anomaly_model.bin` to the working directory. These files describe real
traffic, so keep them out of version control and shared locations.

To enrich alerts, the sensor sends reverse DNS (PTR) queries for observed IP
addresses to Google Public DNS.

## Development

### Testing on a Mac with OrbStack

OrbStack Linux machines share one kernel with BTF, kprobes and TCX, so the
eBPF build runs there. Each machine has its own pid and network namespaces;
the sensor only reports sockets of its own network namespace.

```bash
orb create ubuntu mcp-sensor
orb -m mcp-sensor bash -lc 'sudo apt install -y build-essential clang llvm libelf-dev zlib1g-dev pkg-config libpcap-dev'
orb -m mcp-sensor bash -lc 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
```

Build from the same checkout: run these from the repository root on the Mac
(`orb` keeps the working directory, macOS paths are mounted in the machine).
Use a separate target directory so the Linux and macOS builds don't share
`target/`:

```bash
orb -m mcp-sensor bash -lc 'CARGO_TARGET_DIR=$HOME/.cache/mcp-sensor-target cargo build --release --features ebpf'
```

```bash
orb -m mcp-sensor bash -lc 'sudo $HOME/.cache/mcp-sensor-target/release/mcp-network-sensor -i eth0'
```

### Editing and compiling BPF code

`cargo build --features ebpf` hands clang the libbpf headers and `vmlinux.h`
itself. For editors and for running clang by hand, collect the same headers
into `target/bpf-include` (re-run after updating libbpf-rs or vmlinux):

```bash
scripts/bpf-headers.sh            # host arch; or: scripts/bpf-headers.sh x86_64
```

VSCode (C/C++ extension) picks them up through `.vscode/c_cpp_properties.json`;
reload the window after the first run. The config targets arm64 — on x86_64,
run the script with `x86_64` and change `__TARGET_ARCH_arm64` to
`__TARGET_ARCH_x86`.

Apple clang has no BPF backend, so compile a single program by hand in the
Linux machine (or with LLVM from Homebrew):

```bash
orb -m mcp-sensor bash -lc 'clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -fno-stack-protector -Wno-missing-declarations -I target/bpf-include -c src/bpf/flowfilter.bpf.c -o /tmp/flowfilter.bpf.o'
```

## License

MIT, see [LICENSE](LICENSE). The eBPF programs in `src/bpf/` are licensed under
LGPL-2.1 or BSD-2-Clause, as stated in their headers.
