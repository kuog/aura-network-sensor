# Build & Run (Linux/macOS)

Both platforms capture through libpcap (Linux: PACKET_MMAP ring, macOS: BPF device).

## macOS

```bash
cargo build --release
sudo ./target/release/mcp-network-sensor -i en0
```

## Linux

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

## Testing on a Mac with OrbStack

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

## Editing and compiling BPF code

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
