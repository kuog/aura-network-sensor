# Build & Run (Linux/macOS)

## Linux (pnet / AF_PACKET)

```bash
cargo build --release
sudo ./target/release/mcp-network-sensor -i <interface>
```

## macOS (pcap)

```bash
cargo build --release
sudo ./target/release/mcp-network-sensor -i <interface>
```

## Offline PCAP (both)

```bash
cargo run --release -- -f ./captures/example.pcap
```
