#!/usr/bin/env bash
# Collect the headers the BPF programs include — libbpf's <bpf/*.h> and
# vmlinux.h — into target/bpf-include, for editors (IntelliSense, clangd) and
# for running clang on src/bpf/*.bpf.c by hand. `cargo build --features ebpf`
# does not need this: libbpf-cargo provides the same headers on its own.
#
# Usage: scripts/bpf-headers.sh [aarch64|x86_64]   (default: this machine's arch)
set -euo pipefail
cd "$(dirname "$0")/.."

arch=${1:-$(uname -m)}
case "$arch" in
  arm64) arch=aarch64 ;;
  amd64) arch=x86_64 ;;
esac

# Both crates come from Cargo.lock; cargo metadata downloads them if needed.
read -r libbpf_dir vmlinux_dir < <(
  cargo metadata --format-version 1 --features ebpf | python3 -c '
import json, os, sys
dirs = {p["name"]: os.path.dirname(p["manifest_path"]) for p in json.load(sys.stdin)["packages"]}
print(dirs["libbpf-sys"], dirs["vmlinux"])'
)

out=target/bpf-include
rm -rf "$out"
mkdir -p "$out/bpf"
for h in bpf_helpers.h bpf_helper_defs.h bpf_tracing.h bpf_core_read.h bpf_endian.h; do
  cp "$libbpf_dir/libbpf/src/$h" "$out/bpf/"
done
cp "$vmlinux_dir/include/$arch/vmlinux.h" "$out/vmlinux.h"

echo "BPF headers for $arch in $out"
