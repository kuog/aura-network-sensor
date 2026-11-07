//! eBPF sensing (Linux, `--features ebpf`).
//!
//! - [`procmon`]: attributes TCP connections to processes and detects TCP
//!   sockets redirected onto stdin/stdout (reverse shells).
//! - [`flow`]: accounts every frame per flow inside the kernel and passes a
//!   flow's payload up to userspace only while it is inside the DPI window.

pub mod flow;
pub mod procmon;

#[allow(clippy::all, dead_code, non_camel_case_types, non_snake_case, unused_imports)]
mod skel {
    pub mod procmon {
        include!(concat!(env!("OUT_DIR"), "/procmon.skel.rs"));
    }
    pub mod flowfilter {
        include!(concat!(env!("OUT_DIR"), "/flowfilter.skel.rs"));
    }
}

use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;

/// CO-RE relocation needs the running kernel's BTF.
pub fn kernel_btf_available() -> bool {
    std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
}

/// `(dev, inode)` of a namespace link such as `/proc/self/ns/pid`.
fn namespace_id(path: &str) -> std::io::Result<(u64, u64)> {
    let md = std::fs::metadata(path)?;
    Ok((md.dev(), md.ino()))
}

fn clock_ns(clock: libc::clockid_t) -> i128 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid clock id and out-pointer.
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

/// Current CLOCK_MONOTONIC time, the clock behind `bpf_ktime_get_ns()`.
fn monotonic_now_ns() -> u64 {
    clock_ns(libc::CLOCK_MONOTONIC) as u64
}

/// Convert a `bpf_ktime_get_ns()` value to epoch seconds.
fn monotonic_ns_to_epoch(ns: u64) -> f64 {
    let offset = clock_ns(libc::CLOCK_REALTIME) - clock_ns(libc::CLOCK_MONOTONIC);
    (ns as i128 + offset) as f64 / 1e9
}

/// An address from BPF data: IPv4 in the first 4 bytes, or full IPv6.
fn ip_from_bytes(is_v4: bool, bytes: &[u8; 16]) -> IpAddr {
    if is_v4 {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        IpAddr::V6(Ipv6Addr::from(*bytes))
    }
}

/// Raw bytes of a skeleton type, e.g. a map key.
fn as_bytes<T: Copy>(value: &T) -> &[u8] {
    // SAFETY: skeleton types are #[repr(C)] plain data; the BPF key/value
    // structs spell out their padding, so every byte is initialized.
    unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) }
}

/// Read a skeleton type from raw BPF bytes (map value, ring buffer record).
fn from_bytes<T: Copy>(bytes: &[u8]) -> Option<T> {
    // SAFETY: length checked; skeleton types are plain data, valid for any bits.
    (bytes.len() >= size_of::<T>()).then(|| unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}
