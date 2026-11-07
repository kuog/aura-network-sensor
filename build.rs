//! Build script: compiles the BPF programs and generates their Rust
//! skeletons when the `ebpf` feature is enabled (Linux only).

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(feature = "ebpf")]
    ebpf::build();
}

#[cfg(feature = "ebpf")]
mod ebpf {
    use std::env;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    use libbpf_cargo::SkeletonBuilder;

    /// BPF programs in `src/bpf/<name>.bpf.c`, each producing `<name>.skel.rs`.
    const PROGRAMS: &[&str] = &["procmon", "flowfilter"];

    pub fn build() {
        if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
            panic!("the `ebpf` feature is Linux-only; build without it on this platform");
        }

        let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
        let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH is set by cargo");
        let vmlinux_dir = vmlinux::include_path_root().join(&arch);

        for name in PROGRAMS {
            let src = format!("src/bpf/{name}.bpf.c");
            SkeletonBuilder::new()
                .source(&src)
                .clang_args([
                    OsStr::new("-I"),
                    vmlinux_dir.as_os_str(),
                    // vmlinux.h itself trips this one; it is harmless.
                    OsStr::new("-Wno-missing-declarations"),
                ])
                .build_and_generate(out_dir.join(format!("{name}.skel.rs")))
                .unwrap_or_else(|e| panic!("failed to build {src}: {e:#}"));
            println!("cargo:rerun-if-changed={src}");
        }
        println!("cargo:rerun-if-changed=src/bpf/common.h");
    }
}
