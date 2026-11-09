pub mod dns;
pub mod tls;
pub mod http;
pub mod port_anomaly;
pub mod scan;
pub mod arp;
pub mod obfuscation;
pub mod shell;
pub mod smb;
pub mod stripping;

/// Whether `line` starts with `name`, compared ASCII case-insensitively.
/// `name` is the header name with its colon.
pub(crate) fn is_header(line: &str, name: &str) -> bool {
    line.as_bytes()
        .get(..name.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(name.as_bytes()))
}
