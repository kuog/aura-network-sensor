use tls_parser::{
    parse_tls_plaintext, parse_tls_extensions, TlsMessage, TlsMessageHandshake, TlsExtension, TlsExtensionType
};
use md5;

pub fn calculate_ja3(data: &[u8]) -> Option<String> {
    // Only a handshake record (content type 22) can hold a Client Hello.
    if data.first() != Some(&0x16) {
        return None;
    }

    // Parse the TLS record
    // We only care about the first record which should be the Client Hello
    if let Ok((_, record)) = parse_tls_plaintext(data) {
        for msg in record.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) = msg {
                // 1. TLS Version
                // JA3 uses the decimal value of the version field in the ClientHello
                let version = u16::from(client_hello.version);

                // 2. Ciphers
                // Filter out GREASE values
                let ciphers: Vec<String> = client_hello.ciphers.iter()
                    .map(|c| u16::from(*c))
                    .filter(|&c| !is_grease(c))
                    .map(|c| c.to_string())
                    .collect();
                
                // 3. Extensions
                // JA3 uses the extension type value.
                let mut extensions: Vec<u16> = Vec::new();
                let mut elliptic_curves: Vec<u16> = Vec::new();
                let mut ec_point_formats: Vec<u8> = Vec::new();

                if let Some(ext_bytes) = client_hello.ext {
                    if let Ok((_, exts)) = parse_tls_extensions(ext_bytes) {
                        for ext in exts {
                            let ext_type = u16::from(TlsExtensionType::from(&ext));
                            if !is_grease(ext_type) {
                                extensions.push(ext_type);
                            }

                            // 4. Elliptic Curves (Supported Groups)
                            // Note: In newer tls-parser versions, EllipticCurves is renamed to SupportedGroups
                            // We try EllipticCurves first as it is the common name in older versions
                            if let TlsExtension::EllipticCurves(curves) = &ext {
                                 for curve in curves.iter() {
                                     let curve_id = curve.0;
                                     if !is_grease(curve_id) {
                                         elliptic_curves.push(curve_id);
                                     }
                                 }
                            }
                            
                            // 5. Elliptic Curve Point Formats
                            if let TlsExtension::EcPointFormats(formats) = &ext {
                                for format in formats.iter() {
                                    ec_point_formats.push(*format);
                                }
                            }
                        }
                    }
                }

                let ja3_string = format!(
                    "{},{},{},{},{}",
                    version,
                    ciphers.join("-"),
                    extensions.iter().map(|e| e.to_string()).collect::<Vec<String>>().join("-"),
                    elliptic_curves.iter().map(|c| c.to_string()).collect::<Vec<String>>().join("-"),
                    ec_point_formats.iter().map(|f| f.to_string()).collect::<Vec<String>>().join("-")
                );

                let digest = md5::compute(ja3_string.as_bytes());
                return Some(format!("{:x}", digest));
            }
        }
    }
    None
}

fn is_grease(val: u16) -> bool {
    // GREASE values are of the form 0x?a?a
    // (val & 0x0f0f) == 0x0a0a
    match val {
        0x0a0a | 0x1a1a | 0x2a2a | 0x3a3a | 0x4a4a | 0x5a5a |
        0x6a6a | 0x7a7a | 0x8a8a | 0x9a9a | 0xaaaa | 0xbaba |
        0xcaca | 0xdada | 0xeaea | 0xfafa => true,
        _ => false,
    }
}
