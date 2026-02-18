use std::collections::HashMap;
use std::net::IpAddr;

struct FragBuffer {
    data: Vec<u8>,
    expected_size: usize,
    received_size: usize,
}

/// Handles IPv4 fragmentation reassembly.
pub struct Defragmenter {
    // Key: (Source IP, Destination IP, IP ID)
    cache: HashMap<(IpAddr, IpAddr, u16), FragBuffer>,
}

impl Default for Defragmenter {
    fn default() -> Self {
        Self::new()
    }
}

impl Defragmenter {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    pub fn process(
        &mut self,
        ip_hdr: &etherparse::Ipv4Header,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        // Return immediately if the packet is not fragmented
        if !ip_hdr.more_fragments && ip_hdr.fragment_offset.value() == 0 {
            return Some(payload.to_vec());
        }

        let key = (
            IpAddr::V4(ip_hdr.source.into()),
            IpAddr::V4(ip_hdr.destination.into()),
            ip_hdr.identification,
        );
        let offset = ip_hdr.fragment_offset.byte_offset() as usize;

        let buf = self.cache.entry(key).or_insert(FragBuffer {
            data: vec![0; 65535], // Max IP packet size
            expected_size: 0,
            received_size: 0,
        });

        // Copy fragment into the buffer at the correct offset
        let end = offset + payload.len();
        if end <= 65535 {
            buf.data[offset..end].copy_from_slice(payload);
            buf.received_size += payload.len();
        }

        // If this is the last fragment, we know the expected size
        if !ip_hdr.more_fragments {
            buf.expected_size = end;
        }

        // If all bytes received, return the full packet
        if buf.expected_size != 0 && buf.received_size == buf.expected_size {
            let result = buf.data[..buf.expected_size].to_vec();
            self.cache.remove(&key);
            return Some(result);
        }

        None
    }
}