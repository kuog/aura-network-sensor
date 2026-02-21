use std::collections::HashMap;
use std::net::IpAddr;

struct FragBuffer {
    data: Vec<u8>,
    expected_size: usize,
    received_size: usize,
}

/// Handles IPv4 + IPv6 fragmentation reassembly.
#[derive(Default)]
pub struct Defragmenter {
    // Key: (Source IP, Destination IP, IPv4 ID)
    cache_v4: HashMap<(IpAddr, IpAddr, u16), FragBuffer>,
    // Key: (Source IP, Destination IP, IPv6 Identification)
    cache_v6: HashMap<(IpAddr, IpAddr, u32), FragBuffer>,
}

impl Defragmenter {
    pub fn new() -> Self {
        Self {
            cache_v4: HashMap::new(),
            cache_v6: HashMap::new(),
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

        let buf = self.cache_v4.entry(key).or_insert(FragBuffer {
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
            self.cache_v4.remove(&key);
            return Some(result);
        }

        None
    }

    pub fn process_ipv6(
        &mut self,
        ip_hdr: &etherparse::Ipv6Header,
        fragment: Option<&etherparse::Ipv6FragmentHeader>,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let fragment = match fragment {
            Some(frag) => frag,
            None => return Some(payload.to_vec()),
        };

        // Atomic fragments (offset=0, more=false) are treated as unfragmented.
        if !fragment.more_fragments && fragment.fragment_offset.value() == 0 {
            return Some(payload.to_vec());
        }

        let key = (
            IpAddr::V6(ip_hdr.source.into()),
            IpAddr::V6(ip_hdr.destination.into()),
            fragment.identification,
        );
        let offset = fragment.fragment_offset.byte_offset() as usize;

        let buf = self.cache_v6.entry(key).or_insert(FragBuffer {
            data: vec![0; 65535], // Max IPv6 payload size (no jumbograms)
            expected_size: 0,
            received_size: 0,
        });

        let end = offset + payload.len();
        if end <= 65535 {
            buf.data[offset..end].copy_from_slice(payload);
            buf.received_size += payload.len();
        }

        if !fragment.more_fragments {
            buf.expected_size = end;
        }

        if buf.expected_size != 0 && buf.received_size == buf.expected_size {
            let result = buf.data[..buf.expected_size].to_vec();
            self.cache_v6.remove(&key);
            return Some(result);
        }

        None
    }
}
