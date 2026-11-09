//! IPv4 and IPv6 fragment reassembly, with bounded memory.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use lru::LruCache;

/// Datagrams being reassembled at once; the least recently touched is dropped.
const MAX_PENDING: usize = 1024;

/// How long a datagram may wait for its missing fragments (as Linux `ipfrag_time`).
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest IP payload a chain of fragments can describe.
const MAX_DATAGRAM: usize = 65_535;

/// Fragment offsets are counted in units of this many bytes.
const BLOCK: usize = 8;

const COVERAGE_WORDS: usize = (MAX_DATAGRAM / BLOCK + 1).div_ceil(64);

/// An IP packet after fragmentation has been dealt with.
pub enum Datagram<'a> {
    /// Not fragmented: the payload as captured.
    Whole(&'a [u8]),
    /// The last missing fragment arrived. `bytes` is the complete IP payload,
    /// transport header included; `protocol` is its IP protocol number.
    Reassembled { protocol: u8, bytes: Vec<u8> },
    /// A fragment of a datagram that is not complete yet, or a malformed one.
    Incomplete,
}

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct FragmentKey {
    src: IpAddr,
    dst: IpAddr,
    id: u32,
    protocol: u8,
}

struct PendingDatagram {
    data: Vec<u8>,
    /// One bit per `BLOCK` bytes received: a duplicate adds nothing.
    coverage: Box<[u64; COVERAGE_WORDS]>,
    covered_blocks: usize,
    /// Known once the last fragment has been seen.
    total_len: Option<usize>,
    started: Instant,
}

impl PendingDatagram {
    fn new(now: Instant) -> Self {
        Self {
            data: Vec::new(),
            coverage: Box::new([0; COVERAGE_WORDS]),
            covered_blocks: 0,
            total_len: None,
            started: now,
        }
    }

    fn mark_received(&mut self, offset: usize, end: usize) {
        for block in offset / BLOCK..end.div_ceil(BLOCK) {
            let (word, bit) = (block / 64, 1u64 << (block % 64));
            if self.coverage[word] & bit == 0 {
                self.coverage[word] |= bit;
                self.covered_blocks += 1;
            }
        }
    }

    fn is_complete(&self) -> bool {
        self.total_len.is_some_and(|len| self.covered_blocks == len.div_ceil(BLOCK))
    }
}

/// Handles IPv4 + IPv6 fragmentation reassembly.
pub struct Defragmenter {
    pending: LruCache<FragmentKey, PendingDatagram>,
}

impl Defragmenter {
    pub fn new() -> Self {
        let capacity = NonZeroUsize::new(MAX_PENDING).expect("capacity is not zero");
        Self { pending: LruCache::new(capacity) }
    }

    pub fn process<'a>(&mut self, ip_hdr: &etherparse::Ipv4Header, payload: &'a [u8]) -> Datagram<'a> {
        if !ip_hdr.more_fragments && ip_hdr.fragment_offset.value() == 0 {
            return Datagram::Whole(payload);
        }

        let key = FragmentKey {
            src: IpAddr::V4(ip_hdr.source.into()),
            dst: IpAddr::V4(ip_hdr.destination.into()),
            id: u32::from(ip_hdr.identification),
            protocol: ip_hdr.protocol.0,
        };
        let offset = ip_hdr.fragment_offset.byte_offset() as usize;
        self.add_fragment(key, offset, ip_hdr.more_fragments, payload, Instant::now())
    }

    pub fn process_ipv6<'a>(
        &mut self,
        ip_hdr: &etherparse::Ipv6Header,
        fragment: Option<&etherparse::Ipv6FragmentHeader>,
        payload: &'a [u8],
    ) -> Datagram<'a> {
        let Some(fragment) = fragment else {
            return Datagram::Whole(payload);
        };

        // Atomic fragments (offset=0, more=false) are treated as unfragmented.
        if !fragment.more_fragments && fragment.fragment_offset.value() == 0 {
            return Datagram::Whole(payload);
        }

        let key = FragmentKey {
            src: IpAddr::V6(ip_hdr.source.into()),
            dst: IpAddr::V6(ip_hdr.destination.into()),
            id: fragment.identification,
            protocol: fragment.next_header.0,
        };
        let offset = fragment.fragment_offset.byte_offset() as usize;
        self.add_fragment(key, offset, fragment.more_fragments, payload, Instant::now())
    }

    fn add_fragment(
        &mut self,
        key: FragmentKey,
        offset: usize,
        more_fragments: bool,
        payload: &[u8],
        now: Instant,
    ) -> Datagram<'static> {
        // Only the last fragment may end inside a block.
        let mut end = offset + payload.len();
        if more_fragments {
            end -= end % BLOCK;
        }
        if end > MAX_DATAGRAM {
            self.pending.pop(&key);
            return Datagram::Incomplete;
        }

        let datagram = self.pending.get_or_insert_mut(key, || PendingDatagram::new(now));
        if now.duration_since(datagram.started) > REASSEMBLY_TIMEOUT {
            *datagram = PendingDatagram::new(now);
        }

        // The end of the datagram must not move once it is known, and no
        // fragment may lie beyond it.
        let consistent = match (more_fragments, datagram.total_len) {
            (true, Some(total)) => end <= total,
            (false, Some(total)) => end == total,
            (false, None) => end >= datagram.data.len(),
            (true, None) => true,
        };
        if !consistent {
            self.pending.pop(&key);
            return Datagram::Incomplete;
        }

        if !more_fragments {
            datagram.total_len = Some(end);
        }
        if end > offset {
            if datagram.data.len() < end {
                datagram.data.resize(end, 0);
            }
            datagram.data[offset..end].copy_from_slice(&payload[..end - offset]);
            datagram.mark_received(offset, end);
        }

        if !datagram.is_complete() {
            return Datagram::Incomplete;
        }
        match self.pending.pop(&key) {
            Some(complete) => Datagram::Reassembled { protocol: key.protocol, bytes: complete.data },
            None => Datagram::Incomplete,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key(id: u32) -> FragmentKey {
        FragmentKey {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            id,
            protocol: 6,
        }
    }

    fn complete(result: Datagram<'_>) -> Vec<u8> {
        match result {
            Datagram::Reassembled { protocol, bytes } => {
                assert_eq!(protocol, 6);
                bytes
            }
            _ => panic!("datagram is not complete"),
        }
    }

    fn incomplete(result: Datagram<'_>) {
        assert!(matches!(result, Datagram::Incomplete));
    }

    #[test]
    fn unfragmented_packets_are_not_copied() {
        let mut defrag = Defragmenter::new();
        let payload = [1u8, 2, 3];
        let header = etherparse::Ipv4Header::default();
        match defrag.process(&header, &payload) {
            Datagram::Whole(whole) => assert!(std::ptr::eq(whole, &payload[..])),
            _ => panic!("expected the payload as captured"),
        }
    }

    #[test]
    fn reassembles_in_any_order() {
        let now = Instant::now();
        let mut defrag = Defragmenter::new();
        incomplete(defrag.add_fragment(key(1), 16, false, b"ccc", now));
        incomplete(defrag.add_fragment(key(1), 0, true, b"aaaaaaaa", now));
        let bytes = complete(defrag.add_fragment(key(1), 8, true, b"bbbbbbbb", now));
        assert_eq!(bytes, b"aaaaaaaabbbbbbbbccc");
        assert!(defrag.pending.is_empty());
    }

    #[test]
    fn duplicates_do_not_complete_a_datagram() {
        let now = Instant::now();
        let mut defrag = Defragmenter::new();
        incomplete(defrag.add_fragment(key(1), 0, true, b"aaaaaaaa", now));
        incomplete(defrag.add_fragment(key(1), 0, true, b"aaaaaaaa", now));
        incomplete(defrag.add_fragment(key(1), 16, false, b"cccccccc", now));
        // Bytes 8..16 are still missing, however many duplicates arrive.
        incomplete(defrag.add_fragment(key(1), 0, true, b"aaaaaaaa", now));
    }

    #[test]
    fn a_datagram_past_the_ip_limit_is_dropped() {
        let now = Instant::now();
        let mut defrag = Defragmenter::new();
        incomplete(defrag.add_fragment(key(1), 0, true, &[0; 65_528], now));
        incomplete(defrag.add_fragment(key(1), 65_528, false, &[0; 16], now));
        assert!(defrag.pending.is_empty());
    }

    #[test]
    fn inconsistent_ends_drop_the_datagram() {
        let now = Instant::now();
        let mut defrag = Defragmenter::new();
        incomplete(defrag.add_fragment(key(1), 0, true, &[0; 32], now));
        // A last fragment ending before data already received.
        incomplete(defrag.add_fragment(key(1), 8, false, &[0; 8], now));
        assert!(defrag.pending.is_empty());

        incomplete(defrag.add_fragment(key(2), 8, false, &[0; 8], now));
        // Data beyond the known end.
        incomplete(defrag.add_fragment(key(2), 16, true, &[0; 8], now));
        assert!(defrag.pending.is_empty());
    }

    #[test]
    fn fragments_with_unaligned_ends_are_trimmed() {
        let now = Instant::now();
        let mut defrag = Defragmenter::new();
        incomplete(defrag.add_fragment(key(1), 0, true, b"aaaaaaaaX", now));
        let bytes = complete(defrag.add_fragment(key(1), 8, false, b"b", now));
        assert_eq!(bytes, b"aaaaaaaab");
    }

    #[test]
    fn memory_is_bounded() {
        let now = Instant::now();
        let mut defrag = Defragmenter::new();
        for id in 0..(MAX_PENDING as u32 * 3) {
            incomplete(defrag.add_fragment(key(id), 0, true, &[0; 8], now));
        }
        assert_eq!(defrag.pending.len(), MAX_PENDING);
    }

    #[test]
    fn a_stale_datagram_starts_over() {
        let now = Instant::now();
        let mut defrag = Defragmenter::new();
        incomplete(defrag.add_fragment(key(1), 0, true, b"oldoldol", now));
        let later = now + REASSEMBLY_TIMEOUT + Duration::from_secs(1);
        incomplete(defrag.add_fragment(key(1), 8, false, b"new", later));
        let bytes = complete(defrag.add_fragment(key(1), 0, true, b"freshnew", later));
        assert_eq!(bytes, b"freshnewnew");
    }
}
