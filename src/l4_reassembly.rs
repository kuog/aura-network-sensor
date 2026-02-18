use std::net::IpAddr;
use lru::LruCache;
use std::num::NonZeroUsize;

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

pub struct TcpStream {
    pub bytes: Vec<u8>,
    pub analyzed: bool,
}

/// Manages TCP flows using an LRU cache to bound memory usage.
pub struct Reassembler {
    pub streams: LruCache<FlowKey, TcpStream>,
}

impl Reassembler {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).expect("Capacity must be > 0");
        Self { streams: LruCache::new(cap) }
    }

    pub fn add_segment(&mut self, key: FlowKey, payload: &[u8]) -> Option<Vec<u8>> {
        let stream = self.streams.get_or_insert_mut(key, || TcpStream {
            bytes: Vec::with_capacity(4096),
            analyzed: false,
        });

        if stream.analyzed { return None; }

        stream.bytes.extend_from_slice(payload);

        // Analyze if headers end (\r\n\r\n) or buffer is getting too large
        if stream.bytes.windows(4).any(|w| w == b"\r\n\r\n") || stream.bytes.len() > 10240 {
            stream.analyzed = true;
            let result = stream.bytes.clone();
            // Free memory but keep the entry to avoid re-analyzing the same flow
            stream.bytes.clear();
            stream.bytes.shrink_to_fit();
            return Some(result);
        }
        None
    }
}