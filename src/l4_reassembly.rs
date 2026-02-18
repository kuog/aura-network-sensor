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
    pub last_seen_ts: Option<f64>, // Time of the last packet
    pub intervals: Vec<f64>,        // List of deltas in seconds
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

    pub fn add_segment(&mut self, key: FlowKey, payload: &[u8], ts: f64) -> Option<(Vec<u8>, f64)> {
        let stream = self.streams.get_or_insert_mut(key, || TcpStream {
            bytes: Vec::with_capacity(4096),
            analyzed: false,
            last_seen_ts: None,
            intervals: Vec::new(),
        });

        // Update timing stats
        if let Some(last_ts) = stream.last_seen_ts {
            let delta = ts - last_ts;
            if delta > 0.001 { // Ignore simultaneous packets
                stream.intervals.push(delta);
            }
        }
        stream.last_seen_ts = Some(ts);

        if stream.analyzed { return None; }

        stream.bytes.extend_from_slice(payload);

        // Analyze if headers end (\r\n\r\n) or buffer is getting too large
        if stream.bytes.windows(4).any(|w| w == b"\r\n\r\n") || stream.bytes.len() > 10240 {
            stream.analyzed = true;
            let result = stream.bytes.clone();
            
            // Calculate beacon score
            let score = crate::telemetry::calculate_beacon_score(&stream.intervals);

            // Free memory but keep the entry to avoid re-analyzing the same flow
            stream.bytes.clear();
            stream.bytes.shrink_to_fit();
            return Some((result, score));
        }
        None
    }
}