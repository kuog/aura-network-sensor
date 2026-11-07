use std::net::IpAddr;
use lru::LruCache;
use std::num::NonZeroUsize;

/// T1041: minimum payload uploaded within one TCP connection (50 MiB)...
pub const EXFIL_MIN_UPLOAD_BYTES: u64 = 50 * 1024 * 1024;
/// ...and minimum upload/download ratio.
pub const EXFIL_MIN_RATIO: f64 = 10.0;

/// The upload/download ratio if a connection crossed the T1041 thresholds.
pub fn exfil_ratio(uploaded: u64, downloaded: u64) -> Option<f64> {
    if uploaded <= EXFIL_MIN_UPLOAD_BYTES {
        return None;
    }
    let ratio = if downloaded > 0 {
        uploaded as f64 / downloaded as f64
    } else {
        uploaded as f64 // Treat 0 download as high ratio
    };
    (ratio > EXFIL_MIN_RATIO).then_some(ratio)
}

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FlowKey {
    pub fn canonical(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16) -> (Self, bool) {
        if src < dst || (src == dst && src_port < dst_port) {
            (FlowKey { src, dst, src_port, dst_port }, false)
        } else {
            (FlowKey { src: dst, dst: src, src_port: dst_port, dst_port: src_port }, true)
        }
    }
}

pub struct TcpStream {
    pub bytes: Vec<u8>,      // Forward payload (Canonical Src -> Dst)
    pub bytes_rev: Vec<u8>,  // Reverse payload (Canonical Dst -> Src)
    pub analyzed: bool,
    pub analyzed_rev: bool,
    
    pub last_seen_ts: Option<f64>,
    pub intervals: Vec<f64>, // Forward intervals
    
    // Exfiltration Stats
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub is_exfil_alerted: bool,
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

    pub fn update_stats(&mut self, src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16, payload_len: u64, is_upload: bool) -> Option<(u64, u64, f64)> {
        let (key, _) = FlowKey::canonical(src, dst, src_port, dst_port);
        
        let stream = self.streams.get_or_insert_mut(key, || TcpStream {
            bytes: Vec::with_capacity(4096),
            bytes_rev: Vec::with_capacity(4096),
            analyzed: false,
            analyzed_rev: false,
            last_seen_ts: None,
            intervals: Vec::new(),
            bytes_uploaded: 0,
            bytes_downloaded: 0,
            is_exfil_alerted: false,
        });

        if is_upload {
            stream.bytes_uploaded += payload_len;
        } else {
            stream.bytes_downloaded += payload_len;
        }

        // Check for Exfiltration (T1041)
        if !stream.is_exfil_alerted {
            if let Some(ratio) = exfil_ratio(stream.bytes_uploaded, stream.bytes_downloaded) {
                stream.is_exfil_alerted = true;
                return Some((stream.bytes_uploaded, stream.bytes_downloaded, ratio));
            }
        }
        None
    }

    pub fn add_segment(&mut self, src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16, payload: &[u8], ts: f64) -> Option<(Vec<u8>, f64)> {
        let (key, is_rev) = FlowKey::canonical(src, dst, src_port, dst_port);
        
        let stream = self.streams.get_or_insert_mut(key, || TcpStream {
            bytes: Vec::with_capacity(4096),
            bytes_rev: Vec::with_capacity(4096),
            analyzed: false,
            analyzed_rev: false,
            last_seen_ts: None,
            intervals: Vec::new(),
            bytes_uploaded: 0,
            bytes_downloaded: 0,
            is_exfil_alerted: false,
        });

        // Update timing stats (only for forward stream for beaconing consistency)
        if !is_rev {
            if let Some(last_ts) = stream.last_seen_ts {
                let delta = ts - last_ts;
                if delta > 0.001 { 
                    stream.intervals.push(delta);
                }
            }
            stream.last_seen_ts = Some(ts);
        }

        if is_rev {
            if stream.analyzed_rev { return None; }
            stream.bytes_rev.extend_from_slice(payload);
            
            if stream.bytes_rev.windows(4).any(|w| w == b"\r\n\r\n") || stream.bytes_rev.len() > 10240 {
                stream.analyzed_rev = true;
                let result = stream.bytes_rev.clone();
                // No beacon score for reverse stream for now
                stream.bytes_rev.clear();
                stream.bytes_rev.shrink_to_fit();
                return Some((result, 1.0)); 
            }
        } else {
            if stream.analyzed { return None; }
            stream.bytes.extend_from_slice(payload);

            if stream.bytes.windows(4).any(|w| w == b"\r\n\r\n") || stream.bytes.len() > 10240 {
                stream.analyzed = true;
                let result = stream.bytes.clone();
                let score = crate::telemetry::calculate_beacon_score(&stream.intervals);
                stream.bytes.clear();
                stream.bytes.shrink_to_fit();
                return Some((result, score));
            }
        }
        None
    }
}