use std::net::IpAddr;
use lru::LruCache;
use memchr::memmem;
use std::num::NonZeroUsize;

/// T1041: minimum payload uploaded within one TCP connection (50 MiB)...
pub const EXFIL_MIN_UPLOAD_BYTES: u64 = 50 * 1024 * 1024;
/// ...and minimum upload/download ratio.
pub const EXFIL_MIN_RATIO: f64 = 10.0;

/// A direction is inspected once this much payload is buffered, even without
/// a header terminator.
const INSPECT_AFTER_BYTES: usize = 10_240;

const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

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

#[derive(Default)]
pub struct TcpStream {
    pub bytes: Vec<u8>,      // Forward payload (Canonical Src -> Dst)
    pub bytes_rev: Vec<u8>,  // Reverse payload (Canonical Dst -> Src)
    pub analyzed: bool,
    pub analyzed_rev: bool,

    pub last_seen_ts: Option<f64>,
    pub intervals: Vec<f64>, // Forward intervals, until the forward direction is inspected

    // Exfiltration Stats
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub is_exfil_alerted: bool,
}

/// Append a segment and report whether the buffer is ready for inspection.
fn buffer_segment(buffer: &mut Vec<u8>, payload: &[u8]) -> bool {
    // What was buffered has been searched, but the terminator can straddle segments.
    let search_from = buffer.len().saturating_sub(HEADER_TERMINATOR.len() - 1);
    buffer.extend_from_slice(payload);
    memmem::find(&buffer[search_from..], HEADER_TERMINATOR).is_some() || buffer.len() > INSPECT_AFTER_BYTES
}

impl TcpStream {
    fn add_payload(&mut self, payload: &[u8], is_rev: bool, ts: f64) -> Option<(Vec<u8>, f64)> {
        if is_rev {
            if self.analyzed_rev || !buffer_segment(&mut self.bytes_rev, payload) {
                return None;
            }
            self.analyzed_rev = true;
            // No beacon score for reverse stream for now
            return Some((std::mem::take(&mut self.bytes_rev), 1.0));
        }

        if self.analyzed {
            return None;
        }

        // Timing stats are kept for the forward stream only, for beaconing consistency.
        if let Some(last_ts) = self.last_seen_ts {
            let delta = ts - last_ts;
            if delta > 0.001 {
                self.intervals.push(delta);
            }
        }
        self.last_seen_ts = Some(ts);

        if !buffer_segment(&mut self.bytes, payload) {
            return None;
        }
        self.analyzed = true;
        let score = crate::telemetry::calculate_beacon_score(&self.intervals);
        self.intervals = Vec::new();
        Some((std::mem::take(&mut self.bytes), score))
    }
}

/// What a TCP segment produced.
#[derive(Default)]
pub struct SegmentOutcome {
    /// (uploaded, downloaded, ratio) if this segment took the connection over
    /// the T1041 thresholds.
    pub exfil: Option<(u64, u64, f64)>,
    /// A direction's buffered payload ready for inspection, with its beacon score.
    pub session: Option<(Vec<u8>, f64)>,
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

    /// Account for a TCP segment and buffer its payload, if it has any.
    #[allow(clippy::too_many_arguments)]
    pub fn add_segment(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        is_upload: bool,
        ts: f64,
    ) -> SegmentOutcome {
        let (key, is_rev) = FlowKey::canonical(src, dst, src_port, dst_port);
        let stream = self.streams.get_or_insert_mut(key, TcpStream::default);

        if is_upload {
            stream.bytes_uploaded += payload.len() as u64;
        } else {
            stream.bytes_downloaded += payload.len() as u64;
        }

        // Check for Exfiltration (T1041)
        let mut outcome = SegmentOutcome::default();
        if !stream.is_exfil_alerted {
            if let Some(ratio) = exfil_ratio(stream.bytes_uploaded, stream.bytes_downloaded) {
                stream.is_exfil_alerted = true;
                outcome.exfil = Some((stream.bytes_uploaded, stream.bytes_downloaded, ratio));
            }
        }

        // Bare ACKs count towards neither the buffers nor the timing.
        if !payload.is_empty() {
            outcome.session = stream.add_payload(payload, is_rev, ts);
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: f64 = 1_700_000_000.0;

    fn addr(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    fn forward(r: &mut Reassembler, payload: &[u8], ts: f64) -> SegmentOutcome {
        r.add_segment(addr(1), addr(2), 40_000, 80, payload, true, ts)
    }

    fn reverse(r: &mut Reassembler, payload: &[u8], ts: f64) -> SegmentOutcome {
        r.add_segment(addr(2), addr(1), 80, 40_000, payload, false, ts)
    }

    #[test]
    fn terminator_is_found_across_segments() {
        for cut in 1..HEADER_TERMINATOR.len() {
            let message = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
            let (head, tail) = message.split_at(message.len() - cut);
            let mut r = Reassembler::new(4);
            assert!(forward(&mut r, head, BASE).session.is_none());
            let (session, _) = forward(&mut r, tail, BASE + 1.0).session.expect("inspected");
            assert_eq!(session, message);
        }
    }

    #[test]
    fn inspected_once_past_the_size_limit() {
        let mut r = Reassembler::new(4);
        assert!(forward(&mut r, &[b'x'; INSPECT_AFTER_BYTES], BASE).session.is_none());
        let (session, _) = forward(&mut r, b"y", BASE + 1.0).session.expect("inspected");
        assert_eq!(session.len(), INSPECT_AFTER_BYTES + 1);
        assert!(forward(&mut r, b"z\r\n\r\n", BASE + 2.0).session.is_none());
    }

    #[test]
    fn directions_are_inspected_independently() {
        let mut r = Reassembler::new(4);
        assert!(forward(&mut r, b"up\r\n\r\n", BASE).session.is_some());
        let (session, score) = reverse(&mut r, b"down\r\n\r\n", BASE + 1.0).session.expect("inspected");
        assert_eq!(session, b"down\r\n\r\n");
        assert_eq!(score, 1.0);
    }

    #[test]
    fn bare_acks_do_not_affect_timing() {
        let with_acks = |acks: bool| {
            let mut r = Reassembler::new(4);
            let mut ts = BASE;
            for _ in 0..6 {
                ts += 5.0;
                forward(&mut r, b"ping", ts);
                if acks {
                    forward(&mut r, b"", ts + 2.0);
                }
            }
            forward(&mut r, b"\r\n\r\n", ts + 5.0).session.expect("inspected").1
        };
        assert_eq!(with_acks(false), with_acks(true));
    }

    #[test]
    fn intervals_stop_growing_after_inspection() {
        let mut r = Reassembler::new(4);
        forward(&mut r, b"done\r\n\r\n", BASE);
        for i in 1..100 {
            forward(&mut r, b"more", BASE + f64::from(i));
        }
        let (key, _) = FlowKey::canonical(addr(1), addr(2), 40_000, 80);
        assert!(r.streams.peek(&key).unwrap().intervals.is_empty());
    }

    #[test]
    fn exfiltration_is_reported_once() {
        let mut r = Reassembler::new(4);
        let chunk = vec![0u8; 26 * 1024 * 1024];
        assert!(forward(&mut r, &chunk, BASE).exfil.is_none());
        let (uploaded, downloaded, ratio) = forward(&mut r, &chunk, BASE + 1.0).exfil.expect("crossed");
        assert_eq!((uploaded, downloaded), (52 * 1024 * 1024, 0));
        assert_eq!(ratio, uploaded as f64);
        assert!(forward(&mut r, &chunk, BASE + 2.0).exfil.is_none());
    }
}
