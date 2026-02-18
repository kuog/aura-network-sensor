/// Calculates Shannon Entropy of a byte slice.
/// Returns a value between 0.0 (constant) and 8.0 (completely random/encrypted).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0usize; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        }).sum()
}

/// Calculates the Coefficient of Variation (CV) for packet intervals.
/// A very low CV (close to 0) means the timing is mechanical (Beaconing).
pub fn calculate_jitter_score(intervals: &[f64]) -> f64 {
    if intervals.len() < 5 { return 1.0; } // Not enough data
    
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    let variance = intervals.iter()
        .map(|&i| (i - mean).powi(2))
        .sum::<f64>() / intervals.len() as f64;
    
    let std_dev = variance.sqrt();
    if mean == 0.0 { return 1.0; }
    
    std_dev / mean // This is the Coefficient of Variation
}

/// Calculates the Coefficient of Variation (CV) for Beaconing detection.
/// CV = Standard Deviation / Mean
/// If CV < 0.2, the timing is highly suspicious (very rhythmic).
pub fn calculate_beacon_score(intervals: &[f64]) -> f64 {
    if intervals.len() < 4 { return 1.0; } // Need at least 4-5 packets

    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean < 0.1 { return 1.0; } // Ignore high-speed floods

    let variance = intervals.iter()
        .map(|&i| (i - mean).powi(2))
        .sum::<f64>() / intervals.len() as f64;
    
    let std_dev = variance.sqrt();
    std_dev / mean
}