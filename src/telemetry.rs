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