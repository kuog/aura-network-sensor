//! Isolation Forest — Pure Rust implementation.
//!
//! The Isolation Forest algorithm detects anomalies by measuring how easily
//! a data point can be isolated through random recursive partitioning.
//! Anomalous points require fewer splits to isolate, resulting in shorter
//! average path lengths across the ensemble of trees.
//!
//! ## Algorithm
//!
//! 1. Build `n_trees` isolation trees, each trained on a random subsample.
//! 2. For each tree, recursively partition data by choosing a random feature
//!    and a random split value between the feature's min and max.
//! 3. The path length to isolate a point is the depth at which it ends up alone.
//! 4. The anomaly score is derived from the average path length across all trees,
//!    normalized by the expected path length for a dataset of the same size.
//!
//! ## Production Features
//!
//! - **Z-score normalization**: Features are standardized before tree construction
//!   and scoring, improving split quality across heterogeneous feature scales.
//! - **Adaptive threshold**: Calibrated from training data at a configurable
//!   percentile so that baseline traffic is classified as normal.
//! - **Score distribution**: Key percentiles (p5, p25, p50, p75, p95, p99) of
//!   training scores are stored for percentile-based confidence calibration.
//! - **Model quality metrics**: Training statistics are logged and persisted
//!   inside the serialized model for observability.
//!
//! ## References
//!
//! - Liu, Ting, Zhou (2008): "Isolation Forest"
//! - Liu, Ting, Zhou (2012): "Isolation-Based Anomaly Detection"

use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// Starts every model file, so a file in an older format is rejected instead
/// of being decoded into garbage.
const MODEL_FILE_MAGIC: &[u8] = b"MCPIF2\n";

// ── Configuration ──────────────────────────────────────────────────────────

/// Configuration for the Isolation Forest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationForestConfig {
    /// Number of isolation trees in the ensemble.
    pub n_trees: usize,
    /// Subsample size for each tree (ψ in the paper).
    /// Recommended: 256 for most datasets.
    pub subsample_size: usize,
    /// Maximum tree depth (auto-calculated as ceil(log2(subsample_size)) if None).
    pub max_depth: Option<usize>,
    /// Anomaly score threshold.
    ///
    /// When `adaptive_threshold` is `true` (default), this field is **overwritten**
    /// after training with the score at `threshold_percentile` of the training data.
    /// This ensures that traffic patterns seen during learning are classified as
    /// normal.  The static value is only used as a fallback when adaptive
    /// calibration is disabled.
    pub threshold: f64,
    /// Random seed for reproducibility (None = random).
    pub seed: Option<u64>,
    /// Whether to compute the threshold adaptively from training data.
    ///
    /// When `true` (default), after building the trees the model scores every
    /// training sample and sets `threshold` to the `threshold_percentile`-th
    /// percentile of those scores.  This means that ≈`threshold_percentile`%
    /// of the training traffic will be classified as **normal**.
    pub adaptive_threshold: bool,
    /// Percentile (0.0–1.0) used for adaptive threshold calibration.
    ///
    /// Default: `0.95` — 95 % of training flows are considered normal.
    pub threshold_percentile: f64,
    /// Whether to apply z-score normalization to features before training
    /// and scoring.  Default: `true`.
    pub normalize_features: bool,
}

impl Default for IsolationForestConfig {
    fn default() -> Self {
        Self {
            n_trees: 200,
            subsample_size: 256,
            max_depth: None,
            threshold: 0.50,
            seed: None,
            adaptive_threshold: true,
            threshold_percentile: 0.95,
            normalize_features: true,
        }
    }
}

// ── Model quality metrics ──────────────────────────────────────────────────

/// Quality metrics computed after training for observability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetrics {
    /// Number of training samples used.
    pub training_samples: usize,
    /// Score distribution percentiles from training data.
    pub score_p5: f64,
    pub score_p25: f64,
    pub score_p50: f64,
    pub score_p75: f64,
    pub score_p95: f64,
    pub score_p99: f64,
    /// Min and max scores observed in training data.
    pub score_min: f64,
    pub score_max: f64,
    /// Mean score across training data.
    pub score_mean: f64,
    /// Percentage of training data classified as anomalous (should be ~5% with p95 threshold).
    pub anomaly_rate_pct: f64,
    /// Total number of tree nodes across all trees.
    pub total_nodes: usize,
    /// Per-feature split counts (how many times each feature was used for splitting).
    /// Index = feature index, value = number of splits using that feature.
    pub feature_split_counts: Vec<usize>,
}

// ── Score distribution for confidence calibration ──────────────────────────

/// Key percentiles of the training score distribution.
///
/// Stored in the model and used by the detector for percentile-based
/// confidence calibration instead of arbitrary linear formulas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreDistribution {
    pub p5: f64,
    pub p25: f64,
    pub p50: f64,
    pub p75: f64,
    pub p95: f64,
    pub p99: f64,
    pub min: f64,
    pub max: f64,
}

impl ScoreDistribution {
    /// Compute confidence for a **normal** classification.
    ///
    /// Maps the score into [0, 1] based on how far below the threshold it is
    /// relative to the training distribution.
    ///   - score at p5  → confidence ≈ 1.0 (very clearly normal)
    ///   - score at threshold → confidence ≈ 0.0 (borderline)
    pub fn confidence_normal(&self, score: f64, threshold: f64) -> f64 {
        let range = threshold - self.p5;
        if range <= 0.0 {
            return 0.5;
        }
        let distance = threshold - score;
        (distance / range).clamp(0.0, 1.0)
    }

    /// Compute confidence for an **anomalous** classification.
    ///
    /// Maps the score into [0, 1] based on how far above the threshold it is
    /// relative to the training distribution.
    ///   - score at threshold → confidence ≈ 0.0 (borderline)
    ///   - score at p99       → confidence ≈ 1.0 (very clearly anomalous)
    pub fn confidence_anomalous(&self, score: f64, threshold: f64) -> f64 {
        let range = self.p99 - threshold;
        if range <= 0.0 {
            return 0.5;
        }
        let distance = score - threshold;
        (distance / range).clamp(0.0, 1.0)
    }
}

// ── Normalization parameters ───────────────────────────────────────────────

/// Per-feature z-score normalization parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NormParams {
    /// Per-feature means.
    means: Vec<f64>,
    /// Per-feature standard deviations.
    stds: Vec<f64>,
}

impl NormParams {
    /// Compute normalization parameters from training data.
    fn from_data(data: &[Vec<f64>], n_features: usize) -> Self {
        let n = data.len() as f64;
        let mut means = vec![0.0; n_features];
        let mut stds = vec![0.0; n_features];

        // Compute means
        for row in data {
            for (j, val) in row.iter().enumerate() {
                means[j] += val;
            }
        }
        for m in &mut means {
            *m /= n;
        }

        // Compute standard deviations
        for row in data {
            for (j, val) in row.iter().enumerate() {
                stds[j] += (val - means[j]).powi(2);
            }
        }
        for s in &mut stds {
            *s = (*s / (n - 1.0).max(1.0)).sqrt();
        }

        Self { means, stds }
    }

    /// Normalize a single feature vector in-place.
    fn normalize(&self, point: &mut [f64]) {
        for (j, val) in point.iter_mut().enumerate() {
            if self.stds[j] > f64::EPSILON {
                *val = (*val - self.means[j]) / self.stds[j];
            }
            // If std ≈ 0, leave the value as-is (constant feature)
        }
    }

    /// Normalize a dataset, returning a new Vec of normalized vectors.
    fn normalize_dataset(&self, data: &[Vec<f64>]) -> Vec<Vec<f64>> {
        data.iter()
            .map(|row| {
                let mut normalized = row.clone();
                self.normalize(&mut normalized);
                normalized
            })
            .collect()
    }
}

// ── Tree nodes ─────────────────────────────────────────────────────────────

/// A single node in an isolation tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum ITreeNode {
    /// Internal node: splits on a feature at a threshold.
    Split {
        /// Feature index to split on.
        feature: usize,
        /// Split threshold value.
        threshold: f64,
        /// Left child (values < threshold).
        left: Box<ITreeNode>,
        /// Right child (values >= threshold).
        right: Box<ITreeNode>,
    },
    /// Leaf node: contains the number of samples that reached this node.
    Leaf {
        /// Number of samples at this leaf.
        size: usize,
    },
}

/// A single isolation tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ITree {
    root: ITreeNode,
}

// ── Isolation Forest model ─────────────────────────────────────────────────

/// The Isolation Forest model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationForest {
    /// The ensemble of isolation trees.
    trees: Vec<ITree>,
    /// Configuration used to build this forest.
    config: IsolationForestConfig,
    /// Number of features (dimensions) in the training data.
    n_features: usize,
    /// Z-score normalization parameters (None if normalization is disabled).
    norm_params: Option<NormParams>,
    /// Training score distribution for confidence calibration.
    score_distribution: Option<ScoreDistribution>,
    /// Model quality metrics computed after training.
    metrics: Option<ModelMetrics>,
}

/// Average path length of unsuccessful search in a Binary Search Tree.
///
/// This is the normalization factor c(n) from the original paper:
/// c(n) = 2 * H(n-1) - 2*(n-1)/n
/// where H(i) is the harmonic number ≈ ln(i) + 0.5772156649 (Euler-Mascheroni constant).
fn c_factor(n: usize) -> f64 {
    if n <= 1 {
        return 0.0;
    }
    let n = n as f64;
    let euler = 0.5772156649;
    2.0 * ((n - 1.0).ln() + euler) - 2.0 * (n - 1.0) / n
}

/// Extract a percentile value from a sorted slice.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 * p).ceil() as usize).min(sorted.len().saturating_sub(1));
    sorted[idx]
}

/// Count total nodes in a tree (for metrics).
fn count_nodes(node: &ITreeNode) -> usize {
    match node {
        ITreeNode::Leaf { .. } => 1,
        ITreeNode::Split { left, right, .. } => 1 + count_nodes(left) + count_nodes(right),
    }
}

/// Count feature split usage in a tree (for metrics).
fn count_feature_splits(node: &ITreeNode, counts: &mut [usize]) {
    if let ITreeNode::Split {
        feature,
        left,
        right,
        ..
    } = node
    {
        counts[*feature] += 1;
        count_feature_splits(left, counts);
        count_feature_splits(right, counts);
    }
}

impl IsolationForest {
    /// Train a new Isolation Forest on the given data.
    ///
    /// # Arguments
    /// * `data` — Training data as a slice of feature vectors.
    ///            Each inner slice must have the same length (n_features).
    /// * `config` — Forest configuration.
    ///
    /// # Returns
    /// A trained `IsolationForest` model, or an error if the data is invalid.
    pub fn fit(data: &[Vec<f64>], config: IsolationForestConfig) -> Result<Self, String> {
        if data.is_empty() {
            return Err("Training data is empty".to_string());
        }

        let n_features = data[0].len();
        if n_features == 0 {
            return Err("Feature vectors are empty".to_string());
        }

        // Validate all rows have the same number of features
        for (i, row) in data.iter().enumerate() {
            if row.len() != n_features {
                return Err(format!(
                    "Row {} has {} features, expected {}",
                    i,
                    row.len(),
                    n_features
                ));
            }
        }

        // ── Feature normalization ──────────────────────────────────────
        let norm_params = if config.normalize_features {
            Some(NormParams::from_data(data, n_features))
        } else {
            None
        };

        let training_data: Vec<Vec<f64>> = if let Some(ref params) = norm_params {
            params.normalize_dataset(data)
        } else {
            data.to_vec()
        };

        // ── Build trees ────────────────────────────────────────────────
        let max_depth = config
            .max_depth
            .unwrap_or_else(|| (config.subsample_size as f64).log2().ceil() as usize);

        let mut rng: Box<dyn RngCore> = if let Some(seed) = config.seed {
            Box::new(StdRng::seed_from_u64(seed))
        } else {
            Box::new(thread_rng())
        };

        let subsample_size = config.subsample_size.min(training_data.len());

        let mut trees = Vec::with_capacity(config.n_trees);
        for _ in 0..config.n_trees {
            // Random subsample (without replacement)
            let indices: Vec<usize> = {
                let mut all: Vec<usize> = (0..training_data.len()).collect();
                all.shuffle(&mut rng);
                all.truncate(subsample_size);
                all
            };

            let subsample: Vec<&[f64]> = indices
                .iter()
                .map(|&i| training_data[i].as_slice())
                .collect();

            let root = Self::build_tree(&subsample, 0, max_depth, n_features, &mut rng);
            trees.push(ITree { root });
        }

        let mut model = Self {
            trees,
            config,
            n_features,
            norm_params,
            score_distribution: None,
            metrics: None,
        };

        // ── Post-training calibration ──────────────────────────────────
        // Score every training sample (using already-normalized data).
        let mut scores: Vec<f64> = training_data
            .iter()
            .map(|row| model.score_raw(row))
            .collect();
        scores.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        // Store score distribution for confidence calibration
        let distribution = ScoreDistribution {
            p5: percentile(&scores, 0.05),
            p25: percentile(&scores, 0.25),
            p50: percentile(&scores, 0.50),
            p75: percentile(&scores, 0.75),
            p95: percentile(&scores, 0.95),
            p99: percentile(&scores, 0.99),
            min: scores.first().copied().unwrap_or(0.0),
            max: scores.last().copied().unwrap_or(1.0),
        };
        model.score_distribution = Some(distribution.clone());

        // Adaptive threshold calibration
        if model.config.adaptive_threshold {
            let idx =
                ((scores.len() as f64 * model.config.threshold_percentile).ceil() as usize)
                    .min(scores.len().saturating_sub(1));
            let adaptive = scores[idx];

            log::info!(
                "[IsolationForest] Adaptive threshold: {:.4} (p{:.0}%, samples={}, fallback={:.2})",
                adaptive,
                model.config.threshold_percentile * 100.0,
                scores.len(),
                model.config.threshold,
            );

            model.config.threshold = adaptive;
        }

        // Compute anomaly rate on training data
        let anomaly_count = scores
            .iter()
            .filter(|&&s| s > model.config.threshold)
            .count();
        let anomaly_rate_pct = anomaly_count as f64 / scores.len() as f64 * 100.0;

        // Compute model quality metrics
        let total_nodes: usize = model.trees.iter().map(|t| count_nodes(&t.root)).sum();
        let mut feature_split_counts = vec![0usize; n_features];
        for tree in &model.trees {
            count_feature_splits(&tree.root, &mut feature_split_counts);
        }

        let score_mean = scores.iter().sum::<f64>() / scores.len() as f64;

        let metrics = ModelMetrics {
            training_samples: scores.len(),
            score_p5: distribution.p5,
            score_p25: distribution.p25,
            score_p50: distribution.p50,
            score_p75: distribution.p75,
            score_p95: distribution.p95,
            score_p99: distribution.p99,
            score_min: distribution.min,
            score_max: distribution.max,
            score_mean,
            anomaly_rate_pct,
            total_nodes,
            feature_split_counts: feature_split_counts.clone(),
        };
        model.metrics = Some(metrics);

        // Log quality metrics
        log::info!(
            "[IsolationForest] Score distribution: min={:.4} p5={:.4} p25={:.4} \
             p50={:.4} p75={:.4} p95={:.4} p99={:.4} max={:.4} mean={:.4}",
            distribution.min,
            distribution.p5,
            distribution.p25,
            distribution.p50,
            distribution.p75,
            distribution.p95,
            distribution.p99,
            distribution.max,
            score_mean,
        );
        log::info!(
            "[IsolationForest] Anomaly rate on training data: {:.1}% ({}/{})",
            anomaly_rate_pct,
            anomaly_count,
            scores.len(),
        );
        log::info!(
            "[IsolationForest] Model size: {} trees, {} total nodes, {} features{}",
            model.trees.len(),
            total_nodes,
            n_features,
            if model.norm_params.is_some() {
                " (z-score normalized)"
            } else {
                ""
            },
        );

        // Log feature importance (top features by split count)
        let total_splits: usize = feature_split_counts.iter().sum();
        if total_splits > 0 {
            let mut indexed: Vec<(usize, usize)> = feature_split_counts
                .iter()
                .enumerate()
                .map(|(i, &c)| (i, c))
                .collect();
            indexed.sort_by(|a, b| b.1.cmp(&a.1));

            let top: Vec<String> = indexed
                .iter()
                .take(5)
                .map(|(i, c)| format!("f{}={:.1}%", i, *c as f64 / total_splits as f64 * 100.0))
                .collect();
            log::info!(
                "[IsolationForest] Feature importance (top 5): {}",
                top.join(", ")
            );
        }

        Ok(model)
    }

    /// Recursively build an isolation tree node.
    fn build_tree(
        data: &[&[f64]],
        depth: usize,
        max_depth: usize,
        n_features: usize,
        rng: &mut dyn RngCore,
    ) -> ITreeNode {
        // Base case: leaf node
        if data.len() <= 1 || depth >= max_depth {
            return ITreeNode::Leaf { size: data.len() };
        }

        // Try to find a feature with non-zero range
        let mut attempts = 0;
        loop {
            let feature = rng.gen_range(0..n_features);

            let min_val = data
                .iter()
                .map(|row| row[feature])
                .fold(f64::INFINITY, f64::min);
            let max_val = data
                .iter()
                .map(|row| row[feature])
                .fold(f64::NEG_INFINITY, f64::max);

            if (max_val - min_val).abs() < f64::EPSILON {
                attempts += 1;
                if attempts >= n_features * 2 {
                    // All features are constant — return leaf
                    return ITreeNode::Leaf { size: data.len() };
                }
                continue;
            }

            // Random split point between min and max
            let threshold = rng.gen_range(min_val..max_val);

            // Partition data
            let (left_data, right_data): (Vec<&[f64]>, Vec<&[f64]>) =
                data.iter().partition(|row| row[feature] < threshold);

            // Avoid degenerate splits
            if left_data.is_empty() || right_data.is_empty() {
                attempts += 1;
                if attempts >= n_features * 2 {
                    return ITreeNode::Leaf { size: data.len() };
                }
                continue;
            }

            let left = Self::build_tree(&left_data, depth + 1, max_depth, n_features, rng);
            let right = Self::build_tree(&right_data, depth + 1, max_depth, n_features, rng);

            return ITreeNode::Split {
                feature,
                threshold,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
    }

    /// Compute the path length for a single point in a single tree.
    fn path_length(node: &ITreeNode, point: &[f64], depth: usize) -> f64 {
        match node {
            ITreeNode::Leaf { size } => {
                // Add the expected path length for the remaining samples
                depth as f64 + c_factor(*size)
            }
            ITreeNode::Split {
                feature,
                threshold,
                left,
                right,
            } => {
                if point[*feature] < *threshold {
                    Self::path_length(left, point, depth + 1)
                } else {
                    Self::path_length(right, point, depth + 1)
                }
            }
        }
    }

    /// Score a raw (already-normalized) feature vector.
    ///
    /// This is the internal scoring function that does NOT apply normalization.
    /// Used during training when data is already normalized.
    fn score_raw(&self, point: &[f64]) -> f64 {
        if point.len() != self.n_features {
            return 0.5;
        }

        let avg_path_length: f64 = self
            .trees
            .iter()
            .map(|tree| Self::path_length(&tree.root, point, 0))
            .sum::<f64>()
            / self.trees.len() as f64;

        let c = c_factor(self.config.subsample_size);
        if c == 0.0 {
            return 0.5;
        }

        // Anomaly score: s(x, n) = 2^(-E(h(x)) / c(n))
        let exponent = -avg_path_length / c;
        2.0_f64.powf(exponent)
    }

    /// Compute the anomaly score for a single data point.
    ///
    /// Applies z-score normalization (if enabled) before scoring.
    ///
    /// Returns a score in [0, 1]:
    /// - Score close to 1.0 → anomaly
    /// - Score close to 0.5 → normal
    /// - Score close to 0.0 → very normal (dense region)
    pub fn score(&self, point: &[f64]) -> f64 {
        if point.len() != self.n_features {
            return 0.5; // Neutral score for invalid input
        }

        if let Some(ref params) = self.norm_params {
            let mut normalized = point.to_vec();
            params.normalize(&mut normalized);
            self.score_raw(&normalized)
        } else {
            self.score_raw(point)
        }
    }

    /// Predict whether a point is anomalous.
    ///
    /// Returns `true` if the anomaly score exceeds the configured threshold.
    pub fn is_anomaly(&self, point: &[f64]) -> bool {
        self.score(point) > self.config.threshold
    }

    /// Get the configured threshold.
    pub fn threshold(&self) -> f64 {
        self.config.threshold
    }

    /// Get the number of features this model expects.
    pub fn n_features(&self) -> usize {
        self.n_features
    }

    /// Get the number of trees in the forest.
    pub fn n_trees(&self) -> usize {
        self.trees.len()
    }

    /// Get the training score distribution (for confidence calibration).
    pub fn score_distribution(&self) -> Option<&ScoreDistribution> {
        self.score_distribution.as_ref()
    }

    /// Get the model quality metrics.
    pub fn metrics(&self) -> Option<&ModelMetrics> {
        self.metrics.as_ref()
    }

    /// Save the model to a file using postcard serialization.
    pub fn save_to_file(&self, path: &str) -> Result<(), String> {
        let encoded =
            postcard::to_stdvec(self).map_err(|e| format!("Serialization error: {}", e))?;

        let mut file = std::fs::File::create(path)
            .map_err(|e| format!("Failed to create file '{}': {}", path, e))?;

        file.write_all(MODEL_FILE_MAGIC)
            .and_then(|()| file.write_all(&encoded))
            .map_err(|e| format!("Failed to write model to '{}': {}", path, e))?;

        Ok(())
    }

    /// Load a model from a file.
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let mut file = std::fs::File::open(path)
            .map_err(|e| format!("Failed to open file '{}': {}", path, e))?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| format!("Failed to read file '{}': {}", path, e))?;

        let encoded = buffer
            .strip_prefix(MODEL_FILE_MAGIC)
            .ok_or_else(|| format!("'{}' is not a model file in the current format", path))?;

        let model: Self =
            postcard::from_bytes(encoded).map_err(|e| format!("Deserialization error: {}", e))?;

        Ok(model)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_factor() {
        assert_eq!(c_factor(0), 0.0);
        assert_eq!(c_factor(1), 0.0);
        assert!(c_factor(256) > 0.0);
        assert!(c_factor(256) < 20.0);
    }

    #[test]
    fn test_basic_anomaly_detection() {
        // Generate normal data: clustered around (5, 5)
        let mut data: Vec<Vec<f64>> = Vec::new();
        let mut rng = StdRng::seed_from_u64(42);

        for _ in 0..200 {
            data.push(vec![rng.gen_range(4.0..6.0), rng.gen_range(4.0..6.0)]);
        }

        let config = IsolationForestConfig {
            n_trees: 50,
            subsample_size: 128,
            threshold: 0.55,
            seed: Some(42),
            ..Default::default()
        };

        let forest = IsolationForest::fit(&data, config).unwrap();

        // Normal point should have low anomaly score
        let normal_score = forest.score(&[5.0, 5.0]);
        assert!(
            normal_score < 0.55,
            "Normal point score {} should be < 0.55",
            normal_score
        );

        // Anomalous point (far from cluster) should have high score
        let anomaly_score = forest.score(&[100.0, 100.0]);
        assert!(
            anomaly_score > 0.5,
            "Anomaly point score {} should be > 0.5",
            anomaly_score
        );
    }

    #[test]
    fn test_save_load_model() {
        let data: Vec<Vec<f64>> = (0..100)
            .map(|i| vec![i as f64, (i * 2) as f64])
            .collect();

        let config = IsolationForestConfig {
            n_trees: 10,
            subsample_size: 50,
            seed: Some(123),
            ..Default::default()
        };

        let forest = IsolationForest::fit(&data, config).unwrap();
        let test_point = vec![50.0, 100.0];
        let original_score = forest.score(&test_point);

        // Save and reload
        let tmp_path = "/tmp/test_iforest_model_v2.bin";
        forest.save_to_file(tmp_path).unwrap();
        let loaded = IsolationForest::load_from_file(tmp_path).unwrap();
        let loaded_score = loaded.score(&test_point);

        assert!(
            (original_score - loaded_score).abs() < f64::EPSILON,
            "Scores should be identical after save/load"
        );

        // Cleanup
        let _ = std::fs::remove_file(tmp_path);
    }

    #[test]
    fn test_load_rejects_file_in_old_format() {
        let path = std::env::temp_dir().join(format!("iforest-old-{}.bin", std::process::id()));
        std::fs::write(&path, [0u8; 64]).unwrap();
        let result = IsolationForest::load_from_file(path.to_str().unwrap());
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err(), "A file without the magic header must not load");
    }

    #[test]
    fn test_normalization_improves_detection() {
        // Create data with very different scales:
        // Feature 0: small range (0-1), Feature 1: large range (0-10000)
        let mut data: Vec<Vec<f64>> = Vec::new();
        let mut rng = StdRng::seed_from_u64(99);

        for _ in 0..300 {
            data.push(vec![
                rng.gen_range(0.4..0.6),
                rng.gen_range(4000.0..6000.0),
            ]);
        }

        // With normalization
        let config_norm = IsolationForestConfig {
            n_trees: 100,
            subsample_size: 128,
            seed: Some(99),
            normalize_features: true,
            ..Default::default()
        };
        let forest_norm = IsolationForest::fit(&data, config_norm).unwrap();

        // Without normalization
        let config_raw = IsolationForestConfig {
            n_trees: 100,
            subsample_size: 128,
            seed: Some(99),
            normalize_features: false,
            ..Default::default()
        };
        let forest_raw = IsolationForest::fit(&data, config_raw).unwrap();

        // An anomaly in the small-scale feature should be detected by both,
        // but normalization should give a higher score for it
        let anomaly_small_feature = vec![10.0, 5000.0]; // Feature 0 is way off
        let score_norm = forest_norm.score(&anomaly_small_feature);
        let score_raw = forest_raw.score(&anomaly_small_feature);

        assert!(
            score_norm > 0.5,
            "Normalized model should detect small-feature anomaly (score={})",
            score_norm
        );
        // The raw model might miss it because feature 1's range dominates
        // We just verify the normalized model detects it
        assert!(
            score_norm >= score_raw,
            "Normalized score ({}) should be >= raw score ({})",
            score_norm,
            score_raw
        );
    }

    #[test]
    fn test_score_distribution_stored() {
        let data: Vec<Vec<f64>> = (0..200)
            .map(|i| vec![i as f64, (i * 3) as f64])
            .collect();

        let config = IsolationForestConfig {
            n_trees: 20,
            subsample_size: 100,
            seed: Some(42),
            ..Default::default()
        };

        let forest = IsolationForest::fit(&data, config).unwrap();

        let dist = forest.score_distribution().expect("Distribution should be stored");
        assert!(dist.min <= dist.p5);
        assert!(dist.p5 <= dist.p25);
        assert!(dist.p25 <= dist.p50);
        assert!(dist.p50 <= dist.p75);
        assert!(dist.p75 <= dist.p95);
        assert!(dist.p95 <= dist.p99);
        assert!(dist.p99 <= dist.max);
    }

    #[test]
    fn test_model_metrics_stored() {
        let data: Vec<Vec<f64>> = (0..200)
            .map(|i| vec![i as f64, (i * 2) as f64, (i % 10) as f64])
            .collect();

        let config = IsolationForestConfig {
            n_trees: 20,
            subsample_size: 100,
            seed: Some(42),
            ..Default::default()
        };

        let forest = IsolationForest::fit(&data, config).unwrap();

        let metrics = forest.metrics().expect("Metrics should be stored");
        assert_eq!(metrics.training_samples, 200);
        assert!(metrics.total_nodes > 0);
        assert_eq!(metrics.feature_split_counts.len(), 3);
        assert!(metrics.anomaly_rate_pct >= 0.0 && metrics.anomaly_rate_pct <= 100.0);
        // With adaptive threshold at p95, anomaly rate should be ~5%
        assert!(
            metrics.anomaly_rate_pct < 15.0,
            "Anomaly rate {:.1}% should be reasonable",
            metrics.anomaly_rate_pct
        );
    }

    #[test]
    fn test_confidence_calibration() {
        let dist = ScoreDistribution {
            p5: 0.30,
            p25: 0.38,
            p50: 0.42,
            p75: 0.48,
            p95: 0.55,
            p99: 0.65,
            min: 0.25,
            max: 0.72,
        };
        let threshold = 0.55;

        // Normal confidence: score well below threshold → high confidence
        let conf_very_normal = dist.confidence_normal(0.30, threshold);
        assert!(
            conf_very_normal > 0.9,
            "Very normal should have high confidence: {}",
            conf_very_normal
        );

        // Normal confidence: score near threshold → low confidence
        let conf_borderline = dist.confidence_normal(0.54, threshold);
        assert!(
            conf_borderline < 0.1,
            "Borderline normal should have low confidence: {}",
            conf_borderline
        );

        // Anomalous confidence: score well above threshold → high confidence
        let conf_very_anomalous = dist.confidence_anomalous(0.65, threshold);
        assert!(
            conf_very_anomalous > 0.9,
            "Very anomalous should have high confidence: {}",
            conf_very_anomalous
        );

        // Anomalous confidence: score just above threshold → low confidence
        let conf_borderline_anom = dist.confidence_anomalous(0.56, threshold);
        assert!(
            conf_borderline_anom < 0.2,
            "Borderline anomalous should have low confidence: {}",
            conf_borderline_anom
        );
    }
}
