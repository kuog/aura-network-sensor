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
//! ## References
//!
//! - Liu, Ting, Zhou (2008): "Isolation Forest"
//! - Liu, Ting, Zhou (2012): "Isolation-Based Anomaly Detection"

use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

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
        }
    }
}

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

/// The Isolation Forest model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationForest {
    /// The ensemble of isolation trees.
    trees: Vec<ITree>,
    /// Configuration used to build this forest.
    config: IsolationForestConfig,
    /// Number of features (dimensions) in the training data.
    n_features: usize,
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

        let max_depth = config
            .max_depth
            .unwrap_or_else(|| (config.subsample_size as f64).log2().ceil() as usize);

        let mut rng: Box<dyn RngCore> = if let Some(seed) = config.seed {
            Box::new(StdRng::seed_from_u64(seed))
        } else {
            Box::new(thread_rng())
        };

        let subsample_size = config.subsample_size.min(data.len());

        let mut trees = Vec::with_capacity(config.n_trees);
        for _ in 0..config.n_trees {
            // Random subsample (without replacement)
            let indices: Vec<usize> = {
                let mut all: Vec<usize> = (0..data.len()).collect();
                all.shuffle(&mut rng);
                all.truncate(subsample_size);
                all
            };

            let subsample: Vec<&[f64]> = indices.iter().map(|&i| data[i].as_slice()).collect();

            let root = Self::build_tree(&subsample, 0, max_depth, n_features, &mut rng);
            trees.push(ITree { root });
        }

        let mut model = Self {
            trees,
            config,
            n_features,
        };

        // ── Adaptive threshold calibration ─────────────────────────────
        // Score every training sample and pick the percentile-th score as
        // the threshold.  This guarantees that ≈percentile% of the traffic
        // observed during the learning phase is classified as NORMAL.
        if model.config.adaptive_threshold {
            let mut scores: Vec<f64> = data.iter().map(|row| model.score(row)).collect();
            scores.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

            let idx = ((scores.len() as f64 * model.config.threshold_percentile).ceil() as usize)
                .min(scores.len().saturating_sub(1));
            let adaptive = scores[idx];

            log::info!(
                "[IsolationForest] Adaptive threshold calibrated: {:.4} \
                 (percentile={:.0}%, training_samples={}, static_fallback={:.2})",
                adaptive,
                model.config.threshold_percentile * 100.0,
                scores.len(),
                model.config.threshold,
            );

            model.config.threshold = adaptive;
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

    /// Compute the anomaly score for a single data point.
    ///
    /// Returns a score in [0, 1]:
    /// - Score close to 1.0 → anomaly
    /// - Score close to 0.5 → normal
    /// - Score close to 0.0 → very normal (dense region)
    pub fn score(&self, point: &[f64]) -> f64 {
        if point.len() != self.n_features {
            return 0.5; // Neutral score for invalid input
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
        // Where E(h(x)) is the average path length
        let exponent = -avg_path_length / c;
        2.0_f64.powf(exponent)
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

    /// Save the model to a file using bincode serialization.
    pub fn save_to_file(&self, path: &str) -> Result<(), String> {
        let encoded = bincode::serialize(self).map_err(|e| format!("Serialization error: {}", e))?;

        let mut file = std::fs::File::create(path)
            .map_err(|e| format!("Failed to create file '{}': {}", path, e))?;

        file.write_all(&encoded)
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

        let model: Self =
            bincode::deserialize(&buffer).map_err(|e| format!("Deserialization error: {}", e))?;

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
            data.push(vec![
                rng.gen_range(4.0..6.0),
                rng.gen_range(4.0..6.0),
            ]);
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
            normal_score < 0.5,
            "Normal point score {} should be < 0.5",
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
        let tmp_path = "/tmp/test_iforest_model.bin";
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
}
