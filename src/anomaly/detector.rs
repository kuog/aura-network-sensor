//! Anomaly Detector — High-level orchestrator for the Isolation Forest pipeline.
//!
//! Manages the lifecycle of the ML model: training from the SQLite database,
//! predicting anomaly scores for new flows, and persisting/loading the model.

use log::{info, warn};
use rusqlite::Connection;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use super::db;
use super::flow_tracker::FlowTracker;
use super::isolation_forest::{IsolationForest, IsolationForestConfig};
use super::types::{AnomalyResult, DetectorPhase, FlowMetrics};

/// Default number of training samples to load from the database.
const DEFAULT_TRAINING_SAMPLES: usize = 10_000;

/// Minimum number of samples required to train a meaningful model.
const MIN_TRAINING_SAMPLES: usize = 50;

/// Default model file path.
const DEFAULT_MODEL_PATH: &str = "anomaly_model.bin";

/// The AnomalyDetector manages the full ML pipeline:
/// - Collects flow data during the learning phase
/// - Trains the Isolation Forest model
/// - Scores new flows during the inference phase
/// - Persists and loads the model
pub struct AnomalyDetector {
    /// The trained Isolation Forest model (None during learning phase).
    model: RwLock<Option<IsolationForest>>,
    /// Current operational phase.
    phase: RwLock<DetectorPhase>,
    /// When the detector was started.
    start_time: Instant,
    /// Duration of the learning phase.
    learning_duration: Duration,
    /// Whether training has been triggered.
    training_triggered: AtomicBool,
    /// Path to the model file.
    model_path: String,
    /// Isolation Forest configuration.
    config: IsolationForestConfig,
    /// Number of training samples to use.
    training_samples: usize,
}

impl AnomalyDetector {
    /// Create a new AnomalyDetector.
    ///
    /// # Arguments
    /// * `learning_minutes` — Duration of the learning phase in minutes.
    /// * `model_path` — Optional path to save/load the model file.
    pub fn new(learning_minutes: u64, model_path: Option<String>) -> Self {
        let model_path = model_path.unwrap_or_else(|| DEFAULT_MODEL_PATH.to_string());

        Self {
            model: RwLock::new(None),
            phase: RwLock::new(DetectorPhase::Learning),
            start_time: Instant::now(),
            learning_duration: Duration::from_secs(learning_minutes * 60),
            training_triggered: AtomicBool::new(false),
            model_path,
            config: IsolationForestConfig::default(),
            training_samples: DEFAULT_TRAINING_SAMPLES,
        }
    }

    /// Create a shared (Arc-wrapped) AnomalyDetector.
    pub fn shared(learning_minutes: u64, model_path: Option<String>) -> Arc<Self> {
        Arc::new(Self::new(learning_minutes, model_path))
    }

    /// Try to load a previously saved model.
    ///
    /// If successful, transitions directly to Inference phase.
    /// Returns `true` if a model was loaded.
    ///
    /// If the loaded model has a different number of features than expected
    /// (e.g., after a feature expansion upgrade), the model is discarded and
    /// the old file is removed so a fresh model will be trained.
    pub fn try_load_model(&self) -> bool {
        if !Path::new(&self.model_path).exists() {
            return false;
        }

        match IsolationForest::load_from_file(&self.model_path) {
            Ok(forest) => {
                // Validate feature count matches current FlowMetrics
                if forest.n_features() != FlowMetrics::FEATURE_COUNT {
                    warn!(
                        "[AnomalyDetector] Model from '{}' has {} features, but current FlowMetrics has {}. \
                         Discarding incompatible model — will retrain.",
                        self.model_path,
                        forest.n_features(),
                        FlowMetrics::FEATURE_COUNT
                    );
                    // Remove the incompatible model file
                    if let Err(e) = std::fs::remove_file(&self.model_path) {
                        warn!("[AnomalyDetector] Failed to remove old model file: {}", e);
                    }
                    return false;
                }

                info!(
                    "[AnomalyDetector] Loaded pre-trained model from '{}' ({} trees, {} features)",
                    self.model_path,
                    forest.n_trees(),
                    forest.n_features()
                );
                *self.model.write().unwrap() = Some(forest);
                *self.phase.write().unwrap() = DetectorPhase::Inference;
                self.training_triggered.store(true, Ordering::SeqCst);
                true
            }
            Err(e) => {
                warn!(
                    "[AnomalyDetector] Failed to load model from '{}': {}",
                    self.model_path, e
                );
                false
            }
        }
    }

    /// Get the current phase.
    pub fn phase(&self) -> DetectorPhase {
        *self.phase.read().unwrap()
    }

    /// Check if the learning phase has elapsed and training should begin.
    ///
    /// Returns `true` if training should be triggered now.
    pub fn should_train(&self) -> bool {
        if self.training_triggered.load(Ordering::SeqCst) {
            return false;
        }

        let elapsed = self.start_time.elapsed();
        elapsed >= self.learning_duration
    }

    /// Train the Isolation Forest model from the database.
    ///
    /// This is a blocking operation that should be called from a background thread.
    /// It loads recent flow features from the database, builds the feature matrix,
    /// and trains the model.
    ///
    /// # Arguments
    /// * `db_conn` — SQLite connection to the features database.
    pub fn train(&self, db_conn: &Connection) -> Result<(), String> {
        // Mark training as triggered (prevent re-entry)
        if self
            .training_triggered
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("Training already triggered".to_string());
        }

        *self.phase.write().unwrap() = DetectorPhase::Training;
        info!("[AnomalyDetector] Starting model training...");

        // Load features from database
        let flows = db::load_recent_features(db_conn, self.training_samples)
            .map_err(|e| format!("Failed to load features: {}", e))?;

        if flows.len() < MIN_TRAINING_SAMPLES {
            *self.phase.write().unwrap() = DetectorPhase::Learning;
            self.training_triggered.store(false, Ordering::SeqCst);
            return Err(format!(
                "Insufficient training data: {} samples (need at least {})",
                flows.len(),
                MIN_TRAINING_SAMPLES
            ));
        }

        info!(
            "[AnomalyDetector] Training with {} flow samples ({} features each)",
            flows.len(),
            FlowMetrics::FEATURE_COUNT
        );

        // Build feature matrix
        let data: Vec<Vec<f64>> = flows
            .iter()
            .map(|f| f.to_feature_vector().to_vec())
            .collect();

        // Train the model
        let forest = IsolationForest::fit(&data, self.config.clone())
            .map_err(|e| format!("Training failed: {}", e))?;

        info!(
            "[AnomalyDetector] Model trained: {} trees, threshold={:.2}",
            forest.n_trees(),
            forest.threshold()
        );

        // Save model to disk
        if let Err(e) = forest.save_to_file(&self.model_path) {
            warn!("[AnomalyDetector] Failed to save model: {}", e);
        } else {
            info!(
                "[AnomalyDetector] Model saved to '{}'",
                self.model_path
            );
        }

        // Activate the model
        *self.model.write().unwrap() = Some(forest);
        *self.phase.write().unwrap() = DetectorPhase::Inference;

        info!("[AnomalyDetector] Transitioned to INFERENCE phase");
        Ok(())
    }

    /// Predict the anomaly score for a flow.
    ///
    /// Returns `None` if the model is not yet trained (learning phase).
    /// Returns `Some(AnomalyResult)` with the anomaly score and classification.
    pub fn predict(&self, flow: &FlowMetrics) -> Option<AnomalyResult> {
        let model_guard = self.model.read().unwrap();
        let model = model_guard.as_ref()?;

        let features = flow.to_feature_vector();
        let score = model.score(&features);
        let is_normal = score <= model.threshold();

        // Confidence: how far the score is from the threshold.
        // Amplified by 5× (was 2×) for better separation with 12-feature model.
        // A distance of 0.10 from threshold → confidence 0.50
        // A distance of 0.20 from threshold → confidence 1.00
        let distance = (score - model.threshold()).abs();
        let confidence = (distance * 5.0).min(1.0);

        Some(AnomalyResult {
            anomaly_score: score,
            is_normal,
            confidence,
        })
    }

    /// Get uptime since the detector was started.
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Get the remaining learning time (0 if learning phase is over).
    pub fn remaining_learning_time(&self) -> Duration {
        let elapsed = self.start_time.elapsed();
        self.learning_duration.saturating_sub(elapsed)
    }

    /// Check if the model is ready for inference.
    pub fn is_ready(&self) -> bool {
        self.model.read().unwrap().is_some()
    }
}

/// Background task that periodically flushes completed flows to the database
/// and triggers model training when the learning phase ends.
///
/// This function is designed to be spawned as a tokio task.
///
/// # Arguments
/// * `detector` — Shared anomaly detector instance.
/// * `flow_tracker` — Shared flow tracker for aggregating packets.
/// * `db_path` — Path to the features database.
/// * `running` — Shared shutdown flag.
/// * `flush_interval_secs` — How often to flush completed flows (default: 5s).
pub async fn background_flush_task(
    detector: Arc<AnomalyDetector>,
    flow_tracker: Arc<FlowTracker>,
    db_path: String,
    running: Arc<AtomicBool>,
    flush_interval_secs: u64,
) {
    let flush_interval = Duration::from_secs(flush_interval_secs);

    // Open a dedicated DB connection for this task
    let conn = match db::init_anomaly_db(&db_path) {
        Ok(c) => c,
        Err(e) => {
            warn!(
                "[AnomalyDetector] Failed to open features DB '{}': {}. Flow tracking disabled.",
                db_path, e
            );
            return;
        }
    };

    info!(
        "[AnomalyDetector] Background flush task started (interval: {}s, learning: {}s)",
        flush_interval_secs,
        detector.remaining_learning_time().as_secs()
    );

    let mut total_flushed: u64 = 0;

    loop {
        tokio::time::sleep(flush_interval).await;

        if !running.load(Ordering::Relaxed) {
            break;
        }

        // Flush completed flows to database
        let completed = flow_tracker.flush_completed();
        if !completed.is_empty() {
            match db::insert_flows_batch(&conn, &completed) {
                Ok(count) => {
                    total_flushed += count as u64;
                    log::debug!(
                        "[AnomalyDetector] Flushed {} flows to DB (total: {})",
                        count,
                        total_flushed
                    );
                }
                Err(e) => {
                    warn!("[AnomalyDetector] Failed to flush flows: {}", e);
                }
            }
        }

        // Check if we should trigger training
        if detector.should_train() {
            info!(
                "[AnomalyDetector] Learning phase complete ({} flows collected). Starting training...",
                total_flushed
            );

            // Train in a blocking task to avoid blocking the tokio runtime
            let detector_clone = detector.clone();
            let db_path_clone = db_path.clone();
            let train_result = tokio::task::spawn_blocking(move || {
                // Open a fresh connection for training (SQLite connections are not Send)
                let train_conn = match db::init_anomaly_db(&db_path_clone) {
                    Ok(c) => c,
                    Err(e) => return Err(format!("Failed to open DB for training: {}", e)),
                };
                detector_clone.train(&train_conn)
            })
            .await;

            match train_result {
                Ok(Ok(())) => {
                    info!("[AnomalyDetector] Model training completed successfully");
                }
                Ok(Err(e)) => {
                    warn!("[AnomalyDetector] Model training failed: {}", e);
                }
                Err(e) => {
                    warn!("[AnomalyDetector] Training task panicked: {}", e);
                }
            }
        }
    }

    // Final flush at shutdown
    let remaining = flow_tracker.flush_all();
    if !remaining.is_empty() {
        match db::insert_flows_batch(&conn, &remaining) {
            Ok(count) => {
                total_flushed += count as u64;
                info!(
                    "[AnomalyDetector] Final flush: {} flows (total: {})",
                    count, total_flushed
                );
            }
            Err(e) => {
                warn!("[AnomalyDetector] Final flush failed: {}", e);
            }
        }
    }

    // WAL checkpoint
    if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
        warn!("[AnomalyDetector] WAL checkpoint failed: {}", e);
    }

    info!(
        "[AnomalyDetector] Background task stopped. Total flows persisted: {}",
        total_flushed
    );
}
