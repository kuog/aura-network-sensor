//! AI-driven Anomaly Detection Module
//!
//! This module implements an Isolation Forest-based anomaly detection system
//! for automatic false-positive suppression and behavioral anomaly detection.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
//! │ FlowTracker  │────▶│  SQLite DB   │────▶│  Isolation   │
//! │ (DashMap)    │     │ (features)   │     │  Forest      │
//! └──────────────┘     └──────────────┘     └──────────────┘
//!       ▲                                         │
//!       │ packets                                 │ anomaly_score
//!       │                                         ▼
//! ┌──────────────┐                          ┌──────────────┐
//! │   Engine     │                          │   Alert      │
//! │  (Stage 2)   │◀─────────────────────────│ Suppression  │
//! └──────────────┘                          └──────────────┘
//! ```
//!
//! ## Phases
//!
//! 1. **Learning Phase**: Collects flow features into SQLite, marks alerts as `[LEARNING MODE]`.
//! 2. **Inference Phase**: Trains the Isolation Forest model, then scores every new flow.

pub mod db;
pub mod detector;
pub mod flow_tracker;
pub mod isolation_forest;
pub mod types;
