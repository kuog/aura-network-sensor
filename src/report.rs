use serde::Serialize;
use std::collections::BTreeMap;
use crate::analysis::enrichment::EnrichedContext;

#[derive(Serialize, Default, Debug, Clone)]
pub struct Context {
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub fields: BTreeMap<String, String>,
}

#[derive(Serialize, Default)]
pub struct Telemetry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jitter: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3: Option<String>,
}

#[derive(Serialize)]
pub struct AiHint {
    pub trigger: String,
    pub suspected_techniques: Vec<String>,
    pub logic: String,
}

#[derive(Serialize)]
pub struct Report {
    pub severity: String,
    pub context: Context,
    pub telemetry: Telemetry,
    pub ai_hints: Vec<AiHint>,
    /// Confidence that this alert is a true positive (0 = likely benign, 100 = very suspicious).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_score: Option<u8>,
    /// Enriched context from TLS SNI inspection and reputation lookup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enriched_context: Option<EnrichedContext>,
    /// Human-readable notes explaining the confidence scoring decisions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scoring_notes: Option<Vec<String>>,
}

impl Report {
    /// Create a report without enrichment (backward-compatible).
    pub fn new(context: Context, telemetry: Telemetry, ai_hints: Vec<AiHint>) -> Self {
        Self {
            severity: "HIGH".to_string(),
            context,
            telemetry,
            ai_hints,
            confidence_score: None,
            enriched_context: None,
            scoring_notes: None,
        }
    }

    /// Create a report with enrichment data from the confidence scoring pipeline.
    pub fn new_enriched(
        context: Context,
        telemetry: Telemetry,
        ai_hints: Vec<AiHint>,
        confidence_score: u8,
        enriched_context: EnrichedContext,
        severity: String,
        scoring_notes: Vec<String>,
    ) -> Self {
        Self {
            severity,
            context,
            telemetry,
            ai_hints,
            confidence_score: Some(confidence_score),
            enriched_context: Some(enriched_context),
            scoring_notes: Some(scoring_notes),
        }
    }
}
