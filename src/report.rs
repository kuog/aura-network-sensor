use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize, Default)]
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
}

#[derive(Serialize)]
pub struct AiHint {
    pub trigger: String,
    pub suspected_techniques: Vec<String>,
    pub logic: String,
}

#[derive(Serialize)]
pub struct Report {
    pub context: Context,
    pub telemetry: Telemetry,
    pub ai_hints: Vec<AiHint>,
}

impl Report {
    pub fn new(context: Context, telemetry: Telemetry, ai_hints: Vec<AiHint>) -> Self {
        Self {
            context,
            telemetry,
            ai_hints,
        }
    }
}
