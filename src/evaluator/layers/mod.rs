pub mod correctness;
pub mod longitudinal_replay;
pub mod performance;
pub mod resource_efficiency;
pub mod security;
pub mod style;

pub use correctness::{CorrectnessEvaluation, CorrectnessLayer};
pub use longitudinal_replay::{
    DefectTestResult, LongitudinalReplayEvaluation, LongitudinalReplayLayer,
};
pub use performance::{PerformanceEvaluation, PerformanceLayer};
pub use resource_efficiency::{ResourceEfficiencyEvaluation, ResourceEfficiencyLayer};
pub use security::{SecurityEvaluation, SecurityLayer};
pub use style::{StyleEvaluation, StyleLayer};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LayerResult {
    pub layer_name: String,
    pub is_hard_invariant: bool,
    pub passed: bool,
    pub score: f64,
    pub summary: String,
    pub violations: Vec<String>,
}
