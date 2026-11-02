use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestStageResult {
    pub stage_name: String,
    pub passed: bool,
    pub tests_executed: usize,
    pub tests_failed: usize,
    pub duration_ms: u64,
    pub invariant_coverage: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PipelineExecutionReport {
    pub commit_hash: String,
    pub timestamp: u64,
    pub stages: Vec<TestStageResult>,
    pub overall_success: bool,
}

pub struct TestPipeline;

impl TestPipeline {
    pub fn stage_1_fast_feedback_invariants() -> Vec<&'static str> {
        vec!["I-01", "I-02", "I-03", "I-04", "I-T06"]
    }

    pub fn stage_2_integration_invariants() -> Vec<&'static str> {
        vec!["I-05", "I-06", "I-09", "I-T04", "I-T05"]
    }

    pub fn stage_3_adversarial_invariants() -> Vec<&'static str> {
        vec!["I-07", "I-08", "I-10", "I-T02", "I-T08"]
    }
}
