use serde::{Deserialize, Serialize};
use arkhe_core::{digest, digest_all, Digest32};

pub const MOBILE_WER_DOMAIN: &[u8] = b"AKG:MOBILE:ACT:v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MobileAction {
    Inference {
        model_weights_hash: [u8; 32],
        temperature_e2: u32,
    },
    ToolInvocation {
        tool_name: String,
        params_hash: [u8; 32],
    },
    PolicyEvaluation {
        policy_id: String,
    },
    StateTransition {
        from_state: String,
        to_state: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TitanM2Attestation {
    pub attestation_blob: Vec<u8>,
    pub first_wer_nonce: [u8; 32],
    pub app_measurement: Digest32,
}

impl TitanM2Attestation {
    pub fn new(attestation_blob: Vec<u8>, first_wer_nonce: [u8; 32], app_measurement: Digest32) -> Self {
        Self {
            attestation_blob,
            first_wer_nonce,
            app_measurement,
        }
    }

    pub fn compute_binding_hash(&self) -> Digest32 {
        digest_all(&[
            self.attestation_blob.as_slice(),
            &self.first_wer_nonce[..],
            &self.app_measurement[..],
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileWER {
    pub version: u8,
    pub device_attestation_hash: Digest32,
    pub app_id: Digest32,
    pub action: MobileAction,
    pub input_digest: Digest32,
    pub output_digest: Digest32,
    pub policy_digest: Digest32,
    pub performed_at: u64,
    pub evidence_refs: Vec<Digest32>,
}

impl MobileWER {
    pub fn compute_record_hash(&self) -> Result<Digest32, String> {
        let serialized = serde_json::to_vec(self)
            .map_err(|e| format!("Failed to serialize MobileWER: {}", e))?;
        let mut data = Vec::with_capacity(MOBILE_WER_DOMAIN.len() + serialized.len());
        data.extend_from_slice(MOBILE_WER_DOMAIN);
        data.extend_from_slice(&serialized);
        Ok(digest(&data))
    }
}
