use serde::{Deserialize, Serialize};
use arkhe_core::Digest32;
use crate::signatures::{Ed25519Signature, MldsaSignature};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridCheckpointEnvelope {
    pub root_hash: Digest32,
    pub checkpoint_index: u64,
    pub timestamp: u64,
    pub strongbox_mldsa_sig: MldsaSignature,
    pub tee_ed25519_sig: Ed25519Signature,
}

impl HybridCheckpointEnvelope {
    pub fn new(
        root_hash: Digest32,
        checkpoint_index: u64,
        timestamp: u64,
        mldsa_sig: Vec<u8>,
        ed25519_sig: Vec<u8>,
    ) -> Self {
        Self {
            root_hash,
            checkpoint_index,
            timestamp,
            strongbox_mldsa_sig: MldsaSignature(mldsa_sig),
            tee_ed25519_sig: Ed25519Signature(ed25519_sig),
        }
    }
}
