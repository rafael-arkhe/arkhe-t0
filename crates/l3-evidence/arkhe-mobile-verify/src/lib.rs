use serde::{Deserialize, Serialize};
use arkhe_afir::{AfirReceipt, AfirVerifier};
use arkhe_mobile_mmr::{LocalCheckpoint, MmrProof};
use arkhe_mobile_wer::MobileWER;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineVerificationBundle {
    pub wer: MobileWER,
    pub proof: MmrProof,
    pub checkpoint: LocalCheckpoint,
    pub afir_receipt: Option<AfirReceipt>,
}

impl OfflineVerificationBundle {
    pub fn new(
        wer: MobileWER,
        proof: MmrProof,
        checkpoint: LocalCheckpoint,
        afir_receipt: Option<AfirReceipt>,
    ) -> Self {
        Self {
            wer,
            proof,
            checkpoint,
            afir_receipt,
        }
    }
}

pub struct OfflineVerifier;

impl OfflineVerifier {
    pub fn verify_bundle(bundle: &OfflineVerificationBundle) -> Result<bool, String> {
        let expected_hash = bundle.wer.compute_record_hash()?;

        if bundle.proof.leaf_index >= bundle.proof.leaf_count {
            return Ok(false);
        }

        if bundle.proof.bagged_root != bundle.checkpoint.bagged_root {
            return Ok(false);
        }

        let mldsa_ok = !bundle.checkpoint.envelope.strongbox_mldsa_sig.0.is_empty();
        let ed25519_ok = !bundle.checkpoint.envelope.tee_ed25519_sig.0.is_empty();
        if !mldsa_ok || !ed25519_ok {
            return Ok(false);
        }

        if let Some(ref receipt) = bundle.afir_receipt {
            if !AfirVerifier::verify_receipt(receipt) {
                return Ok(false);
            }
            if !bundle.wer.evidence_refs.contains(&receipt.inference_root) {
                return Ok(false);
            }
        }

        if expected_hash == [0u8; 32] {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn detect_history_rewrite(
        bundle_a: &OfflineVerificationBundle,
        bundle_b: &OfflineVerificationBundle,
    ) -> bool {
        if bundle_a.checkpoint.leaf_count == bundle_b.checkpoint.leaf_count
            && bundle_a.checkpoint.bagged_root != bundle_b.checkpoint.bagged_root
        {
            return true;
        }
        false
    }
}
