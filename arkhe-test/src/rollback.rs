use std::collections::HashSet;
use arkhe_mobile_mmr::StrongBoxStorage;
use arkhe_mobile_verify::OfflineVerificationBundle;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum RollbackError {
    #[error("Violation of invariant I-T05: rollback attempted to mutate or truncate MMR storage")]
    MmrRewriteForbidden,
    #[error("Violation of invariant I-T05: rollback destroyed or altered past checkpoints")]
    CheckpointMutationForbidden,
    #[error("Violation of invariant I-T05: existing offline bundle invalidated after rollback")]
    EvidenceInvalidated,
    #[error("Invalid target for rollback: {0}")]
    DisallowedTarget(String),
}

/// Invariant I-T05: Rollback seguro
/// Qualquer release pode voltar à última versão íntegra sem corromper MMR, recibos ou checkpoints.
/// rollback => evidência existente intacta
pub struct RollbackManager {
    allowed_targets: HashSet<String>,
    disallowed_targets: HashSet<String>,
}

impl Default for RollbackManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RollbackManager {
    pub fn new() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert("executable_binary".to_string());
        allowed.insert("runtime_configuration".to_string());
        allowed.insert("feature_flags".to_string());
        allowed.insert("network_endpoints".to_string());

        let mut disallowed = HashSet::new();
        disallowed.insert("mmr_storage".to_string());
        disallowed.insert("receipt_log".to_string());
        disallowed.insert("local_checkpoints".to_string());
        disallowed.insert("attestation_records".to_string());
        disallowed.insert("audit_bundles".to_string());

        Self {
            allowed_targets: allowed,
            disallowed_targets: disallowed,
        }
    }

    /// Verifies if a rollback target is permissible under I-T05
    pub fn verify_target(&self, target: &str) -> Result<(), RollbackError> {
        if self.disallowed_targets.contains(target) {
            return Err(RollbackError::DisallowedTarget(target.to_string()));
        }
        if !self.allowed_targets.contains(target) {
            return Err(RollbackError::DisallowedTarget(target.to_string()));
        }
        Ok(())
    }

    /// Validates state preservation during a simulated code/config rollback:
    /// Prior MMR state, checkpoints, and offline verification bundles must remain strictly valid and intact.
    pub fn verify_rollback_preservation(
        &self,
        pre_rollback_storage: &StrongBoxStorage,
        post_rollback_storage: &StrongBoxStorage,
        historical_bundles: &[OfflineVerificationBundle],
    ) -> Result<(), RollbackError> {
        if post_rollback_storage.mmr.leaf_count() < pre_rollback_storage.mmr.leaf_count() {
            return Err(RollbackError::MmrRewriteForbidden);
        }

        if pre_rollback_storage.mmr.compute_bagged_root() != post_rollback_storage.mmr.compute_bagged_root() {
            return Err(RollbackError::MmrRewriteForbidden);
        }

        if post_rollback_storage.checkpoints.len() < pre_rollback_storage.checkpoints.len() {
            return Err(RollbackError::CheckpointMutationForbidden);
        }

        for (i, cp_pre) in pre_rollback_storage.checkpoints.iter().enumerate() {
            let cp_post = &post_rollback_storage.checkpoints[i];
            if cp_pre != cp_post {
                return Err(RollbackError::CheckpointMutationForbidden);
            }
        }

        for bundle in historical_bundles {
            match arkhe_mobile_verify::OfflineVerifier::verify_bundle(bundle) {
                Ok(true) => (),
                _ => return Err(RollbackError::EvidenceInvalidated),
            }
        }

        Ok(())
    }
}
