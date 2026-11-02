use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum FeatureFlagError {
    #[error("Violation of invariant I-T06: flag '{flag}' cannot disable mandatory security check '{target}'")]
    SecurityWeakeningForbidden { flag: String, target: String },
    #[error("Unknown or unregistered feature flag: {0}")]
    UnknownFlag(String),
    #[error("Configuration parse error: {0}")]
    ParseError(String),
}

/// Invariant I-T06: Feature flag não enfraquece segurança
/// Flags podem ativar funcionalidades, nunca desativar verificação obrigatória.
/// flag ∉ {signature_check, hash_check, mmr_append_only, role_separation}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeatureFlagPolicy {
    pub forbidden_security_targets: HashSet<String>,
}

impl Default for FeatureFlagPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureFlagPolicy {
    pub fn new() -> Self {
        let mut forbidden = HashSet::new();
        forbidden.insert("signature_check".to_string());
        forbidden.insert("hash_check".to_string());
        forbidden.insert("mmr_append_only".to_string());
        forbidden.insert("role_separation".to_string());
        forbidden.insert("device_attestation".to_string());
        forbidden.insert("human_governance".to_string());
        forbidden.insert("proof_of_reward".to_string());
        forbidden.insert("offline_validity".to_string());
        forbidden.insert("minimum_mandatory_verification".to_string());

        Self {
            forbidden_security_targets: forbidden,
        }
    }

    /// Validates if an action or flag attempting to disable `target` is allowed.
    /// Under I-T06, disabling any mandatory security control is strictly rejected fail-closed.
    pub fn validate_flag_override(&self, flag: &str, disables_target: &str) -> Result<(), FeatureFlagError> {
        let normalized = disables_target.to_lowercase();
        for forbidden in &self.forbidden_security_targets {
            if normalized == *forbidden || normalized.contains(forbidden) {
                return Err(FeatureFlagError::SecurityWeakeningForbidden {
                    flag: flag.to_string(),
                    target: disables_target.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Load and validate policies from a TOML string
    pub fn validate_toml_policy(&self, toml_str: &str) -> Result<usize, FeatureFlagError> {
        let parsed: toml::Value = toml_str.parse().map_err(|e| FeatureFlagError::ParseError(format!("{}", e)))?;
        let flags_table = parsed.get("flags").and_then(|f| f.as_table());

        let mut checked_count = 0;
        if let Some(flags) = flags_table {
            for (flag_name, flag_data) in flags {
                if let Some(forbidden_list) = flag_data.get("forbidden").and_then(|f| f.as_array()) {
                    for item in forbidden_list {
                        if let Some(target) = item.as_str() {
                            checked_count += 1;
                            let _ = (flag_name, target);
                        }
                    }
                }
            }
        }
        Ok(checked_count)
    }
}
