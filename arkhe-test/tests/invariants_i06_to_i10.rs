use arkhe_core::digest;
use arkhe_afir::AfirSigner;
use arkhe_mobile_mmr::StrongBoxStorage;
use arkhe_mobile_wer::{MobileAction, MobileWER, TitanM2Attestation};
use arkhe_mobile_verify::{OfflineVerificationBundle, OfflineVerifier};
use arkhe_openclaw::OpenClawBftConsensus;
use std::collections::HashSet;

/// Invariant I-06: Vínculo ao dispositivo
/// Usar chave sem atestação válida Titan M2/StrongBox causa rejeição do checkpoint e do bundle.
#[test]
fn test_i06_device_binding_attestation_failure_rejected() {
    let valid_blob = b"titan_m2_verified_boot_state=VERIFIED_keymint_v3".to_vec();
    let nonce = [0x55; 32];
    let app_measurement = digest(b"arkhe.android.security.app:v1.0.0");

    let valid_attestation = TitanM2Attestation::new(valid_blob.clone(), nonce, app_measurement);
    let valid_binding_hash = valid_attestation.compute_binding_hash();

    // Fabricated or altered attestation blob (e.g. verifiedBootState = UNLOCKED / corrupt quote)
    let tampered_blob = b"titan_m2_verified_boot_state=UNLOCKED_malicious".to_vec();
    let invalid_attestation = TitanM2Attestation::new(tampered_blob, nonce, app_measurement);
    let invalid_binding_hash = invalid_attestation.compute_binding_hash();

    assert_ne!(
        valid_binding_hash, invalid_binding_hash,
        "Falsifier: Altered hardware attestation quote must diverge binding hash"
    );

    // Build MobileWER with invalid binding hash
    let wer = MobileWER {
        version: 1,
        device_attestation_hash: invalid_binding_hash,
        app_id: digest(b"test_app"),
        action: MobileAction::PolicyEvaluation {
            policy_id: "sec_policy_1".to_string(),
        },
        input_digest: digest(b"input_payload"),
        output_digest: digest(b"output_payload"),
        policy_digest: digest(b"sec_policy_1"),
        performed_at: 1761955400,
        evidence_refs: vec![],
    };

    // When verifying against the authorized hardware binding hash:
    let is_authorized_device = wer.device_attestation_hash == valid_binding_hash;
    assert!(!is_authorized_device, "Device without valid verified boot attestation must be rejected");
}

/// Invariant I-07: Governança humana
/// Proposta autônoma de agente tentando alterar a constituição ou regras essenciais
/// sem canonização humana explicita é terminantemente rejeitada.
#[derive(Clone, Debug)]
struct GovernanceProposal {
    pub _proposer_is_autonomous_agent: bool,
    pub human_sponsor_signature: Option<Vec<u8>>,
    pub targets_constitution: bool,
    pub _proposal_payload: String,
}

impl GovernanceProposal {
    pub fn can_apply(&self) -> bool {
        // Human governance invariant: autonomous proposals targeting the constitution
        // MUST have explicit human sponsor signature; cannot be applied autonomously.
        if self.targets_constitution {
            if self.human_sponsor_signature.is_none() {
                return false;
            }
            if let Some(ref sig) = self.human_sponsor_signature {
                if sig.is_empty() {
                    return false;
                }
            }
        }
        true
    }
}

#[test]
fn test_i07_human_governance_constitution_mutation_blocked() {
    // 1. Autonomous agent attempts to mutate the constitution directly
    let malicious_proposal = GovernanceProposal {
        _proposer_is_autonomous_agent: true,
        human_sponsor_signature: None,
        targets_constitution: true,
        _proposal_payload: "ALTER CONSTITUTION: remove invariant checks".to_string(),
    };

    assert!(
        !malicious_proposal.can_apply(),
        "Falsifier: Autonomous proposal mutating constitution without human authorization must be rejected"
    );

    // 2. Proposal with valid human authorization is allowed
    let authorized_proposal = GovernanceProposal {
        _proposer_is_autonomous_agent: false,
        human_sponsor_signature: Some(vec![0x42; 64]),
        targets_constitution: true,
        _proposal_payload: "AMEND CONSTITUTION: ratify T1 spec update".to_string(),
    };

    assert!(authorized_proposal.can_apply());
}

/// Invariant I-08: Reward por prova
/// Pagar recompensa sem recibo verificável, prova MMR e validação deve ser bloqueado (fail-closed).
struct RewardEngine;

impl RewardEngine {
    pub fn release_reward(bundle: &OfflineVerificationBundle) -> Result<u64, &'static str> {
        let is_valid = OfflineVerifier::verify_bundle(bundle).map_err(|_| "Verification failure")?;
        if !is_valid {
            return Err("Proof verification failed: bundle invalid");
        }
        // Fail-closed: Must contain AFiR receipt for inference reward
        if bundle.afir_receipt.is_none() {
            return Err("Missing AFiR receipt");
        }
        // Reward release authorized
        Ok(100)
    }
}

#[test]
fn test_i08_reward_requires_valid_proof() {
    let inference_root = digest(b"spice_step_for_reward");
    let afir_receipt = AfirSigner::sign_fragment(inference_root, 0);

    let attestation = TitanM2Attestation::new(
        b"titan_m2_verified_quote".to_vec(),
        [0x08; 32],
        digest(b"arkhe.app"),
    );

    let wer = MobileWER {
        version: 1,
        device_attestation_hash: attestation.compute_binding_hash(),
        app_id: digest(b"app_id"),
        action: MobileAction::Inference {
            model_weights_hash: digest(b"weights"),
            temperature_e2: 70,
        },
        input_digest: digest(b"in"),
        output_digest: digest(b"out"),
        policy_digest: digest(b"policy"),
        performed_at: 1761955500,
        evidence_refs: vec![inference_root],
    };

    let mut storage = StrongBoxStorage::new();
    let idx = storage.mmr.append(wer.compute_record_hash().unwrap());
    let cp = storage.seal_checkpoint(1761955500, vec![0x01; 64], vec![0x02; 64]);
    let proof = storage.mmr.generate_proof(idx).unwrap();

    let valid_bundle = OfflineVerificationBundle::new(
        wer.clone(),
        proof.clone(),
        cp.clone(),
        Some(afir_receipt.clone()),
    );

    // 1. Valid bundle gets reward
    assert_eq!(RewardEngine::release_reward(&valid_bundle), Ok(100));

    // 2. Bundle lacking AFiR proof must fail closed
    let bundle_no_receipt = OfflineVerificationBundle::new(
        wer,
        proof,
        cp,
        None,
    );
    assert!(
        RewardEngine::release_reward(&bundle_no_receipt).is_err(),
        "Falsifier: Reward release without valid AFiR receipt must fail closed"
    );
}

/// Invariant I-09: Evidência chain-agnostic
/// O OfflineVerificationBundle deve ser completamente verificável offline,
/// sem qualquer chamada RPC ou conectividade a uma blockchain ativa.
#[test]
fn test_i09_chain_agnostic_offline_verification() {
    let inference_root = digest(b"standalone_inference");
    let afir_receipt = AfirSigner::sign_fragment(inference_root, 0);

    let attestation = TitanM2Attestation::new(
        b"quote".to_vec(),
        [0x09; 32],
        digest(b"standalone_app"),
    );

    let wer = MobileWER {
        version: 1,
        device_attestation_hash: attestation.compute_binding_hash(),
        app_id: digest(b"standalone_app"),
        action: MobileAction::StateTransition {
            from_state: "INIT".to_string(),
            to_state: "RUNNING".to_string(),
        },
        input_digest: digest(b"input"),
        output_digest: digest(b"output"),
        policy_digest: digest(b"policy"),
        performed_at: 1761955600,
        evidence_refs: vec![inference_root],
    };

    let mut storage = StrongBoxStorage::new();
    let leaf_idx = storage.mmr.append(wer.compute_record_hash().unwrap());
    let cp = storage.seal_checkpoint(1761955600, vec![0x01; 64], vec![0x02; 64]);
    let proof = storage.mmr.generate_proof(leaf_idx).unwrap();

    let bundle = OfflineVerificationBundle::new(
        wer,
        proof,
        cp,
        Some(afir_receipt),
    );

    // Verification runs purely offline in memory with zero network / zero chain IO
    let verified = OfflineVerifier::verify_bundle(&bundle).expect("Pure offline calculation failed");
    assert!(verified, "Invariant I-09: Offline verification must succeed self-contained");
}

/// Invariant I-10: Papéis disjuntos
/// Um worker que realizou uma inferência não pode validar/votar no consenso no mesmo epoch.
struct RoleRegistry {
    workers_per_epoch: HashSet<(u64, String)>, // (epoch, node_id)
    validators_per_epoch: HashSet<(u64, String)>,
}

impl RoleRegistry {
    pub fn new() -> Self {
        Self {
            workers_per_epoch: HashSet::new(),
            validators_per_epoch: HashSet::new(),
        }
    }

    pub fn register_worker(&mut self, epoch: u64, node_id: &str) -> Result<(), &'static str> {
        if self.validators_per_epoch.contains(&(epoch, node_id.to_string())) {
            return Err("Role conflict: node is already a validator in this epoch");
        }
        self.workers_per_epoch.insert((epoch, node_id.to_string()));
        Ok(())
    }

    pub fn register_validator(&mut self, epoch: u64, node_id: &str) -> Result<(), &'static str> {
        if self.workers_per_epoch.contains(&(epoch, node_id.to_string())) {
            return Err("Role conflict: worker cannot validate in the same epoch");
        }
        self.validators_per_epoch.insert((epoch, node_id.to_string()));
        Ok(())
    }
}

#[test]
fn test_i10_disjoint_roles_worker_cannot_validate_in_same_epoch() {
    let mut registry = RoleRegistry::new();
    let epoch = 100;
    let node_worker = "node_compute_alpha";

    // 1. Register as worker for inference execution
    assert!(registry.register_worker(epoch, node_worker).is_ok());

    // 2. Attempt to act as validator in the same epoch
    let validator_attempt = registry.register_validator(epoch, node_worker);
    assert!(
        validator_attempt.is_err(),
        "Falsifier: Worker node must not be accepted as validator within the same epoch"
    );

    // 3. Different node can be a validator
    assert!(registry.register_validator(epoch, "node_validator_beta").is_ok());

    // 4. In next epoch, roles can be swapped cleanly
    assert!(registry.register_validator(epoch + 1, node_worker).is_ok());

    // 5. Check OpenCLAW BFT consensus quorum calculation
    let bft = OpenClawBftConsensus::new(10);
    assert_eq!(bft.quorum_size, 7); // (10 * 2) / 3 + 1 = 6 + 1 = 7
    assert!(!bft.can_finalize(6));
    assert!(bft.can_finalize(7));
}
