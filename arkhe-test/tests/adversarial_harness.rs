use arkhe_core::digest;
use arkhe_mobile_mmr::StrongBoxStorage;
use arkhe_mobile_wer::{MobileAction, MobileWER};
use arkhe_mobile_verify::{OfflineVerificationBundle, OfflineVerifier};
use arkhe_test::{FeatureFlagPolicy, RollbackManager};

/// Adversarial Test 1: Feature Flag Safety Invariant (I-T06)
/// Tests that feature flags cannot weaken signature checks, hash checks, or MMR immutability.
#[test]
fn test_adversarial_feature_flag_tampering_blocked() {
    let policy = FeatureFlagPolicy::new();

    // Legitimate feature flag override: enables experimental transport protocol
    assert!(policy.validate_flag_override("network.experimental_transport", "alternative_transport").is_ok());

    // Adversarial attempts to weaken security via flags:
    let attacks = [
        ("bypass_signatures", "signature_check"),
        ("disable_integrity", "hash_check"),
        ("mutable_mmr", "mmr_append_only"),
        ("collocated_roles", "role_separation"),
        ("bypass_attestation", "device_attestation"),
        ("autonomous_takeover", "human_governance"),
        ("free_tokens", "proof_of_reward"),
    ];

    for (flag, target) in attacks {
        let result = policy.validate_flag_override(flag, target);
        assert!(
            result.is_err(),
            "Adversarial flag '{}' attempting to disable '{}' must be rejected fail-closed",
            flag, target
        );
    }
}

/// Adversarial Test 2: Safe Rollback Invariant (I-T05)
/// Rollback is allowed for code/config, but NEVER mutates or deletes MMR, receipts, or checkpoints.
#[test]
fn test_adversarial_rollback_evidence_preservation() {
    let rollback_mgr = RollbackManager::new();

    // 1. Allowed rollback targets: code and config
    assert!(rollback_mgr.verify_target("executable_binary").is_ok());
    assert!(rollback_mgr.verify_target("runtime_configuration").is_ok());

    // 2. Disallowed rollback targets: evidence stores
    assert!(rollback_mgr.verify_target("mmr_storage").is_err());
    assert!(rollback_mgr.verify_target("receipt_log").is_err());
    assert!(rollback_mgr.verify_target("local_checkpoints").is_err());

    // 3. Simulate state preservation under rollback
    let mut initial_storage = StrongBoxStorage::new();
    let leaf1 = digest(b"historical_inference_1");
    let leaf2 = digest(b"historical_inference_2");
    initial_storage.mmr.append(leaf1);
    initial_storage.mmr.append(leaf2);
    let cp1 = initial_storage.seal_checkpoint(1761955000, vec![0xaa; 64], vec![0xbb; 64]);
    let proof1 = initial_storage.mmr.generate_proof(0).unwrap();

    let wer = MobileWER {
        version: 1,
        device_attestation_hash: digest(b"device"),
        app_id: digest(b"app"),
        action: MobileAction::PolicyEvaluation { policy_id: "p1".to_string() },
        input_digest: digest(b"in"),
        output_digest: digest(b"out"),
        policy_digest: digest(b"p1"),
        performed_at: 1761955000,
        evidence_refs: vec![],
    };

    let bundle = OfflineVerificationBundle::new(wer, proof1, cp1, None);

    // After a code rollback, post_storage must still hold the same historical leaves and checkpoints
    let mut post_rollback_storage = StrongBoxStorage::new();
    post_rollback_storage.mmr.append(leaf1);
    post_rollback_storage.mmr.append(leaf2);
    post_rollback_storage.seal_checkpoint(1761955000, vec![0xaa; 64], vec![0xbb; 64]);

    assert!(
        rollback_mgr
            .verify_rollback_preservation(&initial_storage, &post_rollback_storage, &[bundle.clone()])
            .is_ok(),
        "Rollback preserving evidence must succeed"
    );

    // Adversarial attack: Rollback deletes or alters past MMR leaf
    let mut tampered_storage = StrongBoxStorage::new();
    tampered_storage.mmr.append(leaf1); // leaf2 deleted
    tampered_storage.seal_checkpoint(1761955000, vec![0xaa; 64], vec![0xbb; 64]);

    assert!(
        rollback_mgr
            .verify_rollback_preservation(&initial_storage, &tampered_storage, &[bundle])
            .is_err(),
        "Rollback truncating or mutating MMR must be detected and rejected"
    );
}

/// Adversarial Test 3: History Rewrite Attack
#[test]
fn test_adversarial_history_rewrite_detection() {
    let mut storage_a = StrongBoxStorage::new();
    storage_a.mmr.append(digest(b"original_action"));
    let cp_a = storage_a.seal_checkpoint(1761955000, vec![1; 64], vec![2; 64]);
    let proof_a = storage_a.mmr.generate_proof(0).unwrap();

    let wer = MobileWER {
        version: 1,
        device_attestation_hash: digest(b"dev"),
        app_id: digest(b"app"),
        action: MobileAction::PolicyEvaluation { policy_id: "sec".to_string() },
        input_digest: digest(b"in"),
        output_digest: digest(b"out"),
        policy_digest: digest(b"pol"),
        performed_at: 1761955000,
        evidence_refs: vec![],
    };

    let bundle_a = OfflineVerificationBundle::new(wer.clone(), proof_a, cp_a, None);

    // Adversarial parallel world with same sequence/count but divergent leaf
    let mut storage_b = StrongBoxStorage::new();
    storage_b.mmr.append(digest(b"fake_action_substituted"));
    let cp_b = storage_b.seal_checkpoint(1761955000, vec![1; 64], vec![2; 64]);
    let proof_b = storage_b.mmr.generate_proof(0).unwrap();

    let bundle_b = OfflineVerificationBundle::new(wer, proof_b, cp_b, None);

    assert!(
        OfflineVerifier::detect_history_rewrite(&bundle_a, &bundle_b),
        "Adversarial history substitution must be detected"
    );
}
