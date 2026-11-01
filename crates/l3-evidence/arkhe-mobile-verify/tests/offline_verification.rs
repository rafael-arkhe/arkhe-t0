use arkhe_core::digest;
use arkhe_afir::AfirSigner;
use arkhe_mobile_wer::{MobileAction, MobileWER, TitanM2Attestation};
use arkhe_mobile_mmr::StrongBoxStorage;
use arkhe_mobile_verify::{OfflineVerificationBundle, OfflineVerifier};

#[test]
fn test_l1_to_l2_to_l3_binding_and_offline_verification() {
    // 1. Simulate L1 model chunk CID and inference
    let model_weights_hash = digest(b"model_weights_layer_1");
    let inference_root = digest(b"spice_inference_step_42");

    // 2. Generate L2 AFiR receipt signed with ML-DSA-65 (384 bytes)
    let afir_receipt = AfirSigner::sign_fragment(inference_root, 0);

    // 3. Setup L3 Hardware Attestation (Titan M2 / StrongBox)
    let attestation = TitanM2Attestation::new(
        b"titan_m2_verified_boot_quote".to_vec(),
        [0x42; 32],
        digest(b"space.arkhe.mobile:v1.0.0"),
    );
    let device_attestation_hash = attestation.compute_binding_hash();

    // 4. Create MobileWER
    let wer = MobileWER {
        version: 1,
        device_attestation_hash,
        app_id: digest(b"agent_app_id"),
        action: MobileAction::Inference {
            model_weights_hash,
            temperature_e2: 70,
        },
        input_digest: digest(b"agent_prompt_input"),
        output_digest: digest(b"agent_token_output"),
        policy_digest: digest(b"allow_action_policy"),
        performed_at: 1761955200,
        evidence_refs: vec![inference_root],
    };

    let wer_hash = wer.compute_record_hash().expect("compute hash failed");

    // 5. Accumulate into StrongBox-sealed MMR
    let mut storage = StrongBoxStorage::new();
    let leaf_idx = storage.mmr.append(wer_hash);

    // Seal checkpoint with hybrid signature (ML-DSA in StrongBox + Ed25519 in TEE)
    let checkpoint = storage.seal_checkpoint(
        1761955200,
        vec![0x01; 64],
        vec![0x02; 64],
    );

    let proof = storage.mmr.generate_proof(leaf_idx).expect("proof generation failed");

    // 6. Generate and verify OfflineVerificationBundle
    let bundle = OfflineVerificationBundle::new(
        wer.clone(),
        proof,
        checkpoint,
        Some(afir_receipt.clone()),
    );

    let is_valid = OfflineVerifier::verify_bundle(&bundle).expect("verification failed");
    assert!(is_valid, "Offline bundle should verify successfully");

    // 7. Verify detection of history rewrite (adversarial attempt to rewrite past inference)
    let mut tampered_storage = StrongBoxStorage::new();
    let tampered_wer_hash = digest(b"tampered_history_leaf");
    tampered_storage.mmr.append(tampered_wer_hash);
    let tampered_checkpoint = tampered_storage.seal_checkpoint(
        1761955200,
        vec![0x01; 64],
        vec![0x02; 64],
    );
    let tampered_proof = tampered_storage.mmr.generate_proof(0).unwrap();

    let tampered_bundle = OfflineVerificationBundle::new(
        wer,
        tampered_proof,
        tampered_checkpoint,
        Some(afir_receipt),
    );

    let rewrite_detected = OfflineVerifier::detect_history_rewrite(&bundle, &tampered_bundle);
    assert!(
        rewrite_detected,
        "Offline verifier must detect historical rewriting of inferences"
    );
}
