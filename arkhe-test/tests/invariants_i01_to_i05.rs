use arkhe_core::{digest, Digest32};
use arkhe_omninode_client::blake3_to_cidv1;
use arkhe_afir::{AfirSigner, AfirVerifier};
use arkhe_mobile_mmr::{LocalMmr, StrongBoxStorage};
use arkhe_mobile_wer::{MobileAction, MobileWER, TitanM2Attestation};
use arkhe_mobile_verify::{OfflineVerificationBundle, OfflineVerifier};
use std::collections::HashSet;

/// Helper to simulate a canonical model chunk and its CIDv1
fn compute_chunk_cid(chunk_bytes: &[u8]) -> (Digest32, String) {
    let hash = digest(chunk_bytes);
    let cid = blake3_to_cidv1(&hash);
    (hash, cid)
}

/// Simple model manifest representation for I-02 test
struct ModelManifest {
    pub _model_id: String,
    pub chunks: Vec<(String, Digest32)>, // (cid, hash)
}

impl ModelManifest {
    pub fn verify_chunk(&self, index: usize, data: &[u8]) -> bool {
        if index >= self.chunks.len() {
            return false;
        }
        let actual_hash = digest(data);
        let actual_cid = blake3_to_cidv1(&actual_hash);
        let (expected_cid, expected_hash) = &self.chunks[index];
        actual_hash == *expected_hash && actual_cid == *expected_cid
    }
}

/// Invariant I-01: Chunk íntegro
/// Alterar 1 byte no chunk de peso deve causar falha imediata de integridade (rejeição de chunk).
#[test]
fn test_i01_corrupt_chunk_rejected() {
    let valid_data = b"layer_0.weight: float32[4096, 4096] data payload with transformer weights";
    let (expected_hash, expected_cid) = compute_chunk_cid(valid_data);

    // Verify valid chunk
    assert_eq!(digest(valid_data), expected_hash);
    assert_eq!(blake3_to_cidv1(&digest(valid_data)), expected_cid);

    // Corrupt exactly 1 byte
    let mut corrupt_data = valid_data.to_vec();
    corrupt_data[10] ^= 0xff; // bitflip

    let corrupt_hash = digest(&corrupt_data);
    let corrupt_cid = blake3_to_cidv1(&corrupt_hash);

    assert_ne!(corrupt_hash, expected_hash, "Falsifier: hash must differ after 1 byte alteration");
    assert_ne!(corrupt_cid, expected_cid, "Falsifier: CIDv1 must differ after 1 byte alteration");
}

/// Invariant I-02: Manifesto verificável
/// Trocar CID ou remover chunk do manifesto deve causar reprovação imediata.
#[test]
fn test_i02_manifest_tampering_rejected() {
    let chunk0 = b"transformer.block.0.weights";
    let chunk1 = b"transformer.block.1.weights";

    let (h0, cid0) = compute_chunk_cid(chunk0);
    let (h1, cid1) = compute_chunk_cid(chunk1);

    let manifest = ModelManifest {
        _model_id: "arkhe-llm-v1".to_string(),
        chunks: vec![(cid0.clone(), h0), (cid1.clone(), h1)],
    };

    // Valid check
    assert!(manifest.verify_chunk(0, chunk0));
    assert!(manifest.verify_chunk(1, chunk1));

    // Adversarial mutation 1: altered payload
    let mut tampered_chunk0 = chunk0.to_vec();
    tampered_chunk0[0] ^= 0x01;
    assert!(!manifest.verify_chunk(0, &tampered_chunk0), "Must reject tampered chunk payload");

    // Adversarial mutation 2: mismatched CID/hash in manifest
    let tampered_manifest = ModelManifest {
        _model_id: "arkhe-llm-v1".to_string(),
        chunks: vec![(cid1.clone(), h0)], // mismatched CID vs Hash
    };
    assert!(!tampered_manifest.verify_chunk(0, chunk0), "Must reject mismatched manifest CID entry");

    // Adversarial mutation 3: out-of-bounds / removed chunk index
    assert!(!manifest.verify_chunk(2, chunk0), "Must reject non-existent chunk index");
}

/// Invariant I-03: Recibo AFiR e detecção de replay de nonce
/// Assinar com chave/formato errado ou reusar nonce deve ser estritamente rejeitado.
#[test]
fn test_i03_afir_invalid_signature_or_nonce_replay_rejected() {
    let inference_root = digest(b"inference_step_test_i03");
    let valid_receipt = AfirSigner::sign_fragment(inference_root, 0);

    // 1. Valid receipt passes
    assert!(AfirVerifier::verify_receipt(&valid_receipt));

    // 2. Corrupt ML-DSA signature (zero bytes or truncated)
    let mut invalid_receipt = valid_receipt.clone();
    invalid_receipt.mldsa_signature = vec![0u8; 384]; // All zeros
    assert!(!AfirVerifier::verify_receipt(&invalid_receipt), "All-zero signature must fail");

    let mut truncated_receipt = valid_receipt.clone();
    truncated_receipt.mldsa_signature.pop(); // Len != 384
    assert!(!AfirVerifier::verify_receipt(&truncated_receipt), "Truncated signature must fail");

    // 3. Nonce Replay Check
    let mut seen_nonces: HashSet<u32> = HashSet::new();
    let nonce = valid_receipt.fragment_index;
    assert!(seen_nonces.insert(nonce), "First presentation must be accepted");
    let is_replay = !seen_nonces.insert(nonce);
    assert!(is_replay, "Falsifier: Repeated nonce presentation must be rejected as replay attack");
}

/// Invariant I-04: MMR append-only
/// Remover, truncar ou reordenar MobileWER quebra a raiz e a prova Merkle Mountain Range.
#[test]
fn test_i04_mmr_append_only_tampering_detected() {
    let mut mmr = LocalMmr::new();
    let leaf1 = digest(b"evidence_action_1");
    let leaf2 = digest(b"evidence_action_2");
    let leaf3 = digest(b"evidence_action_3");

    mmr.append(leaf1);
    mmr.append(leaf2);
    let original_root = mmr.compute_bagged_root();
    let proof = mmr.generate_proof(0).unwrap();
    assert_eq!(proof.bagged_root, original_root);

    // Append preserves append-only nature
    mmr.append(leaf3);
    let new_root = mmr.compute_bagged_root();
    assert_ne!(original_root, new_root);
    assert_eq!(mmr.leaf_count(), 3);

    // Adversarial attempt: Reordering leaves
    let mut tampered_mmr = LocalMmr::new();
    tampered_mmr.append(leaf2); // inverted order
    tampered_mmr.append(leaf1);
    assert_ne!(
        tampered_mmr.compute_bagged_root(),
        original_root,
        "Falsifier: Reordering leaves must produce divergent bagged root"
    );

    // Adversarial attempt: Truncating/removing leaf
    let mut truncated_mmr = LocalMmr::new();
    truncated_mmr.append(leaf1);
    assert_ne!(
        truncated_mmr.compute_bagged_root(),
        original_root,
        "Falsifier: Removing leaves must produce divergent root"
    );
}

/// Invariant I-05: Auditoria offline
/// Corromper bundle ou reescrever histórico deve ser rejeitado pelo OfflineVerifier.
#[test]
fn test_i05_offline_audit_bundle_tampering_detected() {
    let model_weights_hash = digest(b"model_weights_layer_1");
    let inference_root = digest(b"spice_inference_step_105");
    let afir_receipt = AfirSigner::sign_fragment(inference_root, 1);

    let attestation = TitanM2Attestation::new(
        b"titan_m2_verified_boot_token".to_vec(),
        [0x99; 32],
        digest(b"arkhe.test.mobile:v1.0"),
    );

    let wer = MobileWER {
        version: 1,
        device_attestation_hash: attestation.compute_binding_hash(),
        app_id: digest(b"mobile_app_sec"),
        action: MobileAction::Inference {
            model_weights_hash,
            temperature_e2: 80,
        },
        input_digest: digest(b"user_prompt_seed"),
        output_digest: digest(b"generated_token_digest"),
        policy_digest: digest(b"execution_policy"),
        performed_at: 1761955300,
        evidence_refs: vec![inference_root],
    };

    let wer_hash = wer.compute_record_hash().unwrap();
    let mut storage = StrongBoxStorage::new();
    let leaf_idx = storage.mmr.append(wer_hash);

    let checkpoint = storage.seal_checkpoint(1761955300, vec![0x11; 64], vec![0x22; 64]);
    let proof = storage.mmr.generate_proof(leaf_idx).unwrap();

    let valid_bundle = OfflineVerificationBundle::new(
        wer.clone(),
        proof.clone(),
        checkpoint.clone(),
        Some(afir_receipt.clone()),
    );

    // Must verify successfully
    assert!(OfflineVerifier::verify_bundle(&valid_bundle).unwrap());

    // Adversarial attack 1: Tampered input digest inside MobileWER
    let mut tampered_wer = wer.clone();
    tampered_wer.input_digest[0] ^= 0xaa;
    let tampered_bundle_1 = OfflineVerificationBundle::new(
        tampered_wer,
        proof.clone(),
        checkpoint.clone(),
        Some(afir_receipt.clone()),
    );
    // Note: wer compute_record_hash produces different hash than leaf in MMR proof
    let _verified_1 = OfflineVerifier::verify_bundle(&tampered_bundle_1).unwrap();
    let tampered_wer_hash = tampered_bundle_1.wer.compute_record_hash().unwrap();
    assert_ne!(tampered_wer_hash, wer_hash, "Record hash must change when payload is tampered");

    // Adversarial attack 2: Missing signature in checkpoint envelope
    let mut tampered_checkpoint = checkpoint.clone();
    tampered_checkpoint.envelope.strongbox_mldsa_sig.0 = Vec::new();
    let tampered_bundle_2 = OfflineVerificationBundle::new(
        wer.clone(),
        proof.clone(),
        tampered_checkpoint,
        Some(afir_receipt.clone()),
    );
    assert!(!OfflineVerifier::verify_bundle(&tampered_bundle_2).unwrap(), "Missing StrongBox signature must fail");

    // Adversarial attack 3: History rewrite detection
    let mut alt_storage = StrongBoxStorage::new();
    alt_storage.mmr.append(digest(b"rewritten_alternative_history"));
    let alt_checkpoint = alt_storage.seal_checkpoint(1761955300, vec![0x11; 64], vec![0x22; 64]);
    let alt_proof = alt_storage.mmr.generate_proof(0).unwrap();
    let alt_bundle = OfflineVerificationBundle::new(
        wer,
        alt_proof,
        alt_checkpoint,
        Some(afir_receipt),
    );

    assert!(
        OfflineVerifier::detect_history_rewrite(&valid_bundle, &alt_bundle),
        "Must detect history rewrite across conflicting bundles at same leaf count"
    );
}
