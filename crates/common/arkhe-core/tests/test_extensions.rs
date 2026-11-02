use arkhe_core::{
    lookup_extension, validate_release_manifest, ExtensionCategory, RequirementLevel,
    SecurityStatus, ALL_EXTENSIONS, MINIMAL_RELEASE_FILES,
};

#[test]
fn test_all_categories_represented() {
    let categories = [
        ExtensionCategory::IdentityAndContent,
        ExtensionCategory::ManifestsAndModels,
        ExtensionCategory::ReceiptsAndEvidence,
        ExtensionCategory::NetworkAndDiscovery,
        ExtensionCategory::InferenceAndExecution,
        ExtensionCategory::VerificationAndFraud,
        ExtensionCategory::EconomicsAndGovernance,
        ExtensionCategory::ChainIntegration,
        ExtensionCategory::BuildAndSupplyChain,
    ];

    for cat in &categories {
        let count = ALL_EXTENSIONS.iter().filter(|e| e.category == *cat).count();
        assert!(count > 0, "Category {:?} must have at least one extension", cat);
    }
}

#[test]
fn test_compound_and_simple_extension_lookup() {
    // Identity & Content
    let spec = lookup_extension("models/qwen.cid").expect("should find cid");
    assert_eq!(spec.extension, "cid");
    assert_eq!(spec.category, ExtensionCategory::IdentityAndContent);
    assert_eq!(spec.requirement, RequirementLevel::Mandatory);

    // Compound extension: .arkmanifest.sig
    let spec = lookup_extension("model.arkmanifest.sig").expect("should find arkmanifest.sig");
    assert_eq!(spec.extension, "arkmanifest.sig");
    assert_eq!(spec.category, ExtensionCategory::ManifestsAndModels);

    // Compound extension: .gguf.part
    let spec = lookup_extension("model.gguf.part0001").expect("should find gguf.part");
    assert_eq!(spec.extension, "gguf.part");
    assert_eq!(spec.category, ExtensionCategory::ManifestsAndModels);

    // Compound extension: .gguf.index
    let spec = lookup_extension("model.gguf.index").expect("should find gguf.index");
    assert_eq!(spec.extension, "gguf.index");

    // Receipts: .afir
    let spec = lookup_extension("receipt.afir").expect("should find afir");
    assert_eq!(spec.extension, "afir");
    assert_eq!(spec.category, ExtensionCategory::ReceiptsAndEvidence);

    // Receipts: .afir.json
    let spec = lookup_extension("receipt.afir.json").expect("should find afir.json");
    assert_eq!(spec.extension, "afir.json");

    // Evidence: .wer, .mmr, .checkpoint, .arkbundle, .wasm
    assert!(lookup_extension("session.wer").is_some());
    assert!(lookup_extension("device.mmr").is_some());
    assert!(lookup_extension("device.checkpoint").is_some());
    assert!(lookup_extension("audit.arkbundle").is_some());
    assert!(lookup_extension("arkverify.wasm").is_some());

    // Governance: .constitution, .constitution.sig
    let spec = lookup_extension("arkhe.constitution.sig").expect("should find constitution.sig");
    assert_eq!(spec.extension, "constitution.sig");
    assert_eq!(spec.category, ExtensionCategory::EconomicsAndGovernance);

    // Inference: .policy.sig
    let spec = lookup_extension("inference.policy.sig").expect("should find policy.sig");
    assert_eq!(spec.extension, "policy.sig");
    assert_eq!(spec.category, ExtensionCategory::InferenceAndExecution);
}

#[test]
fn test_security_status_evaluation() {
    use arkhe_core::extensions::evaluate_security_status;

    // Forbidden in production
    assert_eq!(
        evaluate_security_status(".env", true),
        SecurityStatus::Forbidden
    );
    assert_eq!(
        evaluate_security_status("/app/config/.env", true),
        SecurityStatus::Forbidden
    );

    // Forbidden keys
    assert_eq!(
        evaluate_security_status("private.pem", false),
        SecurityStatus::Forbidden
    );

    // Forbidden backup files that would create parallel histories
    assert_eq!(
        evaluate_security_status("device_mmr.bak", false),
        SecurityStatus::Forbidden
    );
    assert_eq!(
        evaluate_security_status("checkpoint.bak", false),
        SecurityStatus::Forbidden
    );

    // Forbidden payload dumps
    assert_eq!(
        evaluate_security_status("memory.dump", false),
        SecurityStatus::Forbidden
    );

    // Restricted binaries
    assert_eq!(
        evaluate_security_status("libengine.dll", false),
        SecurityStatus::Restricted
    );
    assert_eq!(
        evaluate_security_status("worker.exe", false),
        SecurityStatus::Restricted
    );
    assert_eq!(
        evaluate_security_status("libtorch.so", false),
        SecurityStatus::Restricted
    );
    assert_eq!(
        evaluate_security_status("libmetal.dylib", false),
        SecurityStatus::Restricted
    );

    // Standard valid extensions
    assert_eq!(
        evaluate_security_status("model.arkmanifest", true),
        SecurityStatus::Standard
    );
    assert_eq!(
        evaluate_security_status("fragment.afir", true),
        SecurityStatus::Standard
    );
    assert_eq!(
        evaluate_security_status("session.wer", true),
        SecurityStatus::Standard
    );
}

#[test]
fn test_minimal_release_manifest_validation() {
    let valid_release = [
        "arkhe-node",
        "arkhe-node.sha256",
        "arkhe-node.provenance",
        "arkhe-node.sbom",
        "arkhe-node.sigstore",
        "arkhe.toml",
        "seeds.toml",
        "network.netpolicy",
        "arkhe.constitution",
        "arkhe.constitution.sig",
        "arkverify.wasm",
        "vectors.golden",
    ];

    assert!(validate_release_manifest(&valid_release).is_ok());

    let missing_release = [
        "arkhe-node",
        "arkhe.toml",
    ];

    let err = validate_release_manifest(&missing_release).unwrap_err();
    assert_eq!(err.len(), MINIMAL_RELEASE_FILES.len() - 2);
    assert!(err.contains(&"arkhe-node.sha256"));
    assert!(err.contains(&"arkverify.wasm"));
    assert!(err.contains(&"arkhe.constitution"));
}
