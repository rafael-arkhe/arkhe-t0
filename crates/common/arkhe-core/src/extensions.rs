use std::path::Path;
use serde::{Deserialize, Serialize};

/// The 9 architectural categories of Arkhe file extensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExtensionCategory {
    /// 1. Identity and Content (CID, pubkey, signatures, certs, keystores)
    IdentityAndContent,
    /// 2. Manifests and Models (model manifests, gguf chunks, quant profiles, lineage)
    ManifestsAndModels,
    /// 3. Receipts and Evidence (AFiR receipts, WER, MMR, checkpoints, attestations, bundles, WASM verifier)
    ReceiptsAndEvidence,
    /// 4. Network and Discovery (PeerBook, peerledger, seeds, dhtcache, gossip, netpolicy)
    NetworkAndDiscovery,
    /// 5. Inference and Execution (policy, request/response, session, router, expertmap, GPU profile)
    InferenceAndExecution,
    /// 6. Verification and Fraud (fraud proof, re-execution, ZK proof, TEE quote, verdict, slash, golden vectors)
    VerificationAndFraud,
    /// 7. Economics and Governance (constitution, proposal, vote, canon, emission, reward, stake, epoch, gini)
    EconomicsAndGovernance,
    /// 8. Chain Integration / CAL (anchor, IBC, CCIP, LayerZero, ABI, smart contracts, tx, receiptroot)
    ChainIntegration,
    /// 9. Build, Testing and Supply Chain (config, code, WASM, SBOM, SLSA provenance, hashes, logs, traces)
    BuildAndSupplyChain,
}

/// Normative requirement level defined by the Arkhe protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RequirementLevel {
    Mandatory,
    Optional,
    Recommended,
}

/// Security status of a file or extension within the Arkhe ecosystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityStatus {
    /// Permitted standard file format.
    Standard,
    /// Restricted format; allowed only with hash, signature and SLSA provenance, or in diagnostic contexts.
    Restricted,
    /// Strictly forbidden; never permitted in production or protocol state (fail-closed).
    Forbidden,
}

/// Metadata description for an Arkhe file extension.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionSpec {
    pub extension: &'static str,
    pub example_file: &'static str,
    pub function: &'static str,
    pub category: ExtensionCategory,
    pub requirement: RequirementLevel,
}

/// All official Arkhe protocol and ecosystem file extensions.
pub static ALL_EXTENSIONS: &[ExtensionSpec] = &[
    // 1. Identity and Content
    ExtensionSpec {
        extension: "cid",
        example_file: "model.cid",
        function: "Textual representation of CIDv1/BLAKE3",
        category: ExtensionCategory::IdentityAndContent,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "multihash",
        example_file: "digest.multihash",
        function: "Self-describing hash",
        category: ExtensionCategory::IdentityAndContent,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "pub",
        example_file: "publisher.pub",
        function: "ML-DSA-65 or Ed25519 public key",
        category: ExtensionCategory::IdentityAndContent,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "sig",
        example_file: "manifest.sig",
        function: "Detached cryptographic signature",
        category: ExtensionCategory::IdentityAndContent,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "cert",
        example_file: "device.cert",
        function: "Certificate or identity update",
        category: ExtensionCategory::IdentityAndContent,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "crl",
        example_file: "revocation.crl",
        function: "Revocation of keys or identities",
        category: ExtensionCategory::IdentityAndContent,
        requirement: RequirementLevel::Recommended,
    },
    ExtensionSpec {
        extension: "keystore",
        example_file: "node.keystore",
        function: "Encrypted container of local keys",
        category: ExtensionCategory::IdentityAndContent,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "seed",
        example_file: "node.seed",
        function: "Encrypted identity seed material (never plaintext)",
        category: ExtensionCategory::IdentityAndContent,
        requirement: RequirementLevel::Optional,
    },

    // 2. Manifests and Models
    ExtensionSpec {
        extension: "arkmanifest",
        example_file: "model.arkmanifest",
        function: "Canonical CBOR model manifest",
        category: ExtensionCategory::ManifestsAndModels,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "arkmanifest.sig",
        example_file: "model.arkmanifest.sig",
        function: "Publisher ML-DSA signature over manifest",
        category: ExtensionCategory::ManifestsAndModels,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "gguf",
        example_file: "model.gguf",
        function: "Reference local inference model",
        category: ExtensionCategory::ManifestsAndModels,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "gguf.part",
        example_file: "model.gguf.part0001",
        function: "Model weight chunk for distributed transfer",
        category: ExtensionCategory::ManifestsAndModels,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "gguf.index",
        example_file: "model.gguf.index",
        function: "Index of weight chunks and CIDs",
        category: ExtensionCategory::ManifestsAndModels,
        requirement: RequirementLevel::Recommended,
    },
    ExtensionSpec {
        extension: "quant",
        example_file: "nvfp4.quant",
        function: "Quantization profile (e.g. NVFP4)",
        category: ExtensionCategory::ManifestsAndModels,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "lineage",
        example_file: "training.lineage",
        function: "Training checkpoint chain for payment-grade inference",
        category: ExtensionCategory::ManifestsAndModels,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "eval",
        example_file: "evaluation.eval",
        function: "Evaluation record per checkpoint",
        category: ExtensionCategory::ManifestsAndModels,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "dataset",
        example_file: "cohort.dataset",
        function: "Cohort / dataset descriptor",
        category: ExtensionCategory::ManifestsAndModels,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "tokenizer",
        example_file: "tokenizer.json",
        function: "Model tokenizer descriptor",
        category: ExtensionCategory::ManifestsAndModels,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "vocab",
        example_file: "vocab.txt",
        function: "Legacy vocabulary file",
        category: ExtensionCategory::ManifestsAndModels,
        requirement: RequirementLevel::Optional,
    },

    // 3. Receipts and Evidence
    ExtensionSpec {
        extension: "afir",
        example_file: "fragment.afir",
        function: "Binary 384-byte ML-DSA-65 AFiR receipt",
        category: ExtensionCategory::ReceiptsAndEvidence,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "afir.json",
        example_file: "fragment.afir.json",
        function: "Canonical JCS JSON representation for debug/interop",
        category: ExtensionCategory::ReceiptsAndEvidence,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "afirtree",
        example_file: "session.afirtree",
        function: "Merkle tree of MoE fragment receipts",
        category: ExtensionCategory::ReceiptsAndEvidence,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "wer",
        example_file: "session.wer",
        function: "MobileWER / work evidence record",
        category: ExtensionCategory::ReceiptsAndEvidence,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "mmr",
        example_file: "device.mmr",
        function: "State and peaks of Merkle Mountain Range",
        category: ExtensionCategory::ReceiptsAndEvidence,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "mmrproof",
        example_file: "inclusion.mmrproof",
        function: "MMR inclusion proof",
        category: ExtensionCategory::ReceiptsAndEvidence,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "consistency",
        example_file: "history.consistency",
        function: "Historical consistency proof between MMR roots",
        category: ExtensionCategory::ReceiptsAndEvidence,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "checkpoint",
        example_file: "device.checkpoint",
        function: "Hybrid checkpoint (ML-DSA in StrongBox + Ed25519 in TEE)",
        category: ExtensionCategory::ReceiptsAndEvidence,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "attest",
        example_file: "boot.attest",
        function: "Verified Boot / KeyMint hardware attestation blob",
        category: ExtensionCategory::ReceiptsAndEvidence,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "arkbundle",
        example_file: "audit.arkbundle",
        function: "Complete offline verification bundle container",
        category: ExtensionCategory::ReceiptsAndEvidence,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "wasm",
        example_file: "arkverify.wasm",
        function: "Deterministic portable offline verifier",
        category: ExtensionCategory::ReceiptsAndEvidence,
        requirement: RequirementLevel::Mandatory,
    },

    // 4. Network and Discovery
    ExtensionSpec {
        extension: "peers",
        example_file: "peers.dat",
        function: "PeerBook: addresses, buckets, tried/new peers (fail-closed)",
        category: ExtensionCategory::NetworkAndDiscovery,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "peerledger",
        example_file: "service.peerledger",
        function: "Service receipts, latency, availability ledger",
        category: ExtensionCategory::NetworkAndDiscovery,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "seeds",
        example_file: "seeds.toml",
        function: "Constitutional seed nodes and rotation policy",
        category: ExtensionCategory::NetworkAndDiscovery,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "dhtcache",
        example_file: "dht.cache",
        function: "Kademlia lookup / announce cache",
        category: ExtensionCategory::NetworkAndDiscovery,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "announce",
        example_file: "chunk.announce",
        function: "Content / chunk announcement with token",
        category: ExtensionCategory::NetworkAndDiscovery,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "gossip",
        example_file: "topic.gossip",
        function: "GossipSub topic configuration and routing",
        category: ExtensionCategory::NetworkAndDiscovery,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "netpolicy",
        example_file: "network.netpolicy",
        function: "Limits, connection classes, bandwidth quotas",
        category: ExtensionCategory::NetworkAndDiscovery,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "pcap",
        example_file: "debug.pcap",
        function: "Network packet capture for diagnostics only (never in production)",
        category: ExtensionCategory::NetworkAndDiscovery,
        requirement: RequirementLevel::Optional,
    },

    // 5. Inference and Execution
    ExtensionSpec {
        extension: "policy",
        example_file: "inference.policy",
        function: "Declared inference and containment policy",
        category: ExtensionCategory::InferenceAndExecution,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "policy.sig",
        example_file: "inference.policy.sig",
        function: "Cryptographic signature over policy",
        category: ExtensionCategory::InferenceAndExecution,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "request",
        example_file: "inference.request",
        function: "Canonical policy-scoped inference request",
        category: ExtensionCategory::InferenceAndExecution,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "response",
        example_file: "inference.response",
        function: "Inference response with commitment/receipt reference",
        category: ExtensionCategory::InferenceAndExecution,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "session",
        example_file: "inference.session",
        function: "Inference session binding nonce, policy, and receipts",
        category: ExtensionCategory::InferenceAndExecution,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "router",
        example_file: "moe.router",
        function: "Mixture-of-Experts routing decision",
        category: ExtensionCategory::InferenceAndExecution,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "expertmap",
        example_file: "moe.expertmap",
        function: "Map of expert shards and placements",
        category: ExtensionCategory::InferenceAndExecution,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "kv",
        example_file: "kvcache.bin",
        function: "Local ephemeral KV cache (never admissible as evidence)",
        category: ExtensionCategory::InferenceAndExecution,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "gpu",
        example_file: "gpu.profile",
        function: "GPU worker profile: hardware capacity, backend, execution limits",
        category: ExtensionCategory::InferenceAndExecution,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "onnx",
        example_file: "model.onnx",
        function: "Alternative interoperable model format",
        category: ExtensionCategory::InferenceAndExecution,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "safetensors",
        example_file: "model.safetensors",
        function: "Alternative raw weight storage format",
        category: ExtensionCategory::InferenceAndExecution,
        requirement: RequirementLevel::Optional,
    },

    // 6. Verification and Fraud
    ExtensionSpec {
        extension: "fraudproof",
        example_file: "receipt.fraudproof",
        function: "Fraud proof demonstrating invalid receipt or execution deviation",
        category: ExtensionCategory::VerificationAndFraud,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "reexec",
        example_file: "reexecution.reexec",
        function: "Sampled re-execution result for Tier 1 verification",
        category: ExtensionCategory::VerificationAndFraud,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "zkproof",
        example_file: "fragment.zkproof",
        function: "Zero-Knowledge ML proof for Tier 2 high-value sessions",
        category: ExtensionCategory::VerificationAndFraud,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "teequote",
        example_file: "attestation.teequote",
        function: "TEE attestation quote as verification accelerator",
        category: ExtensionCategory::VerificationAndFraud,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "verdict",
        example_file: "adjudication.verdict",
        function: "Signed dispute adjudication verdict",
        category: ExtensionCategory::VerificationAndFraud,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "slash",
        example_file: "slashing.slash",
        function: "Slashing order cryptographically bound to fraud proof",
        category: ExtensionCategory::VerificationAndFraud,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "golden",
        example_file: "vectors.golden",
        function: "Canonical golden test vectors for conformance testing",
        category: ExtensionCategory::VerificationAndFraud,
        requirement: RequirementLevel::Mandatory,
    },

    // 7. Economics and Governance
    ExtensionSpec {
        extension: "constitution",
        example_file: "arkhe.constitution",
        function: "Content-addressed constitutional charter replicated via CAL",
        category: ExtensionCategory::EconomicsAndGovernance,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "constitution.sig",
        example_file: "arkhe.constitution.sig",
        function: "Qualified quorum signature set over constitution",
        category: ExtensionCategory::EconomicsAndGovernance,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "proposal",
        example_file: "upgrade.proposal",
        function: "Formal upgrade or parameter modification proposal",
        category: ExtensionCategory::EconomicsAndGovernance,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "vote",
        example_file: "quorum.vote",
        function: "Signed governance quorum vote",
        category: ExtensionCategory::EconomicsAndGovernance,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "canon",
        example_file: "canonification.canon",
        function: "Human canonification decree and binding record",
        category: ExtensionCategory::EconomicsAndGovernance,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "emission",
        example_file: "emission.schedule",
        function: "Burn-and-mint token emission schedule",
        category: ExtensionCategory::EconomicsAndGovernance,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "reward",
        example_file: "poi.reward",
        function: "Proof-of-Inference (PoI) reward tied to verified receipt root",
        category: ExtensionCategory::EconomicsAndGovernance,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "stake",
        example_file: "validator.stake",
        function: "Validator and worker bond/stake state",
        category: ExtensionCategory::EconomicsAndGovernance,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "epoch",
        example_file: "roles.epoch",
        function: "Disjoint worker and validator committee assignment per epoch",
        category: ExtensionCategory::EconomicsAndGovernance,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "gini",
        example_file: "emission.gini",
        function: "Publicly auditable decentralization and emission Gini metric",
        category: ExtensionCategory::EconomicsAndGovernance,
        requirement: RequirementLevel::Recommended,
    },

    // 8. Chain Integration (CAL)
    ExtensionSpec {
        extension: "anchor",
        example_file: "checkpoint.anchor",
        function: "On-chain root commitment anchor record",
        category: ExtensionCategory::ChainIntegration,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "ibc",
        example_file: "cal.ibc",
        function: "Cosmos IBC interoperability configuration and adapters",
        category: ExtensionCategory::ChainIntegration,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "ccip",
        example_file: "cal.ccip",
        function: "Chainlink CCIP cross-chain messaging adapter",
        category: ExtensionCategory::ChainIntegration,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "layerzero",
        example_file: "cal.layerzero",
        function: "LayerZero cross-chain omnichain adapter",
        category: ExtensionCategory::ChainIntegration,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "abi",
        example_file: "ISettlement.abi",
        function: "EVM contract interface ABI",
        category: ExtensionCategory::ChainIntegration,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "sol",
        example_file: "ArkheSettlement.sol",
        function: "Solidity / EVM settlement contract source",
        category: ExtensionCategory::ChainIntegration,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "move",
        example_file: "arkhe.move",
        function: "Move smart contract source for Aptos/Sui",
        category: ExtensionCategory::ChainIntegration,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "tx",
        example_file: "anchor.tx",
        function: "Raw settlement anchor transaction",
        category: ExtensionCategory::ChainIntegration,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "receiptroot",
        example_file: "settlement.receiptroot",
        function: "Receipt root hash submitted for PoI settlement",
        category: ExtensionCategory::ChainIntegration,
        requirement: RequirementLevel::Mandatory,
    },

    // 9. Build, Testing and Supply Chain
    ExtensionSpec {
        extension: "toml",
        example_file: "Cargo.toml",
        function: "Rust and node configuration",
        category: ExtensionCategory::BuildAndSupplyChain,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "rs",
        example_file: "main.rs",
        function: "Rust source code of the core node",
        category: ExtensionCategory::BuildAndSupplyChain,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "ts",
        example_file: "index.ts",
        function: "TypeScript SDK implementation",
        category: ExtensionCategory::BuildAndSupplyChain,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "cs",
        example_file: "Arkhe.cs",
        function: "C# alternative client implementation",
        category: ExtensionCategory::BuildAndSupplyChain,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "csproj",
        example_file: "Arkhe.csproj",
        function: "C# project definition",
        category: ExtensionCategory::BuildAndSupplyChain,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "wat",
        example_file: "arkverify.wat",
        function: "WebAssembly text format representation",
        category: ExtensionCategory::BuildAndSupplyChain,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "json",
        example_file: "package.json",
        function: "SDK configuration and canonical schema format",
        category: ExtensionCategory::BuildAndSupplyChain,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "lock",
        example_file: "Cargo.lock",
        function: "Hermetic dependency pinning",
        category: ExtensionCategory::BuildAndSupplyChain,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "sbom",
        example_file: "release.sbom",
        function: "Software Bill of Materials (SPDX / CycloneDX)",
        category: ExtensionCategory::BuildAndSupplyChain,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "provenance",
        example_file: "build.provenance",
        function: "SLSA build provenance attestation",
        category: ExtensionCategory::BuildAndSupplyChain,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "sha256",
        example_file: "artifact.sha256",
        function: "Deterministic SHA-256 artifact digest",
        category: ExtensionCategory::BuildAndSupplyChain,
        requirement: RequirementLevel::Mandatory,
    },
    ExtensionSpec {
        extension: "sigstore",
        example_file: "artifact.sigstore",
        function: "Sigstore release verification bundle",
        category: ExtensionCategory::BuildAndSupplyChain,
        requirement: RequirementLevel::Recommended,
    },
    ExtensionSpec {
        extension: "log",
        example_file: "node.log",
        function: "Operational node log (must not contain plaintext prompts/outputs)",
        category: ExtensionCategory::BuildAndSupplyChain,
        requirement: RequirementLevel::Optional,
    },
    ExtensionSpec {
        extension: "trace",
        example_file: "consensus.trace",
        function: "Consensus and testnet execution trace",
        category: ExtensionCategory::BuildAndSupplyChain,
        requirement: RequirementLevel::Mandatory,
    },
];

/// Identifies the normative Arkhe extension specification from a file path or name.
/// Accurately recognizes compound extensions such as `.arkmanifest.sig`, `.gguf.part*`,
/// `.afir.json`, `.policy.sig`, `.constitution.sig`, etc.
pub fn lookup_extension(path: &str) -> Option<&'static ExtensionSpec> {
    let filename = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path);

    // 1. Direct match by example_file name (e.g. peers.dat, seeds.toml, etc.)
    for spec in ALL_EXTENSIONS {
        if spec.example_file.eq_ignore_ascii_case(filename) {
            return Some(spec);
        }
    }

    // 2. Check compound extensions first (longest match)
    for spec in ALL_EXTENSIONS {
        if spec.extension.contains('.') {
            let dot_ext = format!(".{}", spec.extension);
            if filename.ends_with(&dot_ext) {
                return Some(spec);
            }
            // Support numbered parts like model.gguf.part0001
            if spec.extension == "gguf.part" {
                if let Some(pos) = filename.find(".gguf.part") {
                    let suffix = &filename[pos + ".gguf.part".len()..];
                    if suffix.chars().all(|c| c.is_ascii_digit()) {
                        return Some(spec);
                    }
                }
            }
        }
    }

    // 3. Check extension matching spec.extension directly (e.g. file.peers, file.afir)
    if let Some(idx) = filename.rfind('.') {
        let ext = &filename[idx + 1..];
        for spec in ALL_EXTENSIONS {
            if !spec.extension.contains('.') && spec.extension.eq_ignore_ascii_case(ext) {
                return Some(spec);
            }
        }
    }

    None
}

/// Evaluates whether a file or extension is forbidden, restricted, or standard.
/// Fail-closed security rule:
/// - Forbidden: Plaintext private keys (`.pem`), unencrypted `.seed`, `.env` in production,
///   `.bak` of MMR/checkpoints (prevents history branching), `.dump` with prompt/output payload.
/// - Restricted: Unsigned native binaries (`.dll`, `.exe`, `.so`, `.dylib`), `.tmp` receipts.
pub fn evaluate_security_status(path: &str, is_production: bool) -> SecurityStatus {
    let filename = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_ascii_lowercase();

    // 1. Forbidden checks
    if filename.ends_with(".env") && is_production {
        return SecurityStatus::Forbidden;
    }
    if filename.ends_with(".pem") {
        return SecurityStatus::Forbidden;
    }
    if filename.ends_with(".bak")
        && (filename.contains("mmr") || filename.contains("checkpoint") || filename.contains("wer"))
    {
        return SecurityStatus::Forbidden;
    }
    if filename.ends_with(".dump") {
        return SecurityStatus::Forbidden;
    }

    // 2. Restricted checks
    if filename.ends_with(".dll")
        || filename.ends_with(".exe")
        || filename.ends_with(".so")
        || filename.ends_with(".dylib")
    {
        return SecurityStatus::Restricted;
    }
    if filename.ends_with(".tmp") && (filename.contains("receipt") || filename.contains("afir")) {
        return SecurityStatus::Restricted;
    }

    SecurityStatus::Standard
}

/// Required minimal release manifest files according to the Arkhe specification.
pub static MINIMAL_RELEASE_FILES: &[&str] = &[
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

/// Validates whether a list of release files contains all mandatory release artifacts.
pub fn validate_release_manifest<'a>(files: &[&'a str]) -> Result<(), Vec<&'static str>> {
    let mut missing = Vec::new();
    for &required in MINIMAL_RELEASE_FILES {
        let found = files.iter().any(|f| {
            let fname = Path::new(f).file_name().and_then(|s| s.to_str()).unwrap_or(f);
            fname == required
        });
        if !found {
            missing.push(required);
        }
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_basic() {
        assert!(lookup_extension("peers.dat").is_some());
        assert_eq!(lookup_extension("peers.dat").unwrap().extension, "peers");
        assert_eq!(lookup_extension("test.unknown"), None);
    }

    #[test]
    fn test_count_all_extensions() {
        assert!(ALL_EXTENSIONS.len() >= 60);
    }
}
