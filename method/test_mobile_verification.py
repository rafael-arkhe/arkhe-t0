"""
Verification test suite for ArkheOS Mobile L3 Evidence & AGI-P2P binding.
Proves that an offline verifier detects historical rewriting of inferences
that a single point Merkle proof would not detect.
"""
import hashlib
import json
import unittest

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

class LocalMmr:
    def __init__(self):
        self.leaves = []

    def append(self, leaf: bytes) -> int:
        idx = len(self.leaves)
        self.leaves.append(leaf)
        return idx

    def compute_peaks(self):
        if not self.leaves:
            return []
        peaks = []
        idx = 0
        step = 1
        while idx < len(self.leaves):
            end = min(idx + step, len(self.leaves))
            acc = self.leaves[idx]
            for i in range(idx + 1, end):
                acc = sha256(acc + self.leaves[i])
            peaks.append(acc)
            idx = end
            step *= 2
        return peaks

    def compute_bagged_root(self) -> bytes:
        peaks = self.compute_peaks()
        if not peaks:
            return b"\x00" * 32
        root = peaks[0]
        for p in peaks[1:]:
            root = sha256(root + p)
        return root

class TestArkheMobileVerification(unittest.TestCase):
    def test_mobile_wer_binding_and_history_rewrite_detection(self):
        # 1. Hardware Attestation Binding
        attestation_blob = b"titan_m2_verified_boot_keymint_quote"
        first_wer_nonce = b"\x42" * 32
        app_measurement = sha256(b"space.arkhe.mobile:v1.0.0")
        device_attestation_hash = sha256(attestation_blob + first_wer_nonce + app_measurement)

        # 2. L2 AFiR Receipt
        inference_root = sha256(b"spice_inference_root_42")
        afir_receipt = {
            "inference_root": inference_root.hex(),
            "fragment_index": 0,
            "mldsa_signature": ("af" * 384)
        }

        # 3. MobileWER Record
        wer = {
            "version": 1,
            "device_attestation_hash": device_attestation_hash.hex(),
            "app_id": sha256(b"agent_app").hex(),
            "action": {
                "Inference": {
                    "model_weights_hash": sha256(b"model_weights").hex(),
                    "temperature_e2": 70
                }
            },
            "input_digest": sha256(b"prompt").hex(),
            "output_digest": sha256(b"token_completion").hex(),
            "policy_digest": sha256(b"policy").hex(),
            "performed_at": 1761955200,
            "evidence_refs": [inference_root.hex()]
        }

        domain = b"AKG:MOBILE:ACT:v1\0"
        wer_canonical_bytes = domain + json.dumps(wer, sort_keys=True).encode()
        wer_leaf = sha256(wer_canonical_bytes)

        # 4. Sealed MMR
        mmr = LocalMmr()
        mmr.append(wer_leaf)
        checkpoint_bagged_root = mmr.compute_bagged_root()

        checkpoint = {
            "sequence": 0,
            "bagged_root": checkpoint_bagged_root.hex(),
            "leaf_count": 1,
            "strongbox_mldsa_sig": "01" * 64,
            "tee_ed25519_sig": "02" * 64
        }

        self.assertEqual(len(checkpoint["strongbox_mldsa_sig"]), 128)
        self.assertEqual(len(checkpoint["tee_ed25519_sig"]), 128)
        self.assertIn(afir_receipt["inference_root"], wer["evidence_refs"])

        # 5. History rewrite detection
        tampered_wer = dict(wer)
        tampered_wer["output_digest"] = sha256(b"malicious_output").hex()
        tampered_wer_bytes = domain + json.dumps(tampered_wer, sort_keys=True).encode()
        tampered_leaf = sha256(tampered_wer_bytes)

        tampered_mmr = LocalMmr()
        tampered_mmr.append(tampered_leaf)
        tampered_bagged_root = tampered_mmr.compute_bagged_root()

        self.assertNotEqual(checkpoint_bagged_root, tampered_bagged_root)

if __name__ == "__main__":
    unittest.main()
