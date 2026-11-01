use serde::{Deserialize, Serialize};
use arkhe_core::{digest_all, Digest32};
use arkhe_crypto::HybridCheckpointEnvelope;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrProof {
    pub leaf_index: usize,
    pub leaf_count: usize,
    pub peaks: Vec<Digest32>,
    pub bagged_root: Digest32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalMmr {
    leaves: Vec<Digest32>,
}

impl LocalMmr {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn append(&mut self, leaf: Digest32) -> usize {
        let idx = self.leaves.len();
        self.leaves.push(leaf);
        idx
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    pub fn compute_peaks(&self) -> Vec<Digest32> {
        if self.leaves.is_empty() {
            return Vec::new();
        }
        let mut peaks = Vec::new();
        let mut idx = 0;
        let mut step = 1;
        while idx < self.leaves.len() {
            let end = (idx + step).min(self.leaves.len());
            let mut acc = self.leaves[idx];
            for i in (idx + 1)..end {
                acc = digest_all(&[&acc, &self.leaves[i]]);
            }
            peaks.push(acc);
            idx = end;
            step *= 2;
        }
        peaks
    }

    pub fn compute_bagged_root(&self) -> Digest32 {
        let peaks = self.compute_peaks();
        if peaks.is_empty() {
            return [0u8; 32];
        }
        let mut root = peaks[0];
        for peak in &peaks[1..] {
            root = digest_all(&[&root, peak]);
        }
        root
    }

    pub fn generate_proof(&self, leaf_index: usize) -> Option<MmrProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }
        Some(MmrProof {
            leaf_index,
            leaf_count: self.leaves.len(),
            peaks: self.compute_peaks(),
            bagged_root: self.compute_bagged_root(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalCheckpoint {
    pub sequence: u64,
    pub bagged_root: Digest32,
    pub leaf_count: usize,
    pub envelope: HybridCheckpointEnvelope,
}

impl LocalCheckpoint {
    pub fn new(
        sequence: u64,
        bagged_root: Digest32,
        leaf_count: usize,
        timestamp: u64,
        strongbox_mldsa_sig: Vec<u8>,
        tee_ed25519_sig: Vec<u8>,
    ) -> Self {
        let envelope = HybridCheckpointEnvelope::new(
            bagged_root,
            sequence,
            timestamp,
            strongbox_mldsa_sig,
            tee_ed25519_sig,
        );
        Self {
            sequence,
            bagged_root,
            leaf_count,
            envelope,
        }
    }
}

pub struct StrongBoxStorage {
    pub mmr: LocalMmr,
    pub checkpoints: Vec<LocalCheckpoint>,
}

impl StrongBoxStorage {
    pub fn new() -> Self {
        Self {
            mmr: LocalMmr::new(),
            checkpoints: Vec::new(),
        }
    }

    pub fn seal_checkpoint(
        &mut self,
        timestamp: u64,
        mldsa_sig: Vec<u8>,
        ed25519_sig: Vec<u8>,
    ) -> LocalCheckpoint {
        let seq = self.checkpoints.len() as u64;
        let root = self.mmr.compute_bagged_root();
        let count = self.mmr.leaf_count();
        let cp = LocalCheckpoint::new(seq, root, count, timestamp, mldsa_sig, ed25519_sig);
        self.checkpoints.push(cp.clone());
        cp
    }
}
