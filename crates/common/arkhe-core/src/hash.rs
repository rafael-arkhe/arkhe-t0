use sha2::{Digest, Sha256};

pub type Digest32 = [u8; 32];

pub fn digest(data: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn digest_all(slices: &[&[u8]]) -> Digest32 {
    let mut hasher = Sha256::new();
    for s in slices {
        hasher.update(s);
    }
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
