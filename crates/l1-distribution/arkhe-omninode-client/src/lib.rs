use arkhe_core::Digest32;

pub fn blake3_to_cidv1(hash: &Digest32) -> String {
    format!("bafk{}", hex::encode(&hash[..16]))
}
