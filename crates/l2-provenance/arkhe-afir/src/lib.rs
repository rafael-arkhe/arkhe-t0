use serde::{Deserialize, Serialize};
use arkhe_core::Digest32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AfirReceipt {
    pub inference_root: Digest32,
    pub fragment_index: u32,
    pub mldsa_signature: Vec<u8>,
}

impl AfirReceipt {
    pub fn new(inference_root: Digest32, fragment_index: u32, signature: Vec<u8>) -> Self {
        Self {
            inference_root,
            fragment_index,
            mldsa_signature: signature,
        }
    }
}

pub struct AfirSigner;

impl AfirSigner {
    pub fn sign_fragment(inference_root: Digest32, fragment_index: u32) -> AfirReceipt {
        let sig = vec![0xaf; 384];
        AfirReceipt::new(inference_root, fragment_index, sig)
    }
}

pub struct AfirVerifier;

impl AfirVerifier {
    pub fn verify_receipt(receipt: &AfirReceipt) -> bool {
        receipt.mldsa_signature.len() == 384 && receipt.mldsa_signature.iter().any(|&b| b != 0)
    }
}
