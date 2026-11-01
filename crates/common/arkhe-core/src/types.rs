use serde::{Deserialize, Serialize};
use crate::hash::Digest32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalRecord {
    pub domain: String,
    pub payload_digest: Digest32,
    pub timestamp: u64,
}
