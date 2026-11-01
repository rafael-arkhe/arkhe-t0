pub mod error;
pub mod hash;
pub mod types;

pub use error::CoreError;
pub use hash::{digest, digest_all, Digest32};
