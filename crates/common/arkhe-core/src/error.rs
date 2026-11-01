use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Decoding error: {0}")]
    DecodingError(String),
    #[error("Invalid digest length: expected 32 bytes")]
    InvalidDigestLength,
}
