use thiserror::Error;

#[derive(Error, Debug)]
pub enum GnarkBackendError {
    #[error("an error occurred while serializing the circuit: {0}")]
    SerializeCircuitError(String),
    #[error("an error occurred while serializing a key: {0}")]
    SerializeKeyError(String),
    #[error("an error occurred while deserializing a proof: {0}")]
    DeserializeProofError(String),
    #[error("an error occurred")]
    Error,
}
