use thiserror::Error;

#[derive(Error, Debug)]
pub enum GnarkBackendError {
    #[error("an error occurred while serializing the circuit: {0}")]
    SerializeCircuitError(String),

    #[error("an error occurred while serializing a key: {0}")]
    SerializeKeyError(String),

    #[error("an error occurred while serializing a proof: {0}")]
    SerializeProofError(String),

    #[error("an error occurred while deserializing a proof: {0}")]
    DeserializeProofError(String),

    #[error("an error occurred while deserializing a key: {0}")]
    DeserializeKeyError(String),

    #[error("currently we do not support non-arithmetic opcodes {0}")]
    UnsupportedOpcodeError(String),

    #[error("Verify did not return a valid bool")]
    VerifyInvalidBoolError,

    #[error("an error occurred: {0}")]
    Error(String),
}
