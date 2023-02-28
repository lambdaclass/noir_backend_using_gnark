use thiserror::Error;

#[derive(Error, Debug)]
pub enum GnarkBackendError {
    #[error("an error occured while serializing the circuit")]
    SerializeCircuitError,
    #[error("an error occured while serializing a key")]
    SerializeKeyError,
    #[error("an error occured while deserializing a proof")]
    DeserializeProofError,
    #[error("some error")]
    Error,
}
