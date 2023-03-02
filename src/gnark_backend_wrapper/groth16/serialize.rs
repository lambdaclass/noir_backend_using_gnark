use std::num::TryFromIntError;

use super::{
    acir_to_r1cs::{AddTerm, MulTerm},
    errors::GnarkBackendError,
};
use crate::gnark_backend_wrapper as gnark_backend;
use ark_serialize::CanonicalSerialize;
use serde::{ser::SerializeStruct, Serialize};

impl Serialize for MulTerm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut serialized_coefficient = Vec::new();
        self.coefficient
            .serialize_uncompressed(&mut serialized_coefficient)
            .map_err(serde::ser::Error::custom)?;
        // Turn little-endian to big-endian.
        serialized_coefficient.reverse();
        let encoded_coefficient = hex::encode(serialized_coefficient);

        let mut s = serializer.serialize_struct("MulTerm", 3)?;
        s.serialize_field("coefficient", &encoded_coefficient)?;
        s.serialize_field("multiplicand", &self.multiplicand)?;
        s.serialize_field("multiplier", &self.multiplier)?;
        s.end()
    }
}

impl Serialize for AddTerm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut serialized_coefficient = Vec::new();
        self.coefficient
            .serialize_uncompressed(&mut serialized_coefficient)
            .map_err(serde::ser::Error::custom)?;
        // Turn little-endian to big-endian.
        serialized_coefficient.reverse();
        let encoded_coefficient = hex::encode(serialized_coefficient);

        let mut s = serializer.serialize_struct("AddTerm", 2)?;
        s.serialize_field("coefficient", &encoded_coefficient)?;
        s.serialize_field("sum", &self.sum)?;
        s.end()
    }
}

pub fn serialize_felt_unchecked(
    felt: &gnark_backend::groth16::Fr,
) -> Result<Vec<u8>, GnarkBackendError> {
    let mut serialized_felt = Vec::new();
    felt.serialize_uncompressed(&mut serialized_felt)
        .map_err(|e| GnarkBackendError::SerializeFeltError(e.to_string()))?;
    // Turn little-endian to big-endian.
    serialized_felt.reverse();
    Ok(serialized_felt)
}

pub fn serialize_felt<S>(
    felt: &gnark_backend::groth16::Fr,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::ser::Serializer,
{
    let mut serialized_felt = Vec::new();
    felt.serialize_uncompressed(&mut serialized_felt)
        .map_err(serde::ser::Error::custom)?;
    // Turn little-endian to big-endian.
    serialized_felt.reverse();
    let encoded_coefficient = hex::encode(serialized_felt);
    serializer.serialize_str(&encoded_coefficient)
}

pub fn serialize_felts<S>(
    felts: &[gnark_backend::groth16::Fr],
    serializer: S,
) -> Result<S::Ok, GnarkBackendError>
where
    S: serde::ser::Serializer,
{
    let mut buff: Vec<u8> = Vec::new();
    let n_felts: u32 = felts
        .len()
        .try_into()
        .map_err(|e: TryFromIntError| GnarkBackendError::SerializeFeltError(e.to_string()))?;
    buff.extend_from_slice(&n_felts.to_be_bytes());

    felts.iter().try_for_each(|felt| {
        let serialized_felt = serialize_felt_unchecked(felt)?;
        buff.extend_from_slice(&serialized_felt);
        Ok::<_, GnarkBackendError>(())
    })?;
    let encoded_buff = hex::encode(buff);
    serializer
        .serialize_str(&encoded_buff)
        .map_err(|e: S::Error| GnarkBackendError::SerializeFeltError(e.to_string()))
}
