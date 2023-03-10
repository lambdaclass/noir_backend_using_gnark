use super::{from_felt, num_constraints, serialize::serialize_felts};
use crate::acvm;
use crate::gnark_backend_wrapper::c_go_structures::{GoString, KeyPair};
use crate::gnark_backend_wrapper::errors::GnarkBackendError;
use std::ffi::{CStr, CString};
use std::num::TryFromIntError;
use std::os::raw::{c_char, c_uchar};

extern "C" {
    fn PlonkVerifyWithMeta(acir: GoString, encoded_values: GoString, proof: GoString) -> c_uchar;
    fn PlonkProveWithMeta(acir: GoString, encoded_values: GoString) -> *const c_char;
    fn PlonkVerifyWithVK(
        acir: GoString,
        proof: GoString,
        public_inputs: GoString,
        verifying_key: GoString,
    ) -> c_uchar;
    fn PlonkProveWithPK(
        acir: GoString,
        encoded_values: GoString,
        proving_key: GoString,
    ) -> *const c_char;
    fn PlonkPreprocess(acir: GoString, encoded_random_values: GoString) -> KeyPair;
}

pub fn prove_with_meta(
    circuit: acvm::Circuit,
    values: Vec<acvm::FieldElement>,
) -> Result<Vec<u8>, GnarkBackendError> {
    // Serialize to json and then convert to GoString
    let acir_json = serde_json::to_string(&circuit)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let acir_c_str = CString::new(acir_json)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let acir_go_string = GoString::try_from(&acir_c_str)?;

    let felts: Vec<super::Fr> = values.into_iter().map(from_felt).collect();
    let felts_serialized: Vec<u8> = Vec::new();
    let mut serializer = serde_json::Serializer::new(felts_serialized);
    serialize_felts(&felts, &mut serializer)
        .map_err(|e| GnarkBackendError::SerializeFeltsError(e.to_string()))?;
    let encoded_felts = String::from_utf8(serializer.into_inner())
        .map_err(|e| GnarkBackendError::SerializeFeltsError(e.to_string()))?;
    let felts_c_str = CString::new(encoded_felts)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let values_go_string = GoString::try_from(&felts_c_str)?;

    let result: *const c_char = unsafe { PlonkProveWithMeta(acir_go_string, values_go_string) };
    let c_str = unsafe { CStr::from_ptr(result) };
    let bytes = c_str
        .to_str()
        .map_err(|e| GnarkBackendError::DeserializeProofError(e.to_string()))?
        .as_bytes();

    Ok(bytes.to_vec())
}

pub fn prove_with_pk(
    circuit: &acvm::Circuit,
    values: Vec<acvm::FieldElement>,
    proving_key: &[u8],
) -> Result<Vec<u8>, GnarkBackendError> {
    // Serialize to json and then convert to GoString
    let acir_json = serde_json::to_string(&circuit)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let acir_c_str = CString::new(acir_json)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let acir_go_string = GoString::try_from(&acir_c_str)?;

    let felts: Vec<super::Fr> = values.into_iter().map(from_felt).collect();
    let felts_serialized: Vec<u8> = Vec::new();
    let mut serializer = serde_json::Serializer::new(felts_serialized);
    serialize_felts(&felts, &mut serializer)
        .map_err(|e| GnarkBackendError::SerializeFeltsError(e.to_string()))?;
    let encoded_felts = String::from_utf8(serializer.into_inner())
        .map_err(|e| GnarkBackendError::SerializeFeltsError(e.to_string()))?;
    let felts_c_str = CString::new(encoded_felts)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let values_go_string = GoString::try_from(&felts_c_str)?;

    let proving_key_serialized = hex::encode(proving_key);
    let proving_key_c_str = CString::new(proving_key_serialized)
        .map_err(|e| GnarkBackendError::SerializeKeyError(e.to_string()))?;
    let proving_key_go_string = GoString::try_from(&proving_key_c_str)
        .map_err(|e| GnarkBackendError::SerializeKeyError(e.to_string()))?;

    let proof: *const c_char =
        unsafe { PlonkProveWithPK(acir_go_string, values_go_string, proving_key_go_string) };
    let proof_c_str = unsafe { CStr::from_ptr(proof) };
    let proof_str = proof_c_str
        .to_str()
        .map_err(|e| GnarkBackendError::DeserializeProofError(e.to_string()))?;
    let decoded_proof = hex::decode(proof_str)
        .map_err(|e| GnarkBackendError::DeserializeProofError(e.to_string()))?;

    Ok(decoded_proof)
}

pub fn verify_with_meta(
    circuit: acvm::Circuit,
    proof: &[u8],
    public_inputs: &[acvm::FieldElement],
) -> Result<bool, GnarkBackendError> {
    // Serialize to json and then convert to GoString
    let acir_json = serde_json::to_string(&circuit)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let acir_c_str = CString::new(acir_json)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let acir_go_string = GoString::try_from(&acir_c_str)?;

    let felts: Vec<super::Fr> = public_inputs.iter().cloned().map(from_felt).collect();
    let felts_serialized: Vec<u8> = Vec::new();
    let mut serializer = serde_json::Serializer::new(felts_serialized);
    serialize_felts(&felts, &mut serializer)
        .map_err(|e| GnarkBackendError::SerializeFeltsError(e.to_string()))?;
    let encoded_felts = String::from_utf8(serializer.into_inner())
        .map_err(|e| GnarkBackendError::SerializeFeltsError(e.to_string()))?;
    let felts_c_str = CString::new(encoded_felts)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let values_go_string = GoString::try_from(&felts_c_str)?;

    let serialized_proof = String::from_utf8(proof.to_vec())
        .map_err(|e| GnarkBackendError::SerializeProofError(e.to_string()))?;
    let c_str = CString::new(serialized_proof)
        .map_err(|e| GnarkBackendError::SerializeProofError(e.to_string()))?;
    let go_string_proof = GoString::try_from(&c_str)?;

    let result = unsafe { PlonkVerifyWithMeta(acir_go_string, values_go_string, go_string_proof) };
    match result {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(GnarkBackendError::VerifyInvalidBoolError),
    }
}

pub fn verify_with_vk(
    circuit: &acvm::Circuit,
    proof: &[u8],
    public_inputs: &[acvm::FieldElement],
    verifying_key: &[u8],
) -> Result<bool, GnarkBackendError> {
    // Serialize to json and then convert to GoString
    let acir_json = serde_json::to_string(&circuit)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let acir_c_str = CString::new(acir_json)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let acir_go_string = GoString::try_from(&acir_c_str)?;

    let felts: Vec<super::Fr> = public_inputs.iter().cloned().map(from_felt).collect();
    let encoded_felts = serialize::encode_felts(&felts)?;
    let felts_c_str = CString::new(encoded_felts)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let public_inputs_go_string = GoString::try_from(&felts_c_str)?;

    let proof_serialized = hex::encode(proof);
    let proof_c_str = CString::new(proof_serialized)
        .map_err(|e| GnarkBackendError::SerializeProofError(e.to_string()))?;
    let proof_go_string = GoString::try_from(&proof_c_str)?;

    let verifying_key_serialized = hex::encode(verifying_key);
    let verifying_key_c_str = CString::new(verifying_key_serialized)
        .map_err(|e| GnarkBackendError::SerializeKeyError(e.to_string()))?;
    let verifying_key_go_string = GoString::try_from(&verifying_key_c_str)?;

    let verifies = unsafe {
        PlonkVerifyWithVK(
            acir_go_string,
            public_inputs_go_string,
            proof_go_string,
            verifying_key_go_string,
        )
    };
    match verifies {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(GnarkBackendError::VerifyInvalidBoolError),
    }
}

pub fn get_exact_circuit_size(circuit: &acvm::Circuit) -> Result<u32, GnarkBackendError> {
    let size: u32 = num_constraints(circuit)?
        .try_into()
        .map_err(|e: TryFromIntError| GnarkBackendError::Error(e.to_string()))?;
    Ok(size)
}

pub fn preprocess(circuit: &acvm::Circuit) -> Result<(Vec<u8>, Vec<u8>), GnarkBackendError> {
    let num_witnesses: usize = circuit
        .num_vars()
        .try_into()
        .map_err(|e: TryFromIntError| GnarkBackendError::Error(e.to_string()))?;

    // Serialize to json and then convert to GoString
    let acir_json = serde_json::to_string(&circuit)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let acir_c_str = CString::new(acir_json)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let acir_go_string = GoString::try_from(&acir_c_str)?;

    let random_values: Vec<super::Fr> = vec![rand::random(); num_witnesses - 1];
    let serialized_random_values: Vec<u8> = Vec::new();
    let mut serializer = serde_json::Serializer::new(serialized_random_values);
    serialize_felts(&random_values, &mut serializer)
        .map_err(|e| GnarkBackendError::SerializeFeltsError(e.to_string()))?;
    let encoded_random_values = String::from_utf8(serializer.into_inner())
        .map_err(|e| GnarkBackendError::SerializeFeltsError(e.to_string()))?;
    let random_values_c_str = CString::new(encoded_random_values)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let random_values_go_string = GoString::try_from(&random_values_c_str)?;

    let key_pair: KeyPair = unsafe { PlonkPreprocess(acir_go_string, random_values_go_string) };

    let proving_key_c_str = unsafe { CStr::from_ptr(key_pair.proving_key) };
    let proving_key_str = proving_key_c_str
        .to_str()
        .map_err(|e| GnarkBackendError::DeserializeKeyError(e.to_string()))?;
    let decoded_proving_key = hex::decode(proving_key_str)
        .map_err(|e| GnarkBackendError::DeserializeKeyError(e.to_string()))?;

    let verifying_key_c_str = unsafe { CStr::from_ptr(key_pair.verifying_key) };
    let verifying_key_str = verifying_key_c_str
        .to_str()
        .map_err(|e| GnarkBackendError::DeserializeKeyError(e.to_string()))?;
    let decoded_verifying_key = hex::decode(verifying_key_str)
        .map_err(|e| GnarkBackendError::DeserializeKeyError(e.to_string()))?;

    Ok((decoded_proving_key, decoded_verifying_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_go_string_from_cstring() {
        let string = "This works".to_owned();
        let c_str = CString::new(string.clone()).unwrap();
        let go_string = GoString::try_from(&c_str).unwrap();
        let deserialized_c_str = unsafe { CStr::from_ptr(go_string.ptr) };
        let deserialized_string = deserialized_c_str.to_str().unwrap().to_owned();
        assert_eq!(string, deserialized_string);
    }

    #[test]
    fn get_exact_circuit_size_should_return_zero_with_an_empty_circuit() {
        let size = get_exact_circuit_size(&acvm::Circuit::default()).unwrap();
        assert_eq!(size, 0);
    }
}
