use std::ffi::{CStr, CString};
use std::num::TryFromIntError;
use std::os::raw::{c_char, c_uchar};

use acvm::{acir::circuit::Circuit, FieldElement};
mod acir_to_r1cs;
mod errors;
mod serialize;
use crate::gnark_backend_wrapper::acir_to_r1cs::RawR1CS;
use crate::gnark_backend_wrapper::errors::GnarkBackendError;

// Arkworks's types are generic for `Field` but Noir's types are concrete and
// its value depends on the feature flag.
cfg_if::cfg_if! {
    if #[cfg(feature = "bn254")] {
        pub use ark_bn254::{Bn254 as Curve, Fr};

        // Converts a FieldElement to a Fr
        // noir_field uses arkworks for bn254
        #[allow(dead_code)]
        pub fn from_felt(felt: acvm::FieldElement) -> Fr {
            felt.into_repr()
        }
    } else if #[cfg(feature = "bls12_381")] {
        pub use ark_bls12_381::{Bls12_381 as Curve, Fr};

        // Converts a FieldElement to a Fr
        // noir_field uses arkworks for bls12_381
        pub fn from_felt(felt: FieldElement) -> Fr {
            felt.into_repr()
        }
    } else {
        compile_error!("please specify a field to compile with");
    }
}

extern "C" {
    fn VerifyWithMeta(rawr1cs: GoString, proof: GoString) -> c_uchar;
    fn ProveWithMeta(rawr1cs: GoString) -> *const c_char;
    fn VerifyWithVK(rawr1cs: GoString, proof: GoString, verifying_key: GoString) -> c_uchar;
    fn ProveWithPK(rawr1cs: GoString, proving_key: GoString) -> *const c_char;
    fn Preprocess(circuit: GoString) -> KeyPair;
}

#[derive(Debug)]
#[repr(C)]
struct GoString {
    ptr: *const c_char,
    length: usize,
}

impl TryFrom<&CString> for GoString {
    type Error = GnarkBackendError;

    fn try_from(value: &CString) -> std::result::Result<Self, Self::Error> {
        let ptr = value.as_ptr();
        let length = value.as_bytes().len();
        Ok(Self { ptr, length })
    }
}

#[repr(C)]
struct KeyPair {
    proving_key: *const c_char,
    verifying_key: *const c_char,
}

pub fn prove_with_meta(
    circuit: Circuit,
    values: Vec<FieldElement>,
) -> Result<Vec<u8>, GnarkBackendError> {
    let rawr1cs = RawR1CS::new(circuit, values)?;

    // Serialize to json and then convert to GoString
    let serialized_rawr1cs = serde_json::to_string(&rawr1cs)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let c_str = CString::new(serialized_rawr1cs)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let go_string_rawr1cs = GoString::try_from(&c_str)?;

    let result: *const c_char = unsafe { ProveWithMeta(go_string_rawr1cs) };
    let c_str = unsafe { CStr::from_ptr(result) };
    let bytes = c_str
        .to_str()
        .map_err(|e| GnarkBackendError::DeserializeProofError(e.to_string()))?
        .as_bytes();

    Ok(bytes.to_vec())
}

pub fn prove_with_pk(
    circuit: &Circuit,
    values: Vec<FieldElement>,
    proving_key: &[u8],
) -> Result<Vec<u8>, GnarkBackendError> {
    let rawr1cs = RawR1CS::new(circuit.clone(), values)?;

    // Serialize to json and then convert to GoString
    let rawr1cs_json = serde_json::to_string(&rawr1cs)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let rawr1cs_c_str = CString::new(rawr1cs_json)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let rawr1cs_go_string = GoString::try_from(&rawr1cs_c_str)?;

    let proving_key_serialized = String::from_utf8(proving_key.to_vec())
        .map_err(|e| GnarkBackendError::SerializeKeyError(e.to_string()))?;
    let proving_key_c_str = CString::new(proving_key_serialized)
        .map_err(|e| GnarkBackendError::SerializeKeyError(e.to_string()))?;
    let proving_key_go_string = GoString::try_from(&proving_key_c_str)
        .map_err(|e| GnarkBackendError::SerializeKeyError(e.to_string()))?;

    let result: *const c_char = unsafe { ProveWithPK(rawr1cs_go_string, proving_key_go_string) };
    let c_str = unsafe { CStr::from_ptr(result) };
    let bytes = c_str
        .to_str()
        .map_err(|e| GnarkBackendError::DeserializeProofError(e.to_string()))?
        .as_bytes();

    Ok(bytes.to_vec())
}

pub fn verify_with_meta(
    circuit: Circuit,
    proof: &[u8],
    public_inputs: &[FieldElement],
) -> Result<bool, GnarkBackendError> {
    let rawr1cs = RawR1CS::new(circuit, public_inputs.to_vec())?;

    // Serialize to json and then convert to GoString
    let rawr1cs_json = serde_json::to_string(&rawr1cs)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let c_str = CString::new(rawr1cs_json)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let go_string_rawr1cs = GoString::try_from(&c_str)?;

    let serialized_proof = String::from_utf8(proof.to_vec())
        .map_err(|e| GnarkBackendError::SerializeProofError(e.to_string()))?;
    let c_str = CString::new(serialized_proof)
        .map_err(|e| GnarkBackendError::SerializeProofError(e.to_string()))?;
    let go_string_proof = GoString::try_from(&c_str)?;

    let result = unsafe { VerifyWithMeta(go_string_rawr1cs, go_string_proof) };
    match result {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(GnarkBackendError::VerifyInvalidBoolError),
    }
}

pub fn verify_with_vk(
    circuit: &Circuit,
    proof: &[u8],
    public_inputs: &[FieldElement],
    verifying_key: &[u8],
) -> Result<bool, GnarkBackendError> {
    let rawr1cs = RawR1CS::new(circuit.clone(), public_inputs.to_vec())?;

    // Serialize to json and then convert to GoString
    let rawr1cs_json = serde_json::to_string(&rawr1cs)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let rawr1cs_c_str = CString::new(rawr1cs_json)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let rawr1cs_go_string = GoString::try_from(&rawr1cs_c_str)?;

    let proof_serialized = String::from_utf8(proof.to_vec())
        .map_err(|e| GnarkBackendError::SerializeProofError(e.to_string()))?;
    let proof_c_str = CString::new(proof_serialized)
        .map_err(|e| GnarkBackendError::SerializeProofError(e.to_string()))?;
    let proof_go_string = GoString::try_from(&proof_c_str)?;

    let verifying_key_serialized = String::from_utf8(verifying_key.to_vec())
        .map_err(|e| GnarkBackendError::SerializeKeyError(e.to_string()))?;
    let verifying_key_c_str = CString::new(verifying_key_serialized)
        .map_err(|e| GnarkBackendError::SerializeKeyError(e.to_string()))?;
    let verifying_key_go_string = GoString::try_from(&verifying_key_c_str)?;

    let result =
        unsafe { VerifyWithVK(rawr1cs_go_string, proof_go_string, verifying_key_go_string) };
    match result {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(GnarkBackendError::VerifyInvalidBoolError),
    }
}

pub fn get_exact_circuit_size(circuit: &Circuit) -> Result<u32, GnarkBackendError> {
    let size: u32 = RawR1CS::num_constraints(circuit)?
        .try_into()
        .map_err(|e: TryFromIntError| GnarkBackendError::Error(e.to_string()))?;
    Ok(size)
}

pub fn preprocess(circuit: &Circuit) -> Result<(Vec<u8>, Vec<u8>), GnarkBackendError> {
    // Serialize to json and then convert to GoString
    let circuit_json = serde_json::to_string(circuit)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let circuit_c_str = CString::new(circuit_json)
        .map_err(|e| GnarkBackendError::SerializeCircuitError(e.to_string()))?;
    let circuit_go_string = GoString::try_from(&circuit_c_str)?;

    let key_pair: KeyPair = unsafe { Preprocess(circuit_go_string) };

    let proving_key_c_str = unsafe { CStr::from_ptr(key_pair.proving_key) };
    let proving_key_bytes = proving_key_c_str
        .to_str()
        .map_err(|e| GnarkBackendError::DeserializeProofError(e.to_string()))?
        .as_bytes();

    let verifying_key_c_str = unsafe { CStr::from_ptr(key_pair.verifying_key) };
    let verifying_key_bytes = verifying_key_c_str
        .to_str()
        .map_err(|e| GnarkBackendError::DeserializeKeyError(e.to_string()))?
        .as_bytes();

    Ok((proving_key_bytes.to_vec(), verifying_key_bytes.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_go_string_from_cstring() {
        let string = "This works".to_string();
        let c_str = CString::new(string.clone()).unwrap();
        let go_string = GoString::try_from(&c_str).unwrap();
        let deserialized_c_str = unsafe { CStr::from_ptr(go_string.ptr) };
        let deserialized_string = deserialized_c_str.to_str().unwrap().to_string();
        assert_eq!(string, deserialized_string);
    }

    #[test]
    fn get_exact_circuit_size_should_return_zero_with_an_empty_circuit() {
        let size = get_exact_circuit_size(&Circuit::default()).unwrap();
        assert_eq!(size, 0);
    }
}
