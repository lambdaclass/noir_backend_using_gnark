use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar};

use acvm::{acir::circuit::Circuit, FieldElement};
use anyhow::{bail, Result};

mod acir_to_r1cs;
mod serialize;
use crate::gnark_backend_glue::acir_to_r1cs::RawR1CS;

// Arkworks's types are generic for `Field` but Noir's types are concrete and
// its value depends on the feature flag.
cfg_if::cfg_if! {
    if #[cfg(feature = "bn254")] {
        pub use ark_bn254::{Bn254 as Curve, Fr};

        // Converts a FieldElement to a Fr
        // noir_field uses arkworks for bn254
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
    fn Verify(rawr1cs: GoString, proof: GoString) -> c_uchar;
    fn Prove(rawr1cs: GoString) -> *const c_char;
    fn ProveWithPK(rawr1cs: GoString, proving_key: GoString) -> *const c_char;
}

#[derive(Debug)]
#[repr(C)]
struct GoString {
    ptr: *const c_char,
    length: usize,
}

impl GoString {
    pub fn from_cstring(c_str: &CString) -> GoString {
        let ptr = c_str.as_ptr();
        let length = c_str.as_bytes().len();
        GoString { ptr, length }
    }
}

pub fn prove_with_meta(circuit: Circuit, values: Vec<FieldElement>) -> Result<Vec<u8>> {
    let rawr1cs = RawR1CS::new(circuit, values)?;

    // Serialize to json and then convert to GoString
    let serialized_rawr1cs = serde_json::to_string(&rawr1cs)?;
    let c_str = CString::new(serialized_rawr1cs)?;
    let go_string_rawr1cs = GoString::from_cstring(&c_str);

    let result: *const c_char = unsafe { Prove(go_string_rawr1cs) };
    let c_str = unsafe { CStr::from_ptr(result) };
    let bytes = c_str.to_str()?.as_bytes();

    Ok(bytes.to_vec())
}

pub fn prove_with_pk(
    circuit: &Circuit,
    values: Vec<FieldElement>,
    proving_key: &[u8],
) -> Result<Vec<u8>> {
    let rawr1cs = RawR1CS::new(*circuit, values)?;

    // Serialize to json and then convert to GoString
    let rawr1cs_json = serde_json::to_string(&rawr1cs)?;
    let rawr1cs_c_str = CString::new(rawr1cs_json)?;
    let rawr1cs_go_string = GoString::from_cstring(&rawr1cs_c_str);

    let proving_key_serialized = std::str::from_utf8(proving_key)?.to_string();
    let proving_key_c_str = CString::new(proving_key_serialized)?;
    let proving_key_go_string = GoString::from_cstring(&proving_key_c_str);

    let result: *const c_char = unsafe { ProveWithPK(rawr1cs_go_string, proving_key_go_string) };
    let c_str = unsafe { CStr::from_ptr(result) };
    let bytes = c_str.to_str()?.as_bytes();

    Ok(bytes.to_vec())
}

pub fn verify_with_meta(
    circuit: Circuit,
    proof: &[u8],
    public_inputs: &[FieldElement],
) -> Result<bool> {
    let rawr1cs = RawR1CS::new(circuit, public_inputs.to_vec())?;

    // Serialize to json and then convert to GoString
    let rawr1cs_json = serde_json::to_string(&rawr1cs)?;
    let c_str = CString::new(rawr1cs_json)?;
    let go_string_rawr1cs = GoString::from_cstring(&c_str);

    let serialized_proof = std::str::from_utf8(proof)?.to_string();
    let c_str = CString::new(serialized_proof)?;
    let go_string_proof = GoString::from_cstring(&c_str);

    let result = unsafe { Verify(go_string_rawr1cs, go_string_proof) };
    match result {
        0 => Ok(false),
        1 => Ok(true),
        _ => bail!("Verify did not return a valid bool"),
    }
}

pub fn verify_with_vk(
    circuit: &Circuit,
    proof: &[u8],
    public_inputs: &[FieldElement],
    verifying_key: &[u8],
) -> Result<bool> {
    todo!()
}

pub fn preprocess(circuit: &Circuit) -> (Vec<u8>, Vec<u8>) {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_should_return_false() {
        let result = verify_with_meta(Circuit::default(), &[65, 66, 67], &[]).unwrap();
        assert!(!result);
    }

    #[test]
    fn prove_should_call_go_backend() {
        let result = prove_with_meta(Circuit::default(), vec![]).unwrap();

        assert_eq!(
            std::str::from_utf8(&result).unwrap(),
            "{\"gates\":[],\"public_inputs\":[],\"values\":[],\"num_variables\":1}"
        );
    }
}
