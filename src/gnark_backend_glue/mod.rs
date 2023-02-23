use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar, c_void};
use std::result;

use acvm::{acir::circuit::Circuit, FieldElement};
use anyhow::Result;
use serde::Serialize;

use self::acir_to_r1cs::RawR1CS;

extern "C" {
    fn Verify() -> c_uchar;
    fn Prove(rawr1cs: GoString) -> *const c_char;
}

#[derive(Debug)]
#[repr(C)]
struct GoString {
    a: *const c_char,
    b: i64,
}

mod acir_to_r1cs;
mod serialize;

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

//WIP
pub fn prove(circuit: Circuit, values: Vec<FieldElement>) -> Result<Vec<u8>> {
    let rawr1cs = RawR1CS::new(circuit, values).unwrap();

    // Serialize to json and then convert to GoString
    let serialized_rawr1cs = serde_json::to_string(&rawr1cs).unwrap();
    let c_msg = CString::new(serialized_rawr1cs).expect("CString::new failed");
    let ptr = c_msg.as_ptr();
    let go_string_rawr1cs = GoString {
        a: ptr,
        b: c_msg.as_bytes().len() as i64,
    };

    let result: *const c_char = unsafe { Prove(go_string_rawr1cs) };
    let c_str = unsafe { CStr::from_ptr(result) };
    let bytes = c_str.to_str().unwrap().as_bytes();

    Ok(bytes.to_vec())
}

//WIP
pub fn verify(_circuit: Circuit, _proof: &[u8], _public_inputs: &[FieldElement]) -> Result<bool> {
    let result = unsafe { Verify() };
    match result {
        0 => Ok(false),
        _ => Ok(true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn verify_should_return_false() {
        let result = verify(Circuit::default(), &[], &[]).unwrap();
        assert!(!result);
    }

    #[test]
    fn prove_should_call_go_backend() {
        //WIP
        let result = prove(Circuit::default(), vec![]).unwrap();

        assert_eq!(
            std::str::from_utf8(&result).unwrap(),
            "{\"gates\":[],\"public_inputs\":[],\"values\":[],\"num_variables\":1}"
        );
    }
}
