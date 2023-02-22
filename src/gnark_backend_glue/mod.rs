use std::{ffi::c_void, os::raw::c_uchar, result};

use acvm::{acir::circuit::Circuit, FieldElement};
use anyhow::Result;

extern "C" {
    fn Verify() -> c_uchar;
    fn Prove() -> *mut c_void;
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
pub fn prove(_circuit: Circuit, _values: Vec<FieldElement>) -> Result<Vec<u8>> {
    let result: u8 = unsafe {
        let c_proof: *mut c_void = Prove();
        *(c_proof as *mut u8)
    };

    Ok(vec![result])
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
        assert_eq!(result, [64]);
    }
}
