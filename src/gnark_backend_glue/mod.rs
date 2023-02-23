use acvm::{acir::circuit::Circuit, FieldElement};
use anyhow::Result;

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

pub fn prove_with_meta(circuit: Circuit, values: Vec<FieldElement>) -> Result<Vec<u8>> {
    todo!()
}

pub fn prove_with_pk(circuit: &Circuit, values: Vec<FieldElement>, proving_key: &[u8]) -> Result<Vec<u8>> {
    todo!()
}

pub fn verify_with_meta(circuit: Circuit, proof: &[u8], public_inputs: &[FieldElement]) -> Result<bool> {
    todo!()
}

pub fn verify_with_vk(circuit: &Circuit, proof: &[u8], public_inputs: &[FieldElement], verifying_key: &[u8]) -> Result<bool> {
    todo!()
}

pub fn preprocess(circuit: &Circuit) -> (Vec<u8>, Vec<u8>) {
    todo!()
}
