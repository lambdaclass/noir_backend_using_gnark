use acvm::{acir::circuit::Circuit, FieldElement};

mod acir_to_r1cs;
mod serialize;

// Arkworks's types are generic for `Field` but Noir's types are concrete and
// their value depends on the feature flag.
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

pub fn prove(_circuit: Circuit, _values: &[FieldElement]) -> Vec<u8> {
    todo!()
}

pub fn verify(_circuit: Circuit, _proof: &[u8], _public_inputs: &[FieldElement]) -> bool {
    todo!()
}
