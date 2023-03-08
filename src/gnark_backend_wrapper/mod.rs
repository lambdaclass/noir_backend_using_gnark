mod errors;
pub use errors::GnarkBackendError;
mod c_go_structures;
pub use c_go_structures::{GoString, KeyPair};

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

cfg_if::cfg_if! {
    if #[cfg(feature = "groth16")] {
        mod groth16;
        pub use groth16::{AddTerm, MulTerm, RawGate, RawR1CS};
        pub use groth16::verify_with_meta;
        pub use groth16::prove_with_meta;
        pub use groth16::verify_with_vk;
        pub use groth16::prove_with_pk;
        pub use groth16::get_exact_circuit_size;
        pub use groth16::preprocess;
    } else if #[cfg(feature = "plonk")] {
        mod plonk;
        pub use plonk::verify_with_meta;
        pub use plonk::prove_with_meta;
        pub use plonk::verify_with_vk;
        pub use plonk::prove_with_pk;
        pub use plonk::get_exact_circuit_size;
        pub use plonk::preprocess;
    }
}
