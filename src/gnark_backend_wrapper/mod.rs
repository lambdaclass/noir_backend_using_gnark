mod errors;
pub use errors::GnarkBackendError;
mod c_go_structures;
pub use c_go_structures::{GoString, KeyPair};

cfg_if::cfg_if! {
    if #[cfg(feature = "groth16")] {
        mod groth16;
        pub use groth16::{AddTerm, Fr, MulTerm, RawGate, RawR1CS};
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
