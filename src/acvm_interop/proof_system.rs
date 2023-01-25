use acvm::acir::{circuit::Circuit, native_types::Witness, BlackBoxFunc};
use acvm::{FieldElement, Language, ProofSystemCompiler};

use super::Gnark;

impl ProofSystemCompiler for Gnark {
    fn np_language(&self) -> Language {
        todo!()
    }

    fn blackbox_function_supported(&self, opcode: &BlackBoxFunc) -> bool {
        todo!()
    }

    fn prove_with_meta(
        &self,
        circuit: Circuit,
        witness_values: std::collections::BTreeMap<Witness, FieldElement>,
    ) -> Vec<u8> {
        todo!()
    }

    fn verify_from_cs(
        &self,
        proof: &[u8],
        public_inputs: Vec<FieldElement>,
        circuit: Circuit,
    ) -> bool {
        todo!()
    }

    fn get_exact_circuit_size(&self, circuit: Circuit) -> u32 {
        todo!()
    }
}
