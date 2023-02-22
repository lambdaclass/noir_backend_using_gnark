use acvm::acir::{circuit::Circuit, native_types::Witness, BlackBoxFunc};
use acvm::{FieldElement, Language, ProofSystemCompiler};

use crate::gnark_backend_glue as gnark_backend;

use super::Gnark;

impl ProofSystemCompiler for Gnark {
    fn np_language(&self) -> Language {
        Language::R1CS
    }

    fn black_box_function_supported(&self, opcode: &BlackBoxFunc) -> bool {
        match opcode {
            BlackBoxFunc::AES => false,
            BlackBoxFunc::AND => false,
            BlackBoxFunc::XOR => false,
            BlackBoxFunc::RANGE => false,
            BlackBoxFunc::SHA256 => false,
            BlackBoxFunc::Blake2s => false,
            BlackBoxFunc::MerkleMembership => false,
            BlackBoxFunc::SchnorrVerify => false,
            BlackBoxFunc::Pedersen => false,
            BlackBoxFunc::HashToField128Security => false,
            BlackBoxFunc::EcdsaSecp256k1 => false,
            BlackBoxFunc::FixedBaseScalarMul => false,
            BlackBoxFunc::Keccak256 => false,
        }
    }

    fn prove_with_meta(
        &self,
        circuit: Circuit,
        witness_values: std::collections::BTreeMap<Witness, FieldElement>,
    ) -> Vec<u8> {
        // TODO: modify gnark serializer to accept the BTreeMap
        let values: Vec<FieldElement> = witness_values.values().copied().collect();
        gnark_backend::prove(circuit, values).unwrap()
    }

    fn verify_from_cs(
        &self,
        proof: &[u8],
        public_inputs: Vec<FieldElement>,
        circuit: Circuit,
    ) -> bool {
        gnark_backend::verify(circuit, proof, &public_inputs).unwrap()
    }

    fn get_exact_circuit_size(&self, circuit: &Circuit) -> u32 {
        todo!()
    }

    fn preprocess(&self, circuit: &Circuit) -> (Vec<u8>, Vec<u8>) {
        todo!()
    }

    fn prove_with_pk(
        &self,
        circuit: &Circuit,
        witness_values: std::collections::BTreeMap<Witness, FieldElement>,
        proving_key: &[u8],
    ) -> Vec<u8> {
        todo!()
    }

    fn verify_with_vk(
        &self,
        proof: &[u8],
        public_inputs: Vec<FieldElement>,
        circuit: &Circuit,
        verification_key: &[u8],
    ) -> bool {
        todo!()
    }
}
