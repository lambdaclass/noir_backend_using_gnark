use acvm::acir::{circuit::Circuit, native_types::Witness, BlackBoxFunc};
use acvm::{FieldElement, Language, ProofSystemCompiler};

use crate::gnark_backend_wrapper as gnark_backend;

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
        gnark_backend::prove_with_meta(circuit, values).unwrap()
    }

    fn verify_from_cs(
        &self,
        proof: &[u8],
        public_inputs: Vec<FieldElement>,
        circuit: Circuit,
    ) -> bool {
        gnark_backend::verify_with_meta(circuit, proof, &public_inputs).unwrap()
    }

    fn get_exact_circuit_size(&self, circuit: &Circuit) -> u32 {
        gnark_backend::get_exact_circuit_size(circuit).unwrap()
    }

    fn preprocess(&self, circuit: &Circuit) -> (Vec<u8>, Vec<u8>) {
        gnark_backend::preprocess(circuit).unwrap()
    }

    fn prove_with_pk(
        &self,
        circuit: &Circuit,
        witness_values: std::collections::BTreeMap<Witness, FieldElement>,
        proving_key: &[u8],
    ) -> Vec<u8> {
        // TODO: modify gnark serializer to accept the BTreeMap
        let values: Vec<FieldElement> = witness_values.values().copied().collect();
        gnark_backend::prove_with_pk(circuit, values, proving_key).unwrap()
    }

    fn verify_with_vk(
        &self,
        proof: &[u8],
        public_inputs: Vec<FieldElement>,
        circuit: &Circuit,
        verification_key: &[u8],
    ) -> bool {
        gnark_backend::verify_with_vk(circuit, proof, &public_inputs, verification_key).unwrap()
    }
}
