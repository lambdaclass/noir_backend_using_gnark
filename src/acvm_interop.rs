// Allow unwrap because the Backend traits don't support Result.
#![allow(clippy::unwrap_used)]

use acvm::acir::{
    circuit::opcodes::BlackBoxFuncCall, circuit::Circuit, native_types::Witness, BlackBoxFunc,
};
use acvm::{
    FieldElement, Language, OpcodeResolutionError, PartialWitnessGenerator, ProofSystemCompiler,
    SmartContract,
};
use std::collections::BTreeMap;

use crate::gnark_backend_wrapper as gnark_backend;

pub struct Gnark;

impl acvm::Backend for Gnark {}

fn get_values_from_witness_tree(
    num_witnesses: u32,
    witness_values: std::collections::BTreeMap<Witness, FieldElement>,
) -> Vec<FieldElement> {
    (1..num_witnesses)
        .map(|wit_index| {
            // Get the value if it exists, if not then default to zero value.
            witness_values
                .get(&Witness(wit_index))
                .map_or(FieldElement::zero(), |field| *field)
        })
        .collect()
}

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
        let values = get_values_from_witness_tree(circuit.num_vars(), witness_values);
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
        let values = get_values_from_witness_tree(circuit.num_vars(), witness_values);
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

impl PartialWitnessGenerator for Gnark {
    fn solve_black_box_function_call(
        _initial_witness: &mut BTreeMap<Witness, FieldElement>,
        _func_call: &BlackBoxFuncCall,
    ) -> Result<(), OpcodeResolutionError> {
        unimplemented!()
    }
}

pub struct GadgetCaller;

impl GadgetCaller {
    pub fn solve_blackbox_func_call(
        _initial_witness: &mut BTreeMap<Witness, FieldElement>,
        _gadget_call: &BlackBoxFuncCall,
    ) -> Result<(), OpcodeResolutionError> {
        unimplemented!()
    }
}

impl SmartContract for Gnark {
    fn eth_contract_from_cs(&self, _circuit: Circuit) -> String {
        unimplemented!("gnark does not implement an ETH contract")
    }

    fn eth_contract_from_vk(&self, _verification_key: &[u8]) -> String {
        unimplemented!("gnark does not implement an ETH contract")
    }
}
