// Allow unwrap because the Backend traits don't support Result.
#![allow(clippy::unwrap_used)]

use acvm::acir::{
    circuit::opcodes::BlackBoxFuncCall, circuit::Circuit, native_types::Witness, BlackBoxFunc,
};
use acvm::pwg::hash::{blake2s, sha256};
use acvm::pwg::logic::solve_logic_opcode;
use acvm::pwg::range::solve_range_opcode;
use acvm::pwg::signature::ecdsa::secp256k1_prehashed;
use acvm::pwg::witness_to_value;
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
            *witness_to_value(&witness_values, Witness(wit_index)).unwrap_or(&FieldElement::zero())
        })
        .collect()
}

impl ProofSystemCompiler for Gnark {
    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
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
        public_inputs: BTreeMap<Witness, FieldElement>,
        circuit: &Circuit,
        verification_key: &[u8],
    ) -> bool {
        let public: Vec<FieldElement> =
            get_values_from_witness_tree(circuit.num_vars(), public_inputs);
        gnark_backend::verify_with_vk(circuit, proof, &public, verification_key).unwrap()
    }
}

impl PartialWitnessGenerator for Gnark {
    fn solve_black_box_function_call(
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        func_call: &BlackBoxFuncCall,
    ) -> Result<(), OpcodeResolutionError> {
        match func_call.name {
            BlackBoxFunc::AES => Err(OpcodeResolutionError::UnsupportedBlackBoxFunc(
                func_call.name,
            )),
            BlackBoxFunc::AND | BlackBoxFunc::XOR => solve_logic_opcode(initial_witness, func_call),
            BlackBoxFunc::RANGE => solve_range_opcode(initial_witness, func_call),
            BlackBoxFunc::SHA256 => {
                sha256(initial_witness, func_call);
                Ok(())
            }
            BlackBoxFunc::Blake2s => {
                blake2s(initial_witness, func_call);
                Ok(())
            }
            BlackBoxFunc::MerkleMembership => Err(OpcodeResolutionError::UnsupportedBlackBoxFunc(
                func_call.name,
            )),
            BlackBoxFunc::SchnorrVerify => Err(OpcodeResolutionError::UnsupportedBlackBoxFunc(
                func_call.name,
            )),
            BlackBoxFunc::Pedersen => Err(OpcodeResolutionError::UnsupportedBlackBoxFunc(
                func_call.name,
            )),
            BlackBoxFunc::HashToField128Security => {
                // Deal with Blake2s -- XXX: It's not possible for pwg to know that it is Blake2s
                // We need to get this method from the backend
                let mut hasher = <blake2::Blake2s as blake2::Digest>::new();

                // 0. For each input in the vector of inputs, check if we have their witness assignments (Can do this outside of match, since they all have inputs)
                for input_index in func_call.inputs.iter() {
                    let witness = &input_index.witness;
                    let num_bits = input_index.num_bits;

                    let assignment = witness_to_value(initial_witness, *witness)?;

                    let bytes = assignment.fetch_nearest_bytes(num_bits.try_into().unwrap());

                    blake2::Digest::update(&mut hasher, bytes);
                }
                let result = blake2::Digest::finalize(hasher);

                let reduced_res = FieldElement::from_be_bytes_reduce(&result);
                assert_eq!(func_call.outputs.len(), 1);

                initial_witness.insert(func_call.outputs[0], reduced_res);
                Ok(())
            }
            BlackBoxFunc::EcdsaSecp256k1 => secp256k1_prehashed(initial_witness, func_call),
            BlackBoxFunc::FixedBaseScalarMul => Err(
                OpcodeResolutionError::UnsupportedBlackBoxFunc(func_call.name),
            ),
            BlackBoxFunc::Keccak256 => Err(OpcodeResolutionError::UnsupportedBlackBoxFunc(
                func_call.name,
            )),
        }
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
