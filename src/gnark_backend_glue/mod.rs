use acvm::{acir::circuit::Circuit, FieldElement};

mod acir_to_r1cs;
mod helpers;

pub fn prove(_circuit: Circuit, _values: &[FieldElement]) -> Vec<u8> {
    todo!()
}

pub fn verify(_circuit: Circuit, _proof: &[u8], _public_inputs: &[FieldElement]) -> bool {
    todo!()
}
