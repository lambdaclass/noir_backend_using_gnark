use acvm::{acir::circuit::Circuit, FieldElement};

pub fn prove(_circuit: Circuit, _values: &[FieldElement]) -> Vec<u8> {
    todo!()
}

pub fn verify(_circuit: Circuit, _proof: &[u8], _public_inputs: &[FieldElement]) -> bool {
    todo!()
}
