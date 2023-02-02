use acvm::acir::native_types::Witness;
use anyhow::Result;
use serde::Serialize;

use super::from_fe;

// AcirCircuit and AcirArithGate are R1CS-friendly structs.
//
// The difference between these structures and the ACIR structure that the compiler uses is the following:
// - The compilers ACIR struct is currently fixed to bn254
// - These structures only support arithmetic gates, while the compiler has other
// gate types. These can be added later once the backend knows how to deal with things like XOR
// or once ACIR is taught how to do convert these black box functions to Arithmetic gates.
//
// Perfect API would look like:
// - index(srs, circ)
// - prove(index_pk, prover_values, rng)
// - verify(index_vk, verifier, rng)
#[derive(Clone, Serialize)]
pub struct RawR1CS<F: ark_ff::PrimeField> {
    pub gates: Vec<RawGate<F>>,
    pub public_inputs: acvm::acir::circuit::PublicInputs,
    pub values: Vec<F>,
    pub num_variables: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct RawGate<F: ark_ff::PrimeField> {
    pub mul_terms: Vec<(F, Witness, Witness)>,
    pub add_terms: Vec<(F, Witness)>,
    pub constant_term: F,
}

impl<F: ark_ff::PrimeField> RawR1CS<F> {
    pub fn new(
        acir: &acvm::acir::circuit::Circuit,
        values: Vec<F>,
    ) -> Result<Self> {
        // Currently non-arithmetic gates are not supported
        // so we extract all of the arithmetic gates only
        let gates: Vec<_> = acir
            .opcodes
            .into_iter()
            .filter(|opcode| opcode.is_arithmetic())
            .map(|opcode| RawGate::new(opcode.arithmetic().unwrap()))
            .collect();

        Ok(Self {
            gates,
            values,
            num_variables: (acir.current_witness_index + 1).try_into()?,
            public_inputs: acir.public_inputs,
        })
    }
}

impl<F: ark_ff::PrimeField> RawGate<F> {
    pub fn new(arithmetic_gate: acvm::acir::native_types::Expression) -> Self {
        let converted_mul_terms: Vec<_> = arithmetic_gate
            .mul_terms
            .into_iter()
            .map(|(coefficient, multiplicand, multiplier)| (from_fe(coefficient), multiplicand, multiplier))
            .collect();

        let converted_linear_combinations: Vec<_> = arithmetic_gate
            .linear_combinations
            .into_iter()
            .map(|(coefficient, sum)| (from_fe(coefficient), sum))
            .collect();

        Self {
            mul_terms: converted_mul_terms,
            add_terms: converted_linear_combinations,
            constant_term: from_fe(arithmetic_gate.q_c),
        }
    }
}
