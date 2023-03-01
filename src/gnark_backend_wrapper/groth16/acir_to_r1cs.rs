use super::{from_felt, Fr};
use crate::acvm;
use crate::gnark_backend_wrapper::groth16::serialize::{serialize_felt, serialize_felts};
use crate::gnark_backend_wrapper::groth16::GnarkBackendError;
use std::num::TryFromIntError;

// AcirCircuit and AcirArithGate are R1CS-friendly structs.
//
// The difference between these structures and the ACIR structure that the compiler uses is the following:
// - The compilers ACIR struct is currently fixed to bn254
// - These structures only support arithmetic gates, while the compiler has other
// gate types. These can be added later once the backend knows how to deal with things like XOR
// or once ACIR is taught how to do convert these black box functions to Arithmetic gates.
#[derive(Clone, serde::Serialize)]
pub struct RawR1CS {
    pub gates: Vec<RawGate>,
    pub public_inputs: Vec<acvm::Witness>,
    #[serde(serialize_with = "serialize_felts")]
    pub values: Vec<Fr>,
    pub num_variables: u64,
    pub num_constraints: u64,
}

#[derive(Clone, serde::Serialize)]
pub struct RawGate {
    pub mul_terms: Vec<MulTerm>,
    pub add_terms: Vec<AddTerm>,
    #[serde(serialize_with = "serialize_felt")]
    pub constant_term: Fr,
}

#[derive(Clone)]
pub struct MulTerm {
    pub coefficient: Fr,
    pub multiplicand: acvm::Witness,
    pub multiplier: acvm::Witness,
}

#[derive(Clone)]
pub struct AddTerm {
    pub coefficient: Fr,
    pub sum: acvm::Witness,
}

impl RawR1CS {
    pub fn new(
        acir: acvm::Circuit,
        values: Vec<acvm::FieldElement>,
    ) -> Result<Self, GnarkBackendError> {
        let num_constraints: u64 = Self::num_constraints(&acir)?
            .try_into()
            .map_err(|e: TryFromIntError| GnarkBackendError::Error(e.to_string()))?;
        // Currently non-arithmetic gates are not supported
        // so we extract all of the arithmetic gates only
        let gates: Vec<_> = acir
            .opcodes
            .into_iter()
            .filter(acvm::Opcode::is_arithmetic)
            .map(|opcode| match opcode.arithmetic() {
                Some(expression) => RawGate::new(expression),
                None => RawGate::new(acvm::Expression::default()),
            })
            .collect();

        let values: Vec<Fr> = values.into_iter().map(from_felt).collect();

        Ok(Self {
            gates,
            values,
            num_variables: u64::from(acir.current_witness_index) + 1,
            public_inputs: acir.public_inputs.0.into_iter().collect(),
            num_constraints,
        })
    }

    pub fn num_constraints(acir: &acvm::Circuit) -> Result<usize, GnarkBackendError> {
        // each multiplication term adds an extra constraint
        let mut num_opcodes = acir.opcodes.len();

        for opcode in acir.opcodes.iter() {
            match opcode {
                acvm::Opcode::Arithmetic(arith) => num_opcodes += arith.num_mul_terms() + 1, // plus one for the linear combination gate
                acvm::Opcode::Directive(_) => (),
                _ => {
                    return Err(GnarkBackendError::UnsupportedOpcodeError(
                        opcode.to_string(),
                    ))
                }
            }
        }

        Ok(num_opcodes)
    }
}

impl RawGate {
    pub fn new(arithmetic_gate: acvm::Expression) -> Self {
        let converted_mul_terms: Vec<MulTerm> = arithmetic_gate
            .mul_terms
            .into_iter()
            .map(|(coefficient, multiplicand, multiplier)| MulTerm {
                coefficient: from_felt(coefficient),
                multiplicand,
                multiplier,
            })
            .collect();

        let converted_linear_combinations: Vec<_> = arithmetic_gate
            .linear_combinations
            .into_iter()
            .map(|(coefficient, sum)| AddTerm {
                coefficient: from_felt(coefficient),
                sum,
            })
            .collect();

        Self {
            mul_terms: converted_mul_terms,
            add_terms: converted_linear_combinations,
            constant_term: from_felt(arithmetic_gate.q_c),
        }
    }
}

impl Copy for MulTerm {}
impl Copy for AddTerm {}

impl std::fmt::Debug for MulTerm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Coefficient: {:?}", self.coefficient.0 .0)?;
        writeln!(f, "Multiplicand: {:?}", self.multiplicand.0)?;
        writeln!(f, "Multiplier: {:?}", self.multiplier.0)?;
        writeln!(f)
    }
}

impl std::fmt::Debug for AddTerm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Coefficient: {:?}", self.coefficient.0 .0)?;
        writeln!(f, "Sum: {:?}", self.sum.0)?;
        writeln!(f)
    }
}

impl std::fmt::Debug for RawGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.mul_terms.fmt(f)?;
        self.add_terms.fmt(f)?;
        writeln!(f, "Constant term: {:?}", self.constant_term.0 .0)?;
        writeln!(f)
    }
}

impl std::fmt::Debug for RawR1CS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.gates.fmt(f)?;
        writeln!(
            f,
            "Public Inputs: {:?}",
            self.public_inputs
                .iter()
                .map(|public_input| public_input.0)
                .collect::<Vec<_>>()
        )?;
        writeln!(
            f,
            "Values: {:?}",
            self.values
                .iter()
                .map(|value| value.0 .0)
                .collect::<Vec<_>>()
        )?;
        writeln!(f, "Number of variables: {}", self.num_variables)?;
        writeln!(f, "Number of constraints: {}", self.num_constraints)?;
        writeln!(f)
    }
}
