use acvm::acir::{circuit::opcodes::BlackBoxFuncCall, native_types::Witness};
use acvm::PartialWitnessGenerator;
use acvm::{FieldElement, OpcodeResolutionError};
use std::collections::BTreeMap;

mod gadget_call;

use super::Gnark;

impl PartialWitnessGenerator for Gnark {
    fn solve_black_box_function_call(
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        func_call: &BlackBoxFuncCall,
    ) -> Result<(), OpcodeResolutionError> {
        todo!()
    }
}
