use acvm::acir::{circuit::opcodes::BlackBoxFuncCall, native_types::Witness};
use acvm::PartialWitnessGenerator;
use acvm::{FieldElement, OpcodeResolutionError};
use std::collections::BTreeMap;

mod gadget_call;

use super::Gnark;

impl PartialWitnessGenerator for Gnark {
    fn solve_blackbox_function_call(
        _initial_witness: &mut BTreeMap<Witness, FieldElement>,
        _func_call: &BlackBoxFuncCall,
    ) -> Result<(), OpcodeResolutionError> {
        todo!()
    }
}
