use acvm::acir::{circuit::opcodes::BlackBoxFuncCall, native_types::Witness};
use acvm::{FieldElement, OpcodeResolutionError};
use std::collections::BTreeMap;

pub struct GadgetCaller;

impl GadgetCaller {
    pub fn solve_blackbox_func_call(
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        gadget_call: &BlackBoxFuncCall,
    ) -> Result<(), OpcodeResolutionError> {
        todo!()
    }
}
