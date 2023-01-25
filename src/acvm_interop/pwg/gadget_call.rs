use acvm::acir::{circuit::opcodes::BlackBoxFuncCall, native_types::Witness};
use acvm::{FieldElement, OpcodeResolutionError};
use std::collections::BTreeMap;

pub struct _GadgetCaller;

impl _GadgetCaller {
    pub fn _solve_blackbox_func_call(
        _initial_witness: &mut BTreeMap<Witness, FieldElement>,
        _gadget_call: &BlackBoxFuncCall,
    ) -> Result<(), OpcodeResolutionError> {
        todo!()
    }
}
