pub mod proof_system;
pub mod pwg;

mod smart_contract;
pub struct Gnark;

impl acvm::Backend for Gnark {}
