use acvm::acir::circuit::Circuit;

use acvm::SmartContract;

use super::Gnark;

impl SmartContract for Gnark {
    fn eth_contract_from_cs(&self, _circuit: Circuit) -> String {
        unimplemented!("gnark does not implement an ETH contract")
    }

    fn eth_contract_from_vk(&self, _verification_key: &[u8]) -> String {
        unimplemented!("gnark does not implement an ETH contract")
    }
}
