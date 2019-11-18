// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

//! A module with types for declaring nonce check and a client interface for interacting with a
//! nonce check contract.

/// Cache for Account nonce scoop check

use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
};
use std::cell::RefCell;


use hash::keccak;
use error::Error;
use machine::Machine;
use trace;
use types::BlockNumber;
use super::{SystemOrCodeCall, SystemOrCodeCallKind};
use trace::{Tracer, ExecutiveTracer, Tracing};
use block::ExecutedBlock;
use ethabi;
use ethabi::ParamType;
use ethereum_types::{H160, U256, Address};
use parking_lot::RwLock;
use evm::evm::CostType;

use_contract!(nonce_check_contract, "res/contracts/nonce_check.json");

pub struct AccountCacher {
    kind: SystemOrCodeCallKind,
    accounts: HashMap<Address, u64>,

}

impl AccountCacher {
    /// Create a new block nonce cacher contract client targeting the system call kind.
    pub fn new(kind: SystemOrCodeCallKind) -> AccountCacher {
        AccountCacher {
            kind,
            accounts: HashMap::with_capacity(3000),
        }
    }

    /// Create a new block nonce cacher contract client targeting the contract address.
    pub fn new_from_address(address: Address) -> AccountCacher {
        Self::new(SystemOrCodeCallKind::Address(address))
    }

    /// Create a new block nonce cache contract client targeting the given code.
    pub fn new_from_code(code: Arc<Vec<u8>>) -> AccountCacher {
        let code_hash = keccak(&code[..]);

        Self::new(SystemOrCodeCallKind::Code(code, code_hash))
    }


    /// Retrieve a cached nonce scoop for given sender.
    pub fn get_one(&self, sender: &Address) -> Option<&u64> {
        self.accounts.get(sender)
    }

    /// Check block's nonce from contract by sender
    pub fn check<'a>(&mut self, sender: Address, nonce: u64, caller: &'a mut SystemOrCodeCall) -> Result<u64, String> {
        let range = self.cache(sender, caller).unwrap();
        let account_max_range = range.as_u64() * 1000 * 1000 * 4;

        trace!(target: "engine", "got scoop in contract,nonce: {}, Max: {} , range: {}", nonce, account_max_range, range.as_u64());
        return Ok(account_max_range);
    }

    /// Retrieve a cached nonce for given sender.
    pub fn get<'a>(&mut self, sender: Address, nonce: u64, caller: &'a mut SystemOrCodeCall) -> Result<u64, String> {
        if let Some(scoop) = self.accounts.get(&sender) {
            let account_max_range = *scoop;
            if nonce > account_max_range {
                let range = self.cache(sender, caller).unwrap();
                let account_max_range = range.as_u64() * 1000 * 1000 * 4;
                if nonce < account_max_range {
                    trace!(target: "engine", "Cache don't hit, and got new scoop from contract,nonce: {}, Max : {}, range: {}", nonce, account_max_range, range.as_u64());
                    self.accounts.insert(sender, account_max_range);
                }
                return Ok(account_max_range);
            } else {
                trace!(target: "engine", "Cache has hits on nonce check, nonce: {},scoop: {}", nonce, account_max_range);
                return Ok(account_max_range);
            }
        } else {
            let range = self.cache(sender, caller).unwrap();
            let account_max_range = range.as_u64() * 1000 * 1000 * 4;

            trace!(target: "engine", "Cache missed, got new scoop from contract,nonce: {}, Max: {} , range: {}", nonce, account_max_range, range.as_u64());
            if account_max_range != 0 {
                self.accounts.insert(sender.clone(), account_max_range);
                return Ok(account_max_range);
            }
        }
        Ok(0)
    }

    /// Clear all entries from the cache.
    pub fn clear(&mut self) {
        self.accounts.clear();
    }

    /// Calls the block nonce cache contract with the given sender address
    /// and returns the address allocation (address - value). The nonce check contract *must* be
    /// called by the system address so the `caller` must ensure that (e.g. using
    /// `machine.execute_as_system`).
    fn cache(
        &self,
        miner: Address,
        caller: &mut SystemOrCodeCall,
    ) -> Result<U256, Error> {
        let input = nonce_check_contract::functions::getstorage::encode_input(
            H160::from(miner),
        );

        let output = caller(self.kind.clone(), input)
            .map_err(Into::into)
            .map_err(::engines::EngineError::FailedSystemCall)?;
        // since this is a non-constant call we can't use ethabi's function output
        // deserialization, sadness ensues.
        let types = &[
            ParamType::Uint(256)
        ];
        let tokens = ethabi::decode(types, &output)
            .map_err(|err| err.to_string())
            .map_err(::engines::EngineError::FailedSystemCall)?;

        assert!(tokens.len() == 1);

        let nonce_range = tokens[0].clone().to_uint().expect("type checked by ethabi::decode; qed");
        Ok(nonce_range)
    }
}

impl Clone for AccountCacher {
    fn clone(&self) -> Self {
        AccountCacher {
            kind: self.kind.clone(),
            accounts: self.accounts.clone(),
        }
    }
}


mod tests {
    use std::str::FromStr;

    use spec;
    use block::*;
    use engines;
    use spec::Spec;
    use tempdir::TempDir;
    use super::AccountCacher;
    use test_helpers::get_temp_state_db;
    use engines::{default_system_or_code_call, SystemOrCodeCallKind};
    use ethereum_types::{U256, Address};
    use ethereum::{new_homestead_test_machine, new_mcip3_test, new_morden};

    fn test_spec() -> Spec {
        let tempdir = TempDir::new("").unwrap();
        new_morden(&tempdir.path())
    }

    pub fn call_contract(address: Address) -> u64 {
        let nonce = 500_u64;
        nonce
    }

    #[test]
    fn test_nonce_check() {
        let sender = Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
        let nonce = 600_u64;

        let spec = test_spec();
        let engine = &*spec.engine;
        let last_hashes = Arc::new(vec![genesis_header.hash()]);
        let genesis_header = spec.genesis_header();
        let db = spec
            .ensure_db_good(get_temp_state_db(), &Default::default())
            .unwrap();
        let b = OpenBlock::new(
            engine,
            Default::default(),
            false,
            db,
            &genesis_header,
            last_hashes,
            Address::zero(),
            (3141562.into(), 31415620.into()),
            vec![],
            false,
            None,
        ).unwrap();

        let b = b.close().unwrap();
        let mut call = engines::default_system_or_code_call(engine.machine(), block);

        let contract = Address::from_str("000000000000000000000000000000000000000a").unwrap();

        let mut cacher = AccountCacher::new(SystemOrCodeCallKind::Address(contract));

        assert_eq!(cacher.check(&sender, 550).unwrap(), true);
        let result = cacher.get(sender, nonce, call);
        assert_eq!(result, None);

//        let result = cacher.get(sender, nonce, call);
//        assert_eq!(result, None);
//        assert_eq!(cacher.check(&sender, 450).unwrap(), true);
//        let result = cacher.get(sender, nonce, call);
//        assert_eq!(result.unwrap(), 600);
    }
}