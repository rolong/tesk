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

//! A module with types for declaring block rewards and a client interface for interacting with a
//! block reward contract.

use ethabi;
use ethabi::ParamType;
use ethereum_types::{H160, Address, U256};

use std::sync::Arc;
use hash::keccak;
use error::Error;
use machine::Machine;
use trace;
use types::BlockNumber;
use super::{SystemOrCodeCall, SystemOrCodeCallKind};
use trace::{Tracer, ExecutiveTracer, Tracing};
use block::ExecutedBlock;

use_contract!(miner_verify_contract, "res/contracts/miner_verify.json");

/// A client for the block reward contract.
#[derive(PartialEq, Debug)]
pub struct MinerVerifyContract {
    kind: SystemOrCodeCallKind,
}

impl MinerVerifyContract {
    /// Create a new block reward contract client targeting the system call kind.
    pub fn new(kind: SystemOrCodeCallKind) -> MinerVerifyContract {
        MinerVerifyContract {
            kind,
        }
    }

    /// Create a new block reward contract client targeting the contract address.
    pub fn new_from_address(address: Address) -> MinerVerifyContract {
        Self::new(SystemOrCodeCallKind::Address(address))
    }

    /// Create a new block reward contract client targeting the given code.
    pub fn new_from_code(code: Arc<Vec<u8>>) -> MinerVerifyContract {
        let code_hash = keccak(&code[..]);

        Self::new(SystemOrCodeCallKind::Code(code, code_hash))
    }

    /// Calls the block reward contract with the given beneficiaries list (and associated reward kind)
    /// and returns the reward allocation (address - value). The block reward contract *must* be
    /// called by the system address so the `caller` must ensure that (e.g. using
    /// `machine.execute_as_system`).
    pub fn verify(
        &self,
        author: Address,
        miner: Address,
        caller: &mut SystemOrCodeCall,
    ) -> Result<bool, Error> {
        let input = miner_verify_contract::functions::authors::encode_input(
            H160::from(author),
        );
        let output = caller(self.kind.clone(), input)
            .map_err(Into::into)
            .map_err(::engines::EngineError::FailedSystemCall)?;

        // since this is a non-constant call we can't use ethabi's function output
        // deserialization, sadness ensues.
        let types = &[
            ParamType::Address
        ];

        let tokens = ethabi::decode(types, &output)
            .map_err(|err| err.to_string())
            .map_err(::engines::EngineError::FailedSystemCall)?;

        assert!(tokens.len() == 1);

        let address = tokens[0].clone().to_address();

        let ok = miner == address.unwrap();
        trace!(target: "engine", "miner verify result is {:?},block.miner 's: {:?},contract.address 's {:?}", ok, miner, address.unwrap());
        if ok == false {
            return Err(::engines::EngineError::FailedMinerVerify(
                "invalid block miner verify by author contract.".into()
            ).into());

        }
        Ok(ok)
    }
}