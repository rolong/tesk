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

//! Eth Mining RPC implementation

use accounts::AccountProvider;
use ethcore::client::StateInfo;
use ethcore::client::{BlockInfo, EngineInfo};
use ethcore::engines::Nonce as EngineNonce;
use ethcore::miner::MinerService;
use ethereum_types::Address;
use jsonrpc_core::Result;
use std::str::FromStr;
use std::sync::Arc;
use v1::helpers::errors::invalid_params;
use v1::traits::EthMining;
use v1::types::{MiningInfo, Nonce, SubmitNonceResponse};

/// Eth mining rpc implementation for a full node.
pub struct EthMiningClient<C, M> {
    accounts: Arc<AccountProvider>,
    client: Arc<C>,
    miner: Arc<M>,
}

impl<C, M, T: StateInfo + 'static> EthMiningClient<C, M>
where
    C: BlockInfo + EngineInfo + Send + Sync + 'static,
    M: MinerService<State = T>,
{
    pub fn new(accounts: &Arc<AccountProvider>, client: &Arc<C>, miner: &Arc<M>) -> Self {
        Self {
            accounts: accounts.clone(),
            client: client.clone(),
            miner: miner.clone(),
        }
    }
}

impl<C, M, T: StateInfo + 'static> EthMining for EthMiningClient<C, M>
where
    C: BlockInfo + EngineInfo + Send + Sync + 'static,
    M: MinerService<State = T> + 'static,
{
    fn get_mining_info(&self) -> Result<MiningInfo> {
        let header = self.client.best_block_header();
        let generation_signature = self.client.engine().next_generation_signature(&header);
        Ok(MiningInfo {
            generation_signature,
            base_target: header.base_target(),
            height: header.number() + 1,
        })
    }

    fn submit_nonce(&self, nonce: Nonce) -> Result<SubmitNonceResponse> {
        /*
        // check whether has the account
        if !self.accounts.has_account(nonce.account_address) {
            return Err(invalid_params("account_address", "address not found"));
        }
        */

        let deadline = self
            .client
            .engine()
            .submit_nonce(EngineNonce {
                account_id: nonce.account_id,
                nonce: nonce.nonce,
                account_address: nonce.account_address,
                blockheight: nonce.blockheight,
                deadline: nonce.deadline,
            })
            .map_err(|e| invalid_params("nonce", e))?;

        Ok(SubmitNonceResponse { deadline })
    }
}
