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

use ethereum_types::{Address, H256};
use serde::{Deserialize, Serialize, Serializer};
use std::collections::HashMap;

#[derive(Debug)]
pub struct MiningInfo {
    pub height: u64,
    pub generation_signature: H256,
    pub base_target: u64,
}

impl Serialize for MiningInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // NB. all integers convert to strings for safe JSON conversion.

        let mut data = HashMap::new();
        data.insert(
            "generationSignature",
            format!("{:x}", self.generation_signature),
        );
        data.insert("baseTarget", self.base_target.to_string());
        data.insert("height", self.height.to_string());

        data.serialize(serializer)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Nonce {
    pub account_id: u64,
    pub nonce: u64,
    pub account_address: Address,
    pub blockheight: u64,
    pub deadline: Option<u64>, // unadjusted deadline
    pub password: String, // password of signer
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitNonceResponse {
    pub deadline: u64, // adjusted deadline
}
