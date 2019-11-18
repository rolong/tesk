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

use engines::EngineError;
use engines::skhash::SIGNATURE_LENGTH;
use error::Error;
use ethereum_types::{Address, H256};
use ethkey::{public_to_address, recover as ec_recover, Signature};
use lru_cache::LruCache;
use parking_lot::RwLock;
use types::header::Header;

/// How many recovered signature to cache in the memory.
pub const CREATOR_CACHE_NUM: usize = 4096;
lazy_static! {
	/// key: header hash
	/// value: creator address
	static ref CREATOR_BY_HASH: RwLock<LruCache<H256, Address>> = RwLock::new(LruCache::new(CREATOR_CACHE_NUM));
}

/// Recover block creator from signature
pub fn recover_creator(header: &Header) -> Result<Address, Error> {
    // Initialization

    let data = header.extra_data();

    if data.len() < SIGNATURE_LENGTH {
        Err(EngineError::PoCMissingSignature)?
    }
    //  convert `&[u8]` to `[u8; 65]`
    let signature = {
        let mut s = [0; SIGNATURE_LENGTH];
        s.copy_from_slice(&data[..]);
        s
    };

    // modify header and hash it
    let unsigned_header = &mut header.clone();
    unsigned_header.set_extra_data(vec![]);
    let msg = unsigned_header.bare_hash();

    let pubkey = ec_recover(&Signature::from(signature), &msg)?;
    let creator = public_to_address(&pubkey);
    Ok(creator)
}