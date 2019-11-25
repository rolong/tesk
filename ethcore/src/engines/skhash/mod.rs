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

//! Implementation of the Skhash Engine.
//!
//! File structure:
//! - mod.rs -> Provides the engine API implementation, with additional block state tracking
//! - block_state.rs -> Records the Skhash state for given block.
//! - params.rs -> Contains the parameters for the Skhash engine.
//! - step_service.rs -> An event loop to trigger sealing.
//! - util.rs -> Various standalone utility functions.
//! - tests.rs -> Consensus tests as defined in EIP-225.

/// How syncing works:
///
/// 1. Client will call:
///    - `Skhash::verify_block_basic()`
///    - `Skhash::verify_block_unordered()`
///    - `Skhash::verify_block_family()`
/// 2. Using `Skhash::state()` we try and retrieve the parent state. If this isn't found
///    we need to back-fill it from the last known checkpoint.
/// 3. Once we have a good state, we can record it using `SkhashBlockState::apply()`.

/// How sealing works:
///
/// 1. Set a signer using `Engine::set_signer()`. If a miner account was set up through
///    a config file or CLI flag `MinerService::set_author()` will eventually set the signer
/// 2. We check that the engine seals internally through `Skhash::seals_internally()`
///    Note: This is always true for Skhash

/// 3. Miner will create new block, in process it will call several engine methods to do following:
///   a. `Skhash::open_block_header_timestamp()` must set timestamp correctly.
///   b. `Skhash::populate_from_parent()` must set difficulty to correct value.
///       Note: `Skhash::populate_from_parent()` is used in both the syncing and sealing code paths.
/// 4. We call `Skhash::on_seal_block()` which will allow us to modify the block header during seal generation.
/// 5. Finally, `Skhash::verify_local_seal()` is called. After this, the syncing code path will be followed
///    in order to import the new block.
use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};

use std::cell::RefCell;
use std::str::FromStr;
use std::thread;
use std::time;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::signer::EngineSigner;
use block::ExecutedBlock;
use client::{BlockId, EngineClient};
use error::{BlockError, Error, ErrorKind};
use ethereum_types::{Address, H256, H64, U256};
use ethkey::Signature;
use hash::KECCAK_EMPTY_LIST_RLP;
use machine::{EthereumMachine, Machine};
use num::ToPrimitive;
use num_bigint::BigUint;
use parking_lot::RwLock;
use rlp::{encode, Rlp};
use types::header::{ExtendedHeader, Header};
use types::BlockNumber;
use unexpected::{Mismatch, OutOfBounds};

#[cfg(not(feature = "time_checked_add"))]
use time_utils::CheckedSystemTime;

use shabal::compute::calculate_new_gensig;
use shabal::{
    calculate_scoop, decode_gensig, find_best_deadline_rust, noncegen_rust, SkhashManager,
};

use engines;
use engines::block_reward::RewardKind;
use engines::skhash::util::recover_creator;
use engines::{block_reward, miner_verify, nonce_check, Engine, EngineError, EpochVerifier, Nonce, Seal, SystemOrCodeCallKind, EthEngine};

use self::params::SkhashParams;
use core::borrow::BorrowMut;
use engines::miner_verify::MinerVerifyContract;
use engines::nonce_check::AccountCacher;

mod params;
mod util;

// TODO(niklasad1): extract tester types into a separate mod to be shared in the code base

// Protocol constants
/// Fixed number of extra-data suffix bytes reserved for signer signature
pub const SIGNATURE_LENGTH: usize = 65;
/// seal block NONCE_LENGTH
pub const NONCE_LENGTH: usize = 8;
/// Default empty nonce value
pub const NULL_NONCE: H64 = H64([0; 8]);
/// Default value for mixhash
pub const NULL_MIXHASH: H256 = H256([0; 32]);
/// Number of blocks in an shabal snapshot.
// make dependent on difficulty incrment divisor?
const SNAPSHOT_BLOCKS: u64 = 5000;
/// Maximum number of blocks allowed in an ethash snapshot.
const MAX_SNAPSHOT_BLOCKS: u64 = 30000;
/// Verify PoC protocol ,Params of PoC Consensus 's Shabal
const MAX_PLOT_SIZE: usize = 262144;
/// Verify PoC protocol ,Params of PoC Consensus 's Shabal
const HASH_SIZE: usize = 32;
/// Verify PoC protocol ,Params of PoC Consensus 's Shabal
const SCOOP_SIZE: usize = HASH_SIZE * 2;
/// Verify PoC protocol ,Params of PoC Consensus 's Shabal
const INITIAL_BASE_TARGET: u64 = 18325193796;
/// Verify PoC protocol ,Params of PoC Consensus 's Shabal
const MAX_BASE_TARGET: u64 = 18325193796;
/// Verify PoC protocol ,Params of PoC Consensus 's Shabal
const PARITY_DIFF_ADJUST_CHANGE_BLOCK: u64 = 2700;
/// target time span between two blocks in seconds
const TARGET_TIME_SPAN: u64 = 240;
/// Initial BaseTarget match NetCapacity
const BASE_NET_CAPACITY: u64 = 16384;
/// The protocol halves the rate at which new SEEK are created every 4 years
const HALF_TIME: u64 = 525600;
/// allowed max timestamp difference
const MAX_TIMESTAMP_DIFFERENCE: u64 = 15;

/// HashRate calculate Epcoh
const HASH_RATE_CALC_EPOCH: u64 = 21;

const CONTRACT_ADDRESS: &str = "000000000000000000000000000000000000000a";

/// Skhash specific seal
#[derive(Debug, PartialEq)]
pub struct SkhashSeal {
    /// Skhash seal mix_hash
    pub mix_hash: H256,
    /// Skhash seal nonce
    pub nonce: H64,
}

impl SkhashSeal {
    /// Tries to parse rlp as Shabal seal.
    pub fn parse_seal<T: AsRef<[u8]>>(seal: &[T]) -> Result<Self, Error> {
        if seal.len() != 2 {
            let mix_hash = NULL_MIXHASH;
            let nonce = NULL_NONCE;
            let seal = SkhashSeal { mix_hash, nonce };
            Ok(seal)
        } else {
            let mix_hash = Rlp::new(seal[0].as_ref()).as_val::<H256>()?;
            let nonce = Rlp::new(seal[1].as_ref()).as_val::<H64>()?;
            let seal = SkhashSeal { mix_hash, nonce };
            Ok(seal)
        }
    }
}

/// Shabal Skhash Engine implementation
// block_state_by_hash -> block state indexed by header hash.
#[cfg(not(test))]
pub struct Skhash {
    epoch_length: u64,
    skhash_params: SkhashParams,
    poc: SkhashManager,
    machine: EthereumMachine,
    client: RwLock<Option<Weak<dyn EngineClient>>>,
    signer: RwLock<Option<Box<dyn EngineSigner>>>,
    best_nonce: Mutex<Cell<Option<Nonce>>>,
    account_cache: AccountCacher,
}

#[cfg(test)]
/// Test version of `SkhashEngine` to make all fields public
pub struct Skhash {
    pub epoch_length: u64,
    pub skhash_params: SkhashParams,
    pub poc: SkhashManager,
    pub machine: EthereumMachine,
    pub client: Arc<RwLock<Option<Weak<EngineClient>>>>,
    pub signer: RwLock<Option<Box<EngineSigner>>>,
    pub best_nonce: Mutex<Cell<Option<Nonce>>>,
    pub account_cache: AccountCacher,
}

// TODO [rphmeier]
//
// for now, this is different than Skhash's own epochs, and signal
// "consensus epochs".
// in this sense, `Skhash` is epochless: the same `EpochVerifier` can be used
// for any block in the chain.
// in the future, we might move the Ethash epoch
// caching onto this mechanism as well.
impl EpochVerifier<EthereumMachine> for Skhash {
    fn verify_light(&self, _header: &Header) -> Result<(), Error> {
        Ok(())
    }
    fn verify_heavy(&self, header: &Header) -> Result<(), Error> {
        self.verify_block_unordered(header)
    }
}

impl Engine<EthereumMachine> for Skhash {
    fn name(&self) -> &str {
        "Skhash"
    }
    fn machine(&self) -> &EthereumMachine {
        &self.machine
    }

    // Two fields - nonce and mix.
    fn seal_fields(&self, _header: &Header) -> usize {
        2
    }

    /// Additional engine-specific information for the user/developer concerning `header`.
    fn extra_info(&self, header: &Header) -> BTreeMap<String, String> {
        match SkhashSeal::parse_seal(header.seal()) {
            Ok(seal) => map![
                "nonce".to_owned() => format!("0x{:x}", seal.nonce),
                "mixHash".to_owned() => format!("0x{:x}", seal.mix_hash)
            ],
            _ => BTreeMap::default(),
        }
    }

    /// SkHash of PoC consensus doesn't allow Uncle block
    fn maximum_uncle_count(&self, _block: BlockNumber) -> usize {
        0
    }

    fn maximum_gas_limit(&self) -> Option<U256> {
        Some(0x7fff_ffff_ffff_ffffu64.into())
    }

    fn populate_from_parent(&self, header: &mut Header, parent: &Header) {
        self.calculate_difficulty(header, parent);
        self.calculate_hash_rate(header, parent);
        header.set_signature(self.next_generation_signature(parent));
    }

    /// Check Sender's nonce from PoC miner.
    /// It is current only used in PoC consensus.
    fn check_nonce(
        &self,
        rc_block: RefCell<ExecutedBlock>,
    ) -> Result<(RefCell<ExecutedBlock>), Error> {
        let mut block = rc_block.borrow_mut().clone();
        let nonce = SkhashSeal::parse_seal(block.header.seal())?.nonce.low_u64();
        //let miner = *block.header.miner();
        if nonce != 0 {
            let author = *block.header.author();
            let mut call = engines::default_system_or_code_call(&self.machine, &mut block);
            let mut cache = self.account_cache.clone();

            let range = cache.check(author, nonce, &mut call)?;

            if range < nonce {
                Err(EngineError::Custom(format!(
                    "verify block: invalid nonce scope, Expected: <= {}, Current: {}",
                    range, nonce
                )))?
            }
        }
        Ok((rc_block))
    }

    /// Apply the block reward on finalisation of the block.
    /// This assumes that all uncles are valid uncles (i.e. of at least one generation before the current).
    fn on_close_block(&self, block: &mut ExecutedBlock) -> Result<(), Error> {
        use std::ops::Shr;
        let rc_block = RefCell::new(block.clone());
        //block.header = rc_block.borrow_mut().header.clone();
        let header = &mut block.header;

        let rc_block = self.check_nonce(rc_block)?;
        // verify block 's miner must match author in contract
        // self.verify_block_miner(rc_block)?;

        self.apply_block_rewards(block)
    }

    #[cfg(not(feature = "miner-debug"))]
    fn verify_local_seal(&self, header: &Header) -> Result<(), Error> {
        self.verify_block_basic(header)
            .and_then(|_| self.verify_block_unordered(header))
    }

    #[cfg(feature = "miner-debug")]
    fn verify_local_seal(&self, _header: &Header) -> Result<(), Error> {
        warn!("Skipping seal verification, running in miner testing mode.");
        Ok(())
    }

    fn verify_block_basic(&self, header: &Header) -> Result<(), Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if header.timestamp() > now + MAX_TIMESTAMP_DIFFERENCE {
            Err(EngineError::Custom(format!("verify block: block timestamp in the future, block timestamp: {},, now: {}", header.timestamp(), now).into()))?
        }

        Ok(())
    }

    fn verify_block_unordered(&self, header: &Header) -> Result<(), Error> {
        let creator = recover_creator(header).unwrap();

        if creator == *header.author() {
            Ok(())
        } else {
            trace!(target: "engine ", "Expected creator: {}, decrypted creator:{}", *header.author(), creator);
            Err(ErrorKind::PoCBlockSignatureInvalid.into())
        }
    }

    fn verify_block_family(&self, header: &Header, parent: &Header) -> Result<(), Error> {
        // we should not calculate deadline for genesis blocks
        if header.number() == 0 {
            return Err(From::from(BlockError::RidiculousNumber(OutOfBounds {
                min: Some(1),
                max: None,
                found: header.number(),
            })));
        }

        // parent sanity check
        if parent.hash() != *header.parent_hash() || header.number() != parent.number() + 1 {
            Err(BlockError::UnknownParent(parent.hash()))?
        }

        if header.timestamp() <= parent.timestamp() {
            Err(BlockError::TimestampOverflow)?
        }

        // TODO: consider removing these lines.
        let min_difficulty = self.skhash_params.minimum_difficulty;
        if header.difficulty() < &min_difficulty {
            return Err(From::from(BlockError::DifficultyOutOfBounds(OutOfBounds {
                min: Some(min_difficulty),
                max: None,
                found: header.difficulty().clone(),
            })));
        }

        // check the seal fields (check the Skhash nonce).
        {
            let nonce = SkhashSeal::parse_seal(header.seal())?.nonce.low_u64();

            let deadline = {
                let gen_sig = self.next_generation_signature(parent);
                let account_id = header.author().low_u64();
                let deadline_unadjusted =
                    self.calculate_deadline(&gen_sig, header.number(), account_id, nonce)?;
                deadline_unadjusted / parent.base_target()
            };

            if header.timestamp() - parent.timestamp() <= deadline {
                Err(EngineError::Custom(format!("verify block: invalid timestamp, parent block timestamp: {}, block timestamp: {}, not met deadline: {}", parent.timestamp(), header.timestamp(), deadline).into()))?
            }
        }

        Ok(())
    }

    fn snapshot_components(&self) -> Option<Box<dyn (::snapshot::SnapshotComponents)>> {
        Some(Box::new(::snapshot::PowSnapshot::new(
            SNAPSHOT_BLOCKS,
            MAX_SNAPSHOT_BLOCKS,
        )))
    }

    fn fork_choice(&self, new: &ExtendedHeader, current: &ExtendedHeader) -> engines::ForkChoice {
        engines::total_difficulty_fork_choice(new, current)
    }

    fn register_client(&self, client: Weak<dyn EngineClient>) {
        *self.client.write() = Some(client.clone());
    }

    fn set_signer(&self, signer: Box<dyn EngineSigner>) {
        trace!(target: "engine", "set_signer: {}", signer.address());
        *self.signer.write() = Some(signer);
    }

    /// Skhash doesn't require external work to seal, so we always return true here.
    fn seals_internally(&self) -> Option<bool> {
        Some(true)
    }

    /// Returns if we are ready to seal.
    fn generate_seal(&self, block: &ExecutedBlock, _parent: &Header) -> Seal {
        trace!(target: "engine", "tried to generate_seal");

        if block.header.number() == 0 {
            trace!(target: "engine", "attempted to seal genesis block");
            return Seal::None;
        }

        if self.can_block() {
            match self.best_nonce.lock() {
                Ok(best_nonce_lock) => match best_nonce_lock.take() {
                    Some(best_nonce) => {
                        let miner = H256::from(best_nonce.account_address);
                        let nonce = best_nonce.nonce.to_be_bytes();

                        // set back
                        best_nonce_lock.set(Some(best_nonce));

                        let seal = vec![encode(&miner), encode(&nonce.to_vec())];
                        return Seal::Regular(seal);
                    }
                    None => {
                        error!(target: "engine", "generate_seal: best_nonce is None");
                    }
                },
                Err(e) => {
                    error!(target: "engine", "generate_seal: lock best_nonce: {}", e);
                }
            }
        }

        Seal::None
    }

    fn on_seal_block(&self, block: &mut ExecutedBlock) -> Result<(), Error> {
        // refresh block timestamp because of a block may from a queue of prepared blocks
        block.header.set_timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );

        let header = &mut block.header;

        let mut extra: Vec<u8> = Vec::with_capacity(NONCE_LENGTH + SIGNATURE_LENGTH);

        // append signature onto extra_data
        {
            header.set_extra_data(vec![]);
            let sig = self.sign_header(&header)?;
            extra.extend_from_slice(&sig[..]);
        }
        header.set_extra_data(extra.clone());
        let rc_block = RefCell::new(block.clone());
        self.check_nonce(rc_block)?;

        Ok(())
    }

    fn next_generation_signature(&self, header: &Header) -> H256 {
        let prev_gen_sig = {
            let sig = format!("{:x}", header.signature());
            decode_gensig(&sig)
        };
        let prev_generator = header.author().low_u64();
        let gen_sig = calculate_new_gensig(prev_generator, &prev_gen_sig);
        H256::from(gen_sig)
    }

    // returns adjusted deadline if success
    fn submit_nonce(&self, mut nonce: Nonce) -> Result<u64, String> {
        let client = self
            .client
            .read()
            .as_ref()
            .and_then(|weak| weak.upgrade())
            .ok_or("requires client ref, but none registered.")?;
        let chain_info = client.chain_info();
        if nonce.blockheight != chain_info.best_block_number + 1 {
            return Err("block height invalid".into());
        }

        let header = client
            .block_header(BlockId::Hash(chain_info.best_block_hash))
            .ok_or("block not found")?
            .decode()
            .map_err(|e| format!("{}", e))?;

        let deadline = {
            let gen_sig = self.next_generation_signature(&header);
            let deadline_unadjusted = self
                .calculate_deadline(
                    &gen_sig,
                    chain_info.best_block_number + 1,
                    nonce.account_id,
                    nonce.nonce,
                )
                .map_err(|e| format!("{}", e))?;
            deadline_unadjusted / header.base_target()
        };

        nonce.deadline = Some(deadline);

        // accepts the nonce if its deadline is better than the previous
        match self.best_nonce.lock() {
            Ok(best_nonce_lock) => match best_nonce_lock.take() {
                Some(best_nonce) => {
                    if deadline < best_nonce.deadline.unwrap() {
                        best_nonce_lock.set(Some(nonce));
                    }
                }
                None => {
                    best_nonce_lock.set(Some(nonce));
                }
            },
            Err(e) => {
                return Err(format!("{}", e));
            }
        }
        Ok(deadline)
    }

    fn step(&self) {
        if self.can_block() {
            let client = match self.client.read().as_ref().and_then(|weak| weak.upgrade()) {
                Some(client) => client,
                None => {
                    return;
                }
            };
            client.update_sealing();
        }
    }
}

impl Skhash {
    /// Create a new instance of Skhash engine
    pub fn new(
        cache_dir: &Path,
        skhash_params: SkhashParams,
        machine: EthereumMachine,
    ) -> Arc<Self> {
        let contract_address = Address::from_str(CONTRACT_ADDRESS).unwrap();

        let engine = Skhash {
            epoch_length: skhash_params.epoch,
            skhash_params,
            machine,
            poc: SkhashManager::new(cache_dir.as_ref()),
            client: Default::default(),
            signer: Default::default(),
            best_nonce: Mutex::new(Cell::new(None)),
            account_cache: AccountCacher::new(SystemOrCodeCallKind::Address(
                contract_address,
            )),
        };

        let engine = Arc::new(engine);

        engine.start_step_service(Arc::downgrade(&engine) as Weak<dyn Engine<_>>);

        engine
    }

    /// Query rewards from contract that use block miner account
    fn apply_block_rewards(
        &self,
        block: &mut ExecutedBlock,
    ) -> Result<(), Error> {
        use std::ops::Shr;

        let author = *block.header.author();
        let number = block.header.number();
        let hash_rate = *block.header.hash_rate();

        let (_, reward) = self.skhash_params.block_reward.iter()
            .rev()
            .find(|&(block, _)| *block <= number)
            .expect("Current block's reward is not found; this indicates a chain config error; qed");
        let init_reward = *reward;
        let contract_address = Address::from_str(CONTRACT_ADDRESS).unwrap();
        let mut reward_contract_preparation = Vec::new();

        let block_reward_amount = init_reward / (U256::from(2).pow(U256::from(number) / U256::from(HALF_TIME)));
        reward_contract_preparation.push((contract_address, RewardKind::Author, block_reward_amount));
        block_reward::apply_block_rewards(&reward_contract_preparation, block, &self.machine)?;

        let rewards = match self.skhash_params.block_reward_contract {
            Some(ref c) if number >= self.skhash_params.block_reward_contract_transition => {
                let mut beneficiaries = Vec::new();

                beneficiaries.push((author, RewardKind::Author));
                let mut call = engines::default_system_or_code_call(&self.machine, block);
                trace!(target: "engine", "debug log skhash hash_rate {:?} in blockNumber :{:?}", hash_rate, number);
                c.reward(block_reward_amount, &beneficiaries, &mut call)?;
                return Ok(());
            }
            _ => {
                let mut rewards = Vec::new();

                let (_, reward) = self.skhash_params.block_reward.iter()
                    .rev()
                    .find(|&(block, _)| *block <= number)
                    .expect("Current block's reward is not found; this indicates a chain config error; qed");
                let reward = *reward;

                //let n_uncles = LiveBlock::uncles(&*block).len();
                let n_uncles = block.uncles.len();

                // Bestow block rewards.
                let result_block_reward = reward + reward.shr(5) * U256::from(n_uncles);

                rewards.push((author, RewardKind::Author, result_block_reward));

                // Bestow uncle rewards.
                for u in &block.uncles {
                    let uncle_author = u.author();
                    let result_uncle_reward = (reward * U256::from(8 + u.number() - number)).shr(3);
                    rewards.push((
                        *uncle_author,
                        RewardKind::uncle(number, u.number()),
                        result_uncle_reward,
                    ));
                }
                rewards
            }
        };
        Ok(())
    }

    fn can_block(&self) -> bool {
        let nonce = {
            let best_nonce_lock = self.best_nonce.lock().unwrap();
            let best_nonce = best_nonce_lock.take();
            best_nonce_lock.set(best_nonce.clone());
            match best_nonce {
                Some(nonce) => nonce,
                None => {
                    return false;
                }
            }
        };

        let client = match self.client.read().as_ref().and_then(|weak| weak.upgrade()) {
            Some(client) => client,
            None => {
                return false;
            }
        };
        let chain_info = client.chain_info();
        if nonce.blockheight != chain_info.best_block_number + 1 {
            return false;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        trace!(target: "engine", "step() now: {},  chain_info.best_block_timestamp: {}, best_nonce: {:?}", now, chain_info.best_block_timestamp, &nonce);
        if now - chain_info.best_block_timestamp > nonce.deadline.unwrap() {
            true
        } else {
            false
        }
    }

    fn start_step_service<M: Machine + 'static>(&self, engine: Weak<dyn Engine<M>>) {
        let _thread = thread::Builder::new()
            .name("SkhashStepService".into())
            .spawn(move || {
                // startup delay.
                thread::sleep(Duration::from_secs(5));

                loop {
                    // TODO [yujian] to support shutdown

                    engine.upgrade().map(|x| x.step());
                    thread::sleep(Duration::from_millis(2000));
                }

                // trace!(target: "miner", "SkhashStepService: shutdown.");
            })
            .expect("SkhashStepService thread failed");
    }

    fn calculate_difficulty(&self, header: &mut Header, parent: &Header) {
        match self.calculate_base_target(header, parent) {
            Ok((difficulty, base_target)) => {
                header.set_difficulty(difficulty);
                header.set_base_target(base_target);
            }
            Err(e) => {
                error!(target: "engine", "calculate_difficulty: calculate_base_target: {}", e);
            }
        }
    }

    fn sign_header(&self, header: &Header) -> Result<Signature, Error> {
        match self.signer.read().as_ref() {
            None => Err(EngineError::RequiresSigner)?,
            Some(signer) => {
                let digest = header.bare_hash();
                match signer.sign(digest) {
                    Ok(sig) => Ok(sig),
                    Err(e) => Err(EngineError::Custom(e.into()))?,
                }
            }
        }
    }

    fn calculate_avg_basetarget(&self, parent: &Header) -> Result<(u64), Error> {
        if parent.number() == 0 {
            return Ok(parent.base_target());
        }
        let mut it_header = (*parent).clone();

        let mut count_base_target = 0u64;
        let mut counter = 0u64;
        let client = self
            .client
            .read()
            .as_ref()
            .and_then(|weak| weak.upgrade())
            .ok_or("requires client ref, but none registered.")?;

        loop {
            it_header = client
                .block_header(BlockId::Hash(*it_header.parent_hash()))
                .ok_or("parent block header not found")?
                .decode()
                .map_err(|e| e.to_string())?;
            count_base_target += it_header.base_target();

            counter += 1;
            if (counter % self.skhash_params.epoch == 0) || it_header.number() == 0 {
                break;
            }
        }

        let avg_base_target = count_base_target / counter;

        Ok(avg_base_target)
    }

    /// Each Epoch changes the hashRate once, and the first epoch formula is: 2E64 / init_base_target
    fn calculate_hash_rate(&self, header: &mut Header, parent: &Header) -> Result<(), Error> {
        let basetarget = parent.base_target();
        let mut hash_rate = *parent.hash_rate();

        if header.number() % HASH_RATE_CALC_EPOCH == 0 {
            //hash_rate = U256::from(INITIAL_BASE_TARGET) / U256::from(basetarget);
            hash_rate = self.calculate_avg_hashrate(header)?;
            trace!(target: "engine", "calculate_hash_rate hash_rate:{}, base_target:{}", hash_rate, header.base_target());
        }
        header.set_hash_rate(hash_rate);

        Ok(())
    }

    fn calculate_avg_hashrate(&self, parent: &Header) -> Result<(U256), Error> {
        if parent.number() == 0 {
            return Ok(*parent.hash_rate());
        }
        let mut it_header = (*parent).clone();

        let mut count_base_hashrate = U256::from(0);
        let mut counter = 0u64;
        let client = self
            .client
            .read()
            .as_ref()
            .and_then(|weak| weak.upgrade())
            .ok_or("requires client ref, but none registered.")?;

        loop {
            it_header = client
                .block_header(BlockId::Hash(*it_header.parent_hash()))
                .ok_or("parent block header not found")?
                .decode()
                .map_err(|e| e.to_string())?;
            let basetarget = it_header.base_target();
            count_base_hashrate += U256::from(INITIAL_BASE_TARGET) / U256::from(basetarget);

            counter += 1;
            if (counter % HASH_RATE_CALC_EPOCH == 0) || it_header.number() == 0 {
                break;
            }
        }

        let avg_base_hashrate = count_base_hashrate / U256::from(counter);

        Ok(avg_base_hashrate)
    }

    fn calculate_deadline(
        &self,
        signature: &H256,
        height: u64,
        account_id: u64,
        nonce: u64,
    ) -> Result<u64, Error> {
        let now = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap_or_default();

        trace!(target: "engine", "calculate_deadline begin time:{:#?}", now);
        let signature = format!("{:x}", signature);
        let gensig_chain = decode_gensig(&signature);
        let scoop = calculate_scoop(height, &gensig_chain);
        let scoop_now = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap_or_default();
        trace!(target: "engine", "calculate_scoop end time:{:#?}", scoop_now);

        let mut cache = vec![0u8; MAX_PLOT_SIZE];
        noncegen_rust(&mut cache[..], 0, account_id, nonce, 1);

        let mut scoopdata = vec![0u8; SCOOP_SIZE];
        let address = SCOOP_SIZE * scoop as usize;
        scoopdata.clone_from_slice(&cache[address..address + SCOOP_SIZE]);
        let scoopdata_now = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap_or_default();
        trace!(target: "engine", "calculate_scoopdata end time:{:#?}", scoopdata_now);

        let (deadline, _) = find_best_deadline_rust(&scoopdata[..], 1, &gensig_chain);
        let deadline_now = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap_or_default();
        trace!(target: "engine", "calculate_find_best_deadline end time:{:#?}", deadline_now);

        Ok(deadline)
    }

    /// calculates `base_target` and `difficulty` for block of `header`
    fn calculate_base_target(
        &self,
        header: &Header,
        parent: &Header,
    ) -> Result<(U256, u64), String> {
        let client = self
            .client
            .read()
            .as_ref()
            .and_then(|weak| weak.upgrade())
            .ok_or("requires client ref, but none registered.")?;

        let result = if header.number() == 0 {
            (U256::from(0), INITIAL_BASE_TARGET)
        } else if header.number() < 4 {
            let difficulty = U256::from(2).pow(U256::from(64)) / INITIAL_BASE_TARGET;
            (difficulty, INITIAL_BASE_TARGET)
        } else if header.number() < PARITY_DIFF_ADJUST_CHANGE_BLOCK {
            let mut it_header = (*parent).clone();
            let mut avg_base_target = BigUint::from(it_header.base_target().to_owned());
            loop {
                it_header = client
                    .block_header(BlockId::Hash(*it_header.parent_hash()))
                    .ok_or("parent block header not found")?
                    .decode()
                    .map_err(|e| e.to_string())?;
                avg_base_target = avg_base_target + it_header.base_target();
                if it_header.number() <= header.number() - 4 {
                    break;
                }
            }
            avg_base_target = avg_base_target / 4u64;
            let dif_time = header.timestamp() - it_header.timestamp();

            let cur_base_target = avg_base_target.to_u64().unwrap();
            let mut new_base_target = (BigUint::from(cur_base_target) * dif_time
                / (TARGET_TIME_SPAN * 4))
                .to_u64()
                .unwrap();
            if new_base_target > MAX_BASE_TARGET {
                new_base_target = MAX_BASE_TARGET;
            }
            if new_base_target < cur_base_target * 9 / 10 {
                new_base_target = cur_base_target * 9 / 10;
            }
            if new_base_target == 0 {
                new_base_target = 1;
            }
            let twofold_cur_base_target = cur_base_target * 11 / 10;
            if new_base_target > twofold_cur_base_target {
                new_base_target = twofold_cur_base_target;
            }

            let difficulty = U256::from(2).pow(U256::from(64)) / new_base_target;
            (difficulty, new_base_target)
        } else {
            let mut it_header = (*parent).clone();
            let mut avg_base_target = BigUint::from(it_header.base_target().to_owned());
            let mut counter = 1u64;
            loop {
                it_header = client
                    .block_header(BlockId::Hash(*it_header.parent_hash()))
                    .ok_or("parent block header not found")?
                    .decode()
                    .map_err(|e| e.to_string())?;
                counter += 1;
                avg_base_target =
                    (avg_base_target * counter + it_header.base_target()) / (counter + 1);
                if counter >= 24 {
                    break;
                }
            }
            let mut dif_time = header.timestamp() - it_header.timestamp();
            let target_timespan = TARGET_TIME_SPAN * 24;

            if dif_time < target_timespan / 2 {
                dif_time = target_timespan / 2;
            }
            if dif_time > target_timespan * 2 {
                dif_time = target_timespan * 2;
            }

            let cur_base_target = parent.base_target();
            let mut new_base_target = (avg_base_target * dif_time / target_timespan)
                .to_u64()
                .unwrap();

            if new_base_target > MAX_BASE_TARGET {
                new_base_target = MAX_BASE_TARGET;
            }
            if new_base_target == 0 {
                new_base_target = 1;
            }

            if new_base_target < cur_base_target * 8 / 10 {
                new_base_target = cur_base_target * 8 / 10;
            }

            if new_base_target > cur_base_target * 12 / 10 {
                new_base_target = cur_base_target * 12 / 10;
            }

            let difficulty = U256::from(2).pow(U256::from(64)) / new_base_target;
            (difficulty, new_base_target)
        };
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::{Skhash, SkhashParams};
    use block::*;
    use engines::Engine;
    use error::{BlockError, Error, ErrorKind};
    use ethereum::ethash::Ethash;
    use ethereum::{new_homestead_test_machine, new_mcip3_test, new_morden};
    use ethereum_types::{Address, H256, H64, U256};
    use rlp;
    use spec::Spec;
    use std::collections::BTreeMap;
    use std::str::FromStr;
    use std::sync::Arc;
    use tempdir::TempDir;
    use test_helpers::get_temp_state_db;
    use types::header::Header;

    fn test_spec() -> Spec {
        let tempdir = TempDir::new("").unwrap();
        new_morden(&tempdir.path())
    }

    fn get_default_skhash_params() -> SkhashParams {
        SkhashParams {
            minimum_difficulty: U256::from(131072),
            difficulty_bound_divisor: U256::from(2048),
            difficulty_increment_divisor: 10,
            metropolis_difficulty_increment_divisor: 9,
            duration_limit: 13,
            block_reward: {
                let mut ret = BTreeMap::new();
                ret.insert(0, 0.into());
                ret
            },
            expip2_transition: u64::max_value(),
            expip2_duration_limit: 30,
            block_reward_contract: None,
            block_reward_contract_transition: 0,
            progpow_transition: u64::max_value(),
            epoch: 3000,
        }
    }

    #[test]
    fn on_calculate_max_nonce_scope() {
        assert_eq!(32800_f64 * 1000 * 1000 * 4, 131200000000000);
        println!("account nonce value{}", 32800_f64 * 1000 * 1000 * 4);
    }

    #[test]
    fn on_close_block() {
        let spec = test_spec();
        let engine = &*spec.engine;
        let genesis_header = spec.genesis_header();
        let db = spec
            .ensure_db_good(get_temp_state_db(), &Default::default())
            .unwrap();
        let last_hashes = Arc::new(vec![genesis_header.hash()]);
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
        )
            .unwrap();
        let b = b.close().unwrap();
        assert_eq!(
            b.state.balance(&Address::zero()).unwrap(),
            U256::from_str("4563918244f40000").unwrap()
        );
    }

    #[test]
    fn on_close_block_with_uncle() {
        let spec = test_spec();
        let engine = &*spec.engine;
        let genesis_header = spec.genesis_header();
        let db = spec
            .ensure_db_good(get_temp_state_db(), &Default::default())
            .unwrap();
        let last_hashes = Arc::new(vec![genesis_header.hash()]);
        let mut b = OpenBlock::new(
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
        )
            .unwrap();
        let mut uncle = Header::new();
        let uncle_author: Address = "ef2d6d194084c2de36e0dabfce45d046b37d1106".into();
        uncle.set_author(uncle_author);
        b.push_uncle(uncle).unwrap();

        let b = b.close().unwrap();
        assert_eq!(
            b.state.balance(&Address::zero()).unwrap(),
            "478eae0e571ba000".into()
        );
        assert_eq!(
            b.state.balance(&uncle_author).unwrap(),
            "3cb71f51fc558000".into()
        );
    }

    #[test]
    fn has_valid_mcip3_era_block_rewards() {
        let spec = new_mcip3_test();
        let engine = &*spec.engine;
        let genesis_header = spec.genesis_header();
        let db = spec
            .ensure_db_good(get_temp_state_db(), &Default::default())
            .unwrap();
        let last_hashes = Arc::new(vec![genesis_header.hash()]);
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
        )
            .unwrap();
        let b = b.close().unwrap();

        let ubi_contract: Address = "00efdd5883ec628983e9063c7d969fe268bbf310".into();
        let dev_contract: Address = "00756cf8159095948496617f5fb17ed95059f536".into();
        assert_eq!(
            b.state.balance(&Address::zero()).unwrap(),
            U256::from_str("d8d726b7177a80000").unwrap()
        );
        assert_eq!(
            b.state.balance(&ubi_contract).unwrap(),
            U256::from_str("2b5e3af16b1880000").unwrap()
        );
        assert_eq!(
            b.state.balance(&dev_contract).unwrap(),
            U256::from_str("c249fdd327780000").unwrap()
        );
    }

    #[test]
    fn has_valid_metadata() {
        let engine = test_spec().engine;
        assert!(!engine.name().is_empty());
    }

    #[test]
    fn can_return_schedule() {
        let engine = test_spec().engine;
        let schedule = engine.schedule(10000000);
        assert!(schedule.stack_limit > 0);

        let schedule = engine.schedule(100);
        assert!(!schedule.have_delegate_call);
    }

    #[test]
    fn can_do_seal_verification_fail() {
        let engine = test_spec().engine;
        let header: Header = Header::default();

        let verify_result = engine.verify_block_basic(&header);

        match verify_result {
            Err(Error(ErrorKind::Block(BlockError::InvalidSealArity(_)), _)) => {}
            Err(_) => {
                panic!(
                    "should be block seal-arity mismatch error (got {:?})",
                    verify_result
                );
            }
            _ => {
                panic!("Should be error, got Ok");
            }
        }
    }

    #[test]
    fn can_do_difficulty_verification_fail() {
        let engine = test_spec().engine;
        let mut header: Header = Header::default();
        header.set_seal(vec![rlp::encode(&H256::zero()), rlp::encode(&H64::zero())]);

        let verify_result = engine.verify_block_basic(&header);

        match verify_result {
            Err(Error(ErrorKind::Block(BlockError::DifficultyOutOfBounds(_)), _)) => {}
            Err(_) => {
                panic!("should be block difficulty error (got {:?})", verify_result);
            }
            _ => {
                panic!("Should be error, got Ok");
            }
        }
    }

    #[test]
    fn can_do_proof_of_work_verification_fail() {
        let engine = test_spec().engine;
        let mut header: Header = Header::default();
        header.set_seal(vec![rlp::encode(&H256::zero()), rlp::encode(&H64::zero())]);
        header.set_difficulty(
            U256::from_str("ffffffffffffffffffffffffffffffffffffffffffffaaaaaaaaaaaaaaaaaaaa")
                .unwrap(),
        );

        let verify_result = engine.verify_block_basic(&header);

        match verify_result {
            Err(Error(ErrorKind::Block(BlockError::InvalidProofOfWork(_)), _)) => {}
            Err(_) => {
                panic!(
                    "should be invalid proof of work error (got {:?})",
                    verify_result
                );
            }
            _ => {
                panic!("Should be error, got Ok");
            }
        }
    }

    #[test]
    fn can_do_seal_unordered_verification_fail() {
        let engine = test_spec().engine;
        let header = Header::default();

        let verify_result = engine.verify_block_unordered(&header);

        match verify_result {
            Err(Error(ErrorKind::Block(BlockError::InvalidSealArity(_)), _)) => {}
            Err(_) => {
                panic!(
                    "should be block seal-arity mismatch error (got {:?})",
                    verify_result
                );
            }
            _ => {
                panic!("Should be error, got Ok");
            }
        }
    }

    #[test]
    fn can_do_seal_unordered_verification_fail2() {
        let engine = test_spec().engine;
        let mut header = Header::default();
        header.set_seal(vec![vec![], vec![]]);

        let verify_result = engine.verify_block_unordered(&header);
        // rlp error, shouldn't panic
        assert!(verify_result.is_err());
    }

    #[test]
    fn can_do_seal256_verification_fail() {
        let engine = test_spec().engine;
        let mut header: Header = Header::default();
        header.set_seal(vec![rlp::encode(&H256::zero()), rlp::encode(&H64::zero())]);
        let verify_result = engine.verify_block_unordered(&header);

        match verify_result {
            Err(Error(ErrorKind::Block(BlockError::MismatchedH256SealElement(_)), _)) => {}
            Err(_) => {
                panic!(
                    "should be invalid 256-bit seal fail (got {:?})",
                    verify_result
                );
            }
            _ => {
                panic!("Should be error, got Ok");
            }
        }
    }

    #[test]
    fn can_do_proof_of_work_unordered_verification_fail() {
        let engine = test_spec().engine;
        let mut header: Header = Header::default();
        header.set_seal(vec![
            rlp::encode(&H256::from(
                "b251bd2e0283d0658f2cadfdc8ca619b5de94eca5742725e2e757dd13ed7503d",
            )),
            rlp::encode(&H64::zero()),
        ]);
        header.set_difficulty(
            U256::from_str("ffffffffffffffffffffffffffffffffffffffffffffaaaaaaaaaaaaaaaaaaaa")
                .unwrap(),
        );

        let verify_result = engine.verify_block_unordered(&header);

        match verify_result {
            Err(Error(ErrorKind::Block(BlockError::InvalidProofOfWork(_)), _)) => {}
            Err(_) => {
                panic!(
                    "should be invalid proof-of-work fail (got {:?})",
                    verify_result
                );
            }
            _ => {
                panic!("Should be error, got Ok");
            }
        }
    }

    #[test]
    fn can_verify_block_family_genesis_fail() {
        let engine = test_spec().engine;
        let header: Header = Header::default();
        let parent_header: Header = Header::default();

        let verify_result = engine.verify_block_family(&header, &parent_header);

        match verify_result {
            Err(Error(ErrorKind::Block(BlockError::RidiculousNumber(_)), _)) => {}
            Err(_) => {
                panic!(
                    "should be invalid block number fail (got {:?})",
                    verify_result
                );
            }
            _ => {
                panic!("Should be error, got Ok");
            }
        }
    }

    #[test]
    fn can_verify_block_family_difficulty_fail() {
        let engine = test_spec().engine;
        let mut header: Header = Header::default();
        header.set_number(2);
        let mut parent_header: Header = Header::default();
        parent_header.set_number(1);

        let verify_result = engine.verify_block_family(&header, &parent_header);

        match verify_result {
            Err(Error(ErrorKind::Block(BlockError::InvalidDifficulty(_)), _)) => {}
            Err(_) => {
                panic!(
                    "should be invalid difficulty fail (got {:?})",
                    verify_result
                );
            }
            _ => {
                panic!("Should be error, got Ok");
            }
        }
    }

    #[test]
    fn difficulty_max_timestamp() {
        let machine = new_homestead_test_machine();
        let ethparams = get_default_skhash_params();
        let tempdir = TempDir::new("").unwrap();
        //        let ethash = Ethash::new(tempdir.path(), ethparams, machine, None);

        let mut parent_header = Header::default();
        parent_header.set_number(1000000);
        parent_header.set_difficulty(U256::from_str("b69de81a22b").unwrap());
        parent_header.set_timestamp(1455404053);
        let mut header = Header::default();
        header.set_number(parent_header.number() + 1);
        header.set_timestamp(u64::max_value());

        //        let difficulty = ethash.calculate_difficulty(&header, &parent_header);
        //        assert_eq!(U256::from(12543204905719u64), H256::from("123456789"));
    }

    #[test]
    fn test_extra_info() {
        let machine = new_homestead_test_machine();
        let ethparams = get_default_skhash_params();
        let tempdir = TempDir::new("").unwrap();
        //        let ethash = Ethash::new(tempdir.path(), ethparams, machine, None);
        let mut header = Header::default();
        header.set_seal(vec![
            rlp::encode(&H256::from(
                "b251bd2e0283d0658f2cadfdc8ca619b5de94eca5742725e2e757dd13ed7503d",
            )),
            rlp::encode(&H64::zero()),
        ]);
        //        let info = ethash.extra_info(&header);
        //        assert_eq!(info["nonce"], "0x0000000000000000");
        //        assert_eq!(
        //            info["mixHash"],
        //            "0xb251bd2e0283d0658f2cadfdc8ca619b5de94eca5742725e2e757dd13ed7503d"
        //        );
    }
}
