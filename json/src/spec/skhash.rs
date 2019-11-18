//!Skhash of PoC Engine params deserialization.

use std::collections::BTreeMap;
use uint::{self, Uint};
use bytes::Bytes;
use hash::Address;

/// Deserializable doppelganger of block rewards for SkhashParams
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
pub enum BlockReward {
    Single(Uint),
    Multi(BTreeMap<Uint, Uint>),
}

/// Skhash of PoC engine deserialization
#[derive(Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Skhash {
    //Skhash params
    pub params: SkhashParams,
}

/// Deserializable doppelganger of SkhashParams
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct SkhashParams {
    /// See main SkhashParams docs.
    #[serde(deserialize_with = "uint::validate_non_zero")]
    pub minimum_difficulty: Uint,
    /// See main SkhashParams docs.
    #[serde(deserialize_with = "uint::validate_non_zero")]
    pub difficulty_bound_divisor: Uint,
    /// See main SkhashParams docs.
    #[serde(default, deserialize_with = "uint::validate_optional_non_zero")]
    pub difficulty_increment_divisor: Option<Uint>,
    /// See main SkhashParams docs.
    #[serde(default, deserialize_with = "uint::validate_optional_non_zero")]
    pub metropolis_difficulty_increment_divisor: Option<Uint>,
    /// See main SkhashParams docs.
    pub duration_limit: Option<Uint>,

    /// Reward per block in wei.
    pub block_reward: Option<BlockReward>,
    /// Block at which the block reward contract should start being used.
    pub block_reward_contract_transition: Option<Uint>,
    /// Block reward contract address (setting the block reward contract
    /// overrides all other block reward parameters).
    pub block_reward_contract_address: Option<Address>,
    /// Block reward code. This overrides the block reward contract address.
    pub block_reward_contract_code: Option<Bytes>,

    /// EXPIP-2 block height
    pub expip2_transition: Option<Uint>,
    /// EXPIP-2 duration limit
    pub expip2_duration_limit: Option<Uint>,
    /// Block to transition to progpow
    #[serde(rename = "progpowTransition")]
    pub progpow_transition: Option<Uint>,
    ///  Network computing power statistics epoch length
    pub epoch: u64,
}