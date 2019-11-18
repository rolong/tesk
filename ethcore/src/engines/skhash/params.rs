use std::collections::BTreeMap;
use std::sync::Arc;

use types::BlockNumber;
use ethereum_types::U256;
use engines::block_reward::BlockRewardContract;

use ethjson;

/// TODO current SkhashParams copy from Ethash 's
/// `Skhash` params
pub struct SkhashParams {
    /// Minimum difficulty.
    pub minimum_difficulty: U256,
    /// Difficulty bound divisor.
    pub difficulty_bound_divisor: U256,
    /// Difficulty increment divisor.
    pub difficulty_increment_divisor: u64,
    /// Metropolis difficulty increment divisor.
    pub metropolis_difficulty_increment_divisor: u64,
    /// Block duration.
    pub duration_limit: u64,
    /// Block reward in base units.
    pub block_reward: BTreeMap<BlockNumber, U256>,
    /// EXPIP-2 block height
    pub expip2_transition: u64,
    /// EXPIP-2 duration limit
    pub expip2_duration_limit: u64,
    /// Block reward contract transition block.
    pub block_reward_contract_transition: u64,
    /// Block reward contract.
    pub block_reward_contract: Option<BlockRewardContract>,
    /// Block to transition to progpow
    pub progpow_transition: u64,
    ///  Epoch length as defined in EIP
    pub epoch: u64,
}

impl From<ethjson::spec::SkhashParams> for SkhashParams {
    fn from(p: ethjson::spec::SkhashParams) -> Self {
        let epoch = p.epoch.into();

        SkhashParams {
            epoch: epoch,
            minimum_difficulty: p.minimum_difficulty.into(),
            difficulty_bound_divisor: p.difficulty_bound_divisor.into(),
            difficulty_increment_divisor: p.difficulty_increment_divisor.map_or(10, Into::into),
            metropolis_difficulty_increment_divisor: p.metropolis_difficulty_increment_divisor.map_or(9, Into::into),
            duration_limit: p.duration_limit.map_or(0, Into::into),
            block_reward: p.block_reward.map_or_else(
                || {
                    let mut ret = BTreeMap::new();
                    ret.insert(0, U256::zero());
                    ret
                },
                |reward| {
                    match reward {
                        ethjson::spec::SkBlockReward::Single(reward) => {
                            let mut ret = BTreeMap::new();
                            ret.insert(0, reward.into());
                            ret
                        }
                        ethjson::spec::SkBlockReward::Multi(multi) => {
                            multi.into_iter()
                                .map(|(block, reward)| (block.into(), reward.into()))
                                .collect()
                        }
                    }
                }),
            expip2_transition: p.expip2_transition.map_or(u64::max_value(), Into::into),
            expip2_duration_limit: p.expip2_duration_limit.map_or(30, Into::into),
            progpow_transition: p.progpow_transition.map_or(u64::max_value(), Into::into),
            block_reward_contract_transition: p.block_reward_contract_transition.map_or(0, Into::into),
            block_reward_contract: match (p.block_reward_contract_code, p.block_reward_contract_address) {
                (Some(code), _) => Some(BlockRewardContract::new_from_code(Arc::new(code.into()))),
                (_, Some(address)) => Some(BlockRewardContract::new_from_address(address.into())),
                (None, None) => None,
            },
        }
    }
}