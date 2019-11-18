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

//! RPC types

#[cfg(test)]
mod eth_types;

mod account_info;
mod block;
mod block_number;
mod bytes;
mod call_request;
mod confirmations;
mod consensus_status;
mod derivation;
mod eip191;
mod filter;
mod histogram;
mod index;
mod log;
mod node_kind;
mod poc;
mod private_receipt;
mod provenance;
mod receipt;
mod rpc_settings;
mod secretstore;
mod sync;
mod trace;
mod trace_filter;
mod transaction;
mod transaction_condition;
mod transaction_request;
mod work;

pub mod pubsub;

pub use self::account_info::{
    AccountInfo, EthAccount, ExtAccountInfo, HwAccountInfo, RecoveredAccount, StorageProof,
};
pub use self::block::{Block, BlockTransactions, Header, Rich, RichBlock, RichHeader};
pub use self::block_number::{block_number_to_id, BlockNumber, LightBlockNumber};
pub use self::bytes::Bytes;
pub use self::call_request::CallRequest;
pub use self::confirmations::{
    ConfirmationPayload, ConfirmationRequest, ConfirmationResponse, ConfirmationResponseWithToken,
    DecryptRequest, EIP191SignRequest, Either, EthSignRequest, TransactionModification,
};
pub use self::consensus_status::*;
pub use self::derivation::{Derive, DeriveHash, DeriveHierarchical};
pub use self::eip191::{EIP191Version, PresignedTransaction};
pub use self::filter::{Filter, FilterChanges};
pub use self::histogram::Histogram;
pub use self::index::Index;
pub use self::log::Log;
pub use self::node_kind::{Availability, Capability, NodeKind};
pub use self::poc::{MiningInfo, Nonce, SubmitNonceResponse};
pub use self::private_receipt::{
    PrivateTransactionReceipt, PrivateTransactionReceiptAndTransaction,
};
pub use self::provenance::Origin;
pub use self::receipt::Receipt;
pub use self::rpc_settings::RpcSettings;
pub use self::secretstore::EncryptedDocumentKey;
pub use self::sync::{
    ChainStatus, EthProtocolInfo, PeerInfo, PeerNetworkInfo, PeerProtocolsInfo, Peers,
    PipProtocolInfo, SyncInfo, SyncStatus, TransactionStats,
};
pub use self::trace::{LocalizedTrace, TraceResults, TraceResultsWithTransactionHash};
pub use self::trace_filter::TraceFilter;
pub use self::transaction::{LocalTransactionStatus, RichRawTransaction, Transaction};
pub use self::transaction_condition::TransactionCondition;
pub use self::transaction_request::TransactionRequest;
pub use self::work::Work;
// TODO [ToDr] Refactor to a proper type Vec of enums?
/// Expected tracing type.
pub type TraceOptions = Vec<String>;
