// Copyright 2017-2020 Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! Message types for the overseer and subsystems.
//!
//! These messages are intended to define the protocol by which different subsystems communicate with each
//! other and signals that they receive from an overseer to coordinate their work.
//! This is intended for use with the `polkadot-overseer` crate.
//!
//! Subsystems' APIs are defined separately from their implementation, leading to easier mocking.

use futures::channel::oneshot;

pub use sc_network::IfDisconnected;

use cirrus_node_primitives::{BlockWeight, CollationGenerationConfig};
use sp_executor::{Bundle, ExecutionReceipt, FraudProof};
use sp_runtime::OpaqueExtrinsic;
use subspace_runtime_primitives::{opaque::Header as BlockHeader, BlockNumber, Hash};

/// Subsystem messages where each message is always bound to a relay parent.
pub trait BoundToRelayParent {
	/// Returns the relay parent this message is bound to.
	fn relay_parent(&self) -> Hash;
}

/// The result of `DisputeCoordinatorMessage::ImportStatements`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ImportStatementsResult {
	/// Import was invalid (candidate was not available)  and the sending peer should get banned.
	InvalidImport,
	/// Import was valid and can be confirmed to peer.
	ValidImport,
}

/// A response channel for the result of a chain API request.
pub type ChainApiResponseChannel<T> = oneshot::Sender<Result<T, crate::errors::ChainApiError>>;

/// Chain API request subsystem message.
#[derive(Debug)]
pub enum ChainApiMessage {
	/// Request the block number by hash.
	/// Returns `None` if a block with the given hash is not present in the db.
	BlockNumber(Hash, ChainApiResponseChannel<Option<BlockNumber>>),
	/// Request the block header by hash.
	/// Returns `None` if a block with the given hash is not present in the db.
	BlockHeader(Hash, ChainApiResponseChannel<Option<BlockHeader>>),
	/// Get the cumulative weight of the given block, by hash.
	/// If the block or weight is unknown, this returns `None`.
	///
	/// Note: this is the weight within the low-level fork-choice rule,
	/// not the high-level one implemented in the chain-selection subsystem.
	///
	/// Weight is used for comparing blocks in a fork-choice rule.
	BlockWeight(Hash, ChainApiResponseChannel<Option<BlockWeight>>),
	/// Request the finalized block hash by number.
	/// Returns `None` if a block with the given number is not present in the db.
	/// Note: the caller must ensure the block is finalized.
	FinalizedBlockHash(BlockNumber, ChainApiResponseChannel<Option<Hash>>),
	/// Request the last finalized block number.
	/// This request always succeeds.
	FinalizedBlockNumber(ChainApiResponseChannel<BlockNumber>),
	/// Request the block by hash.
	BlockBody(Hash, ChainApiResponseChannel<Option<Vec<OpaqueExtrinsic>>>),
	/// Request the best block hash.
	BestBlockHash(ChainApiResponseChannel<Hash>),
	/// Request the `k` ancestors block hashes of a block with the given hash.
	/// The response channel may return a `Vec` of size up to `k`
	/// filled with ancestors hashes with the following order:
	/// `parent`, `grandparent`, ...
	Ancestors {
		/// The hash of the block in question.
		hash: Hash,
		/// The number of ancestors to request.
		k: usize,
		/// The response channel.
		response_channel: ChainApiResponseChannel<Vec<Hash>>,
	},
}

impl ChainApiMessage {
	/// If the current variant contains the relay parent hash, return it.
	pub fn relay_parent(&self) -> Option<Hash> {
		None
	}
}

/// A sender for the result of a runtime API request.
pub type RuntimeApiSender<T> = oneshot::Sender<Result<T, crate::errors::RuntimeApiError>>;

/// A request to the Runtime API subsystem.
#[derive(Debug)]
pub enum RuntimeApiRequest {
	/// Submit the candidate receipt to primary chain.
	// TODO: remove later
	SubmitCandidateReceipt(u32, Hash),
	/// Submit the execution receipt to primary chain.
	SubmitExecutionReceipt(ExecutionReceipt<Hash>),
	/// Submit the transaction bundle to primary chain.
	SubmitTransactionBundle(Bundle),
	/// Submit the fraud proof to primary chain.
	SubmitFraudProof(FraudProof),
	/// Extract the bundles from the extrinsics of a block.
	/// Extract the bundles from the extrinsics of a block.
	ExtractBundles(Vec<OpaqueExtrinsic>, RuntimeApiSender<Vec<Bundle>>),
	/// Get the pending head of executor chain.
	PendingHead(RuntimeApiSender<Option<Hash>>),
}

/// A message to the Runtime API subsystem.
#[derive(Debug)]
pub enum RuntimeApiMessage {
	/// Make a request of the runtime API against the post-state of the given relay-parent.
	Request(Hash, RuntimeApiRequest),
}

impl RuntimeApiMessage {
	/// If the current variant contains the relay parent hash, return it.
	pub fn relay_parent(&self) -> Option<Hash> {
		match self {
			Self::Request(hash, _) => Some(*hash),
		}
	}
}

/// Message to the Collation Generation subsystem.
#[derive(Debug)]
pub enum CollationGenerationMessage {
	/// Initialize the collation generation subsystem
	Initialize(CollationGenerationConfig),
	/// Fraud proof needs to be submitted to primary chain.
	SubmitFraudProof(FraudProof),
}

impl CollationGenerationMessage {
	/// If the current variant contains the relay parent hash, return it.
	pub fn relay_parent(&self) -> Option<Hash> {
		None
	}
}
