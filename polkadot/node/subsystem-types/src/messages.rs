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

use std::borrow::Cow;

use futures::channel::oneshot;

use cirrus_node_primitives::{ CollationGenerationConfig};
use sp_executor::{
	BundleEquivocationProof, FraudProof, InvalidTransactionProof, OpaqueBundle,
	OpaqueExecutionReceipt,
};
use sp_runtime::OpaqueExtrinsic;
use subspace_core_primitives::Randomness;
use subspace_runtime_primitives::{opaque::Header as BlockHeader, Hash};

/// A response channel for the result of a chain API request.
pub type ChainApiResponseChannel<T> = oneshot::Sender<Result<T, crate::errors::ChainApiError>>;

/// Chain API request subsystem message.
#[derive(Debug)]
pub enum ChainApiMessage {
	/// Request the block header by hash.
	/// Returns `None` if a block with the given hash is not present in the db.
	BlockHeader(Hash, ChainApiResponseChannel<Option<BlockHeader>>),
	/// Request the block by hash.
	BlockBody(Hash, ChainApiResponseChannel<Option<Vec<OpaqueExtrinsic>>>),
	/// Request the best block hash.
	BestBlockHash(ChainApiResponseChannel<Hash>),
}

/// A sender for the result of a runtime API request.
pub type RuntimeApiSender<T> = oneshot::Sender<Result<T, crate::errors::RuntimeApiError>>;

/// A request to the Runtime API subsystem.
#[derive(Debug)]
pub enum RuntimeApiRequest {
	/// Submit the execution receipt to primary chain.
	SubmitExecutionReceipt(OpaqueExecutionReceipt),
	/// Submit the transaction bundle to primary chain.
	SubmitTransactionBundle(OpaqueBundle),
	/// Submit the fraud proof to primary chain.
	SubmitFraudProof(FraudProof),
	/// Submit the bundle equivocation proof to primary chain.
	SubmitBundleEquivocationProof(BundleEquivocationProof),
	/// Submit the invalid transaction proof to primary chain.
	SubmitInvalidTransactionProof(InvalidTransactionProof),
	/// Extract the bundles from the extrinsics of a block.
	ExtractBundles(Vec<OpaqueExtrinsic>, RuntimeApiSender<Vec<OpaqueBundle>>),
	/// Get the randomness seed for extrinsics shuffling.
	ExtrinsicsShufflingSeed(BlockHeader, RuntimeApiSender<Randomness>),
	/// Get the execution runtime blob.
	ExecutionWasmBundle(RuntimeApiSender<Cow<'static, [u8]>>),
}

/// A message to the Runtime API subsystem.
#[derive(Debug)]
pub enum RuntimeApiMessage {
	/// Make a request of the runtime API against the post-state of the given relay-parent.
	Request(Hash, RuntimeApiRequest),
}

/// Message to the Collation Generation subsystem.
#[derive(Debug)]
pub enum CollationGenerationMessage {
	/// Initialize the collation generation subsystem
	Initialize(CollationGenerationConfig),
	/// Fraud proof needs to be submitted to primary chain.
	FraudProof(FraudProof),
	/// Bundle equivocation proof needs to be submitted to primary chain.
	BundleEquivocationProof(BundleEquivocationProof),
	/// Invalid transaction proof needs to be submitted to primary chain.
	InvalidTransactionProof(InvalidTransactionProof),
}
