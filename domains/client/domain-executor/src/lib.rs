// Copyright 2019-2021 Parity Technologies (UK) Ltd.
// This file is part of Cumulus.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Cumulus.  If not, see <http://www.gnu.org/licenses/>.

//! # Subspace Executor
//!
//! Executors, a separate class of nodes in addition to the consensus nodes (farmers) in Subspace,
//! are designed to reduce the burden of maintaining the chain state for farmers by decoupling the
//! consensus and computation. As an execution layer, executor chain itself does no rely on any
//! typical blockchain consensus like PoW for producing blocks, the block production of executor
//! chain is totally driven by the consensus layer which are collectively maintained by Subspace
//! farmers. Please refer to the white paper [Computation section] for more in-depth description
//! and analysis.
//!
//! Specifically, executors are responsible for producing a [`SignedBundle`] on each slot from
//! the primary chain and producing an [`ExecutionReceipt`] on each primary block.
//!
//! On each new primary chain slot, executors will collect a set of extrinsics from the transaction
//! pool which are verified to be able to cover the transaction fee, and then use these extrinsics
//! to create a [`SignedBundle`], submitting it to the primary chain. The submitted bundles are mere
//! blob from the point of primary chain.
//!
//! On each imported primary block, executors will extract all the bundles from the primary block and
//! convert the bundles to a list of extrinsics, construct a custom [`BlockBuilder`] to build a secondary
//! block. The execution trace of all the extrinsics and hooks like
//! `initialize_block`/`finalize_block` will be recorded during the block execution. Once the
//! secondary block has been imported successfully, an executor that wins the election for producing
//! an execution receipt will publish the receipt over the executors network.
//!
//! The execution receipt of each block contains all the intermediate state roots during the block
//! execution, which will be gossiped in the executor network. All executors whether running as an
//! authority or a full node will compute each block and generate an execution receipt independently,
//! once the execution receipt received from the network does not match the one produced locally,
//! a [`FraudProof`] will be generated and reported to the primary chain accordingly.
//!
//! ## Notes
//!
//! Currently, the following terms are interexchangeable in the executor context:
//!
//! - Farmer, consensus node.
//! - Executor, execution/compute node.
//! - Primary chain, consensus layer.
//! - Secondary chain, execution layer.
//!
//! [Computation section]: https://subspace.network/news/subspace-network-whitepaper
//! [`BlockBuilder`]: ../domain_block_builder/struct.BlockBuilder.html
//! [`FraudProof`]: ../sp_domains/struct.FraudProof.html

#![feature(drain_filter)]

mod aux_schema;
mod bundle_election_solver;
mod core_bundle_processor;
mod core_bundle_producer;
mod core_domain_worker;
mod core_executor;
mod domain_block_processor;
mod domain_bundle_producer;
mod domain_bundle_proposer;
mod fraud_proof;
mod merkle_tree;
mod system_bundle_processor;
mod system_bundle_producer;
mod system_domain_worker;
mod system_executor;
#[cfg(test)]
mod tests;
mod utils;

pub use self::core_executor::Executor as CoreExecutor;
pub use self::system_executor::Executor as SystemExecutor;
use sc_utils::mpsc::TracingUnboundedSender;
use sp_domains::{ExecutionReceipt, SignedBundle};
use sp_runtime::traits::{Block as BlockT, HashFor, NumberFor};

/// The logging target.
const LOG_TARGET: &str = "domain::executor";

type ExecutionReceiptFor<PBlock, Hash> =
    ExecutionReceipt<NumberFor<PBlock>, <PBlock as BlockT>::Hash, Hash>;

type TransactionFor<Backend, Block> =
    <<Backend as sc_client_api::Backend<Block>>::State as sc_client_api::backend::StateBackend<
        HashFor<Block>,
    >>::Transaction;

type BundleSender<Block, PBlock> = TracingUnboundedSender<
    SignedBundle<
        <Block as BlockT>::Extrinsic,
        NumberFor<PBlock>,
        <PBlock as BlockT>::Hash,
        <Block as BlockT>::Hash,
    >,
>;
