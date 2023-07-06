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

//! # Domain Operator
//!
//! ## Domains
//!
//! Domains, the enshrined rollups solution of Subspace, is a configurable execution
//! framework allowing for the simple, secure and low-cost deployment of application
//! specific blockchain called domain.
//!
//! ## Operators
//!
//! In Subspace, the farmers offering the storage resources are responsible for maintaining
//! the consensus layer, operators are a separate class of contributors in the system focusing
//! on the execution layer, they provide the necessary computational resources to maintain the
//! blockchain state by running domains. Some deposits as the stake are required to be an operator.
//!
//! Specifically, operators have the responsibity of producing a [`Bundle`] which contains a
//! number of [`ExecutionReceipt`]s on each slot notified from the consensus chain. The operators
//! are primarily driven by two events from the consensus chain.
//!
//! - On each new slot, operators will attempt to solve a domain-specific bundle election
//! challenge derived from a global randomness provided by the consensus chain. Upon finding
//! a solution to the challenge, they will start producing a bundle: they will collect a set
//! of extrinsics from the transaction pool which are verified to be able to cover the transaction
//! fee. With these colltected extrinsics, the bundle election solution and proper receipts, a
//! [`Bundle`] can be constructed and then be submitted to the consensus chain. The transactions
//! included in each bundle are uninterpretable blob from the consensus chain's persepective.
//!
//! - On each imported consensus block, operators will extract all the needed bundles from it
//! and convert the bundles to a list of extrinsics, construct a custom [`BlockBuilder`] to
//! build a domain block. The execution trace of all the extrinsics and hooks like
//! `initialize_block`/`finalize_block` will be recorded during the domain block execution.
//! Once the domain block is imported successfully, the [`ExecutionReceipt`] of this block
//! will be generated and stored locally.
//!
//! The receipt of each domain block contains all the intermediate state roots during the block
//! execution, which will be gossiped in the domain subnet (in future). All operators whether running as an
//! authority or a full node will compute each block and generate an execution receipt independently,
//! once the execution receipt received from the network does not match the one produced locally,
//! a [`FraudProof`] will be generated and reported to the consensus chain accordingly.
//!
//! [`BlockBuilder`]: ../domain_block_builder/struct.BlockBuilder.html
//! [`FraudProof`]: ../sp_domains/struct.FraudProof.html

#![feature(array_windows)]
#![feature(const_option)]
#![feature(drain_filter)]

mod aux_schema;
mod bundle_processor;
mod bundle_producer_election_solver;
mod domain_block_processor;
mod domain_bundle_producer;
mod domain_bundle_proposer;
mod domain_worker;
mod domain_worker_starter;
mod fraud_proof;
mod operator;
mod parent_chain;
mod sortition;
#[cfg(test)]
mod tests;
mod utils;

pub use self::operator::Operator;
pub use self::parent_chain::DomainParentChain;
pub use self::utils::{DomainBlockImportNotification, DomainImportNotifications};
use crate::utils::BlockInfo;
use futures::channel::mpsc;
use futures::Stream;
use sc_client_api::BlockImportNotification;
use sc_utils::mpsc::TracingUnboundedSender;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::{SelectChain, SyncOracle};
use sp_consensus_slots::Slot;
use sp_domains::{Bundle, DomainId, ExecutionReceipt};
use sp_keystore::KeystorePtr;
use sp_runtime::traits::{
    Block as BlockT, HashFor, Header as HeaderT, NumberFor, One, Saturating, Zero,
};
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;

type ExecutionReceiptFor<Block, CBlock> = ExecutionReceipt<
    NumberFor<CBlock>,
    <CBlock as BlockT>::Hash,
    NumberFor<Block>,
    <Block as BlockT>::Hash,
>;

type TransactionFor<Backend, Block> =
    <<Backend as sc_client_api::Backend<Block>>::State as sc_client_api::backend::StateBackend<
        HashFor<Block>,
    >>::Transaction;

type BundleSender<Block, CBlock> = TracingUnboundedSender<
    Bundle<
        <Block as BlockT>::Extrinsic,
        NumberFor<CBlock>,
        <CBlock as BlockT>::Hash,
        NumberFor<Block>,
        <Block as BlockT>::Hash,
    >,
>;

/// Notification streams from the consensus chain driving the executor.
pub struct OperatorStreams<CBlock, IBNS, CIBNS, NSNS> {
    /// Pause the consensus block import when the consensus chain client
    /// runs much faster than the domain client.
    pub consensus_block_import_throttling_buffer_size: u32,
    /// Notification about to be imported.
    ///
    /// Fired before the completion of entire block import pipeline.
    pub block_importing_notification_stream: IBNS,
    /// Consensus block import notification from the client.
    ///
    /// Fired after the completion of entire block import pipeline.
    pub imported_block_notification_stream: CIBNS,
    /// New slot arrives.
    pub new_slot_notification_stream: NSNS,
    pub _phantom: PhantomData<CBlock>,
}

pub struct OperatorParams<
    Block,
    CBlock,
    Client,
    CClient,
    TransactionPool,
    Backend,
    E,
    IBNS,
    CIBNS,
    NSNS,
    BI,
> where
    Block: BlockT,
    CBlock: BlockT,
    IBNS: Stream<Item = (NumberFor<CBlock>, mpsc::Sender<()>)> + Send + 'static,
    CIBNS: Stream<Item = BlockImportNotification<CBlock>> + Send + 'static,
    NSNS: Stream<Item = (Slot, Blake2b256Hash, Option<mpsc::Sender<()>>)> + Send + 'static,
{
    pub domain_id: DomainId,
    pub consensus_client: Arc<CClient>,
    pub consensus_network_sync_oracle: Arc<dyn SyncOracle + Send + Sync>,
    pub client: Arc<Client>,
    pub transaction_pool: Arc<TransactionPool>,
    pub backend: Arc<Backend>,
    pub code_executor: Arc<E>,
    pub is_authority: bool,
    pub keystore: KeystorePtr,
    pub bundle_sender: Arc<BundleSender<Block, CBlock>>,
    pub operator_streams: OperatorStreams<CBlock, IBNS, CIBNS, NSNS>,
    pub domain_confirmation_depth: NumberFor<Block>,
    pub block_import: Arc<BI>,
}

/// Returns the active leaves the operator should start with.
///
/// The longest chain is used as the fork choice for the leaves as the consensus block's fork choice
/// is only available in the imported consensus block notifications.
async fn active_leaves<CBlock, CClient, SC>(
    client: &CClient,
    select_chain: &SC,
) -> Result<Vec<BlockInfo<CBlock>>, sp_consensus::Error>
where
    CBlock: BlockT,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + 'static,
    SC: SelectChain<CBlock>,
{
    let best_block = select_chain.best_chain().await?;

    // No leaves if starting from the genesis.
    if best_block.number().is_zero() {
        return Ok(Vec::new());
    }

    let mut leaves = select_chain
        .leaves()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|hash| {
            let number = client.number(hash).ok()??;

            // Only consider leaves that are in maximum an uncle of the best block.
            if number < best_block.number().saturating_sub(One::one()) || hash == best_block.hash()
            {
                return None;
            };

            let parent_hash = *client.header(hash).ok()??.parent_hash();

            Some(BlockInfo {
                hash,
                parent_hash,
                number,
                is_new_best: false,
            })
        })
        .collect::<Vec<_>>();

    // Sort by block number and get the maximum number of leaves
    leaves.sort_by_key(|b| b.number);

    leaves.push(BlockInfo {
        hash: best_block.hash(),
        parent_hash: *best_block.parent_hash(),
        number: *best_block.number(),
        is_new_best: true,
    });

    /// The maximum number of active leaves we forward to the [`Operator`] on startup.
    const MAX_ACTIVE_LEAVES: usize = 4;

    Ok(leaves.into_iter().rev().take(MAX_ACTIVE_LEAVES).collect())
}
