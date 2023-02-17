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

//! # Domain Executor
//!
//! ## Domains
//!
//! Domains, the enshrined rollups solution of Subspace, is a configurable execution
//! framework allowing for the simple, secure and low-cost deployment of application
//! specific blockchain called domain.
//!
//! There are three types of domains: system domain, core domain and open domain.
//!
//! - System domain: responsible for securing and managing all the non-system domains
//! by maintaining the receipts of other domains and handling the potential execution
//! disputes using the fraud-proof mechanism. The system domain itself is secured by the
//! consensus chain.
//! - Core domain: developed and audited by Subspace team, providing some important
//! system-wide features, e.g., the payments, contracts and messages.
//! - Open domain: similar to the smart contract in Ethereum which reflects application
//! specific business logic and can be created by anyone with enough security deposits.
//!
//! All kinds of domains form the Subspace execution layer. The domains do not rely on
//! any typical blockchain consensus like PoW for producing blocks, the block production
//! of each domain is totally driven by the consensus chain which are collectively
//! maintained by Subspace farmers. Please refer to the white paper [Computation section]
//! for more in-depth description and analysis.
//!
//! ## Executors
//!
//! In Subspace, the farmers offering the storage resources are responsible for maintaining
//! the consensus layer, executors are a separate class of contributors in the system focusing
//! on the execution layer, they provide the necessary computational resources to maintain the
//! blockchain state by running domains. Some deposits as the stake are required to be an executor.
//! Every executor must run the system domain, but they can opt-in to run one or multiple
//! non-system domains by partially allocating their executor stake on the domain.
//!
//! Specifically, executors have the responsibity of producing a [`SignedBundle`] which contains a
//! number of [`ExecutionReceipt`]s on each slot notified from the consensus chain. The executors
//! are primarily driven by two events from the consensus chain.
//!
//! - On each new slot, executors will attempt to solve a domain-specific bundle election
//! challenge derived from a global randomness provided by the consensus chain. Upon finding
//! a solution to the challenge, they will start producing a bundle: they will collect a set
//! of extrinsics from the transaction pool which are verified to be able to cover the transaction
//! fee. With these colltected extrinsics, the bundle election solution and proper receipts, a
//! [`SignedBundle`] can be constructed and then be submitted to the consensus chain. The transactions
//! included in each bundle are uninterpretable blob from the consensus chain's persepective.
//!
//! - On each imported primary block, executors will extract all the needed bundles from it
//! and convert the bundles to a list of extrinsics, construct a custom [`BlockBuilder`] to
//! build a domain block. The execution trace of all the extrinsics and hooks like
//! `initialize_block`/`finalize_block` will be recorded during the domain block execution.
//! Once the domain block is imported successfully, the [`ExecutionReceipt`] of this block
//! will be generated and stored locally.
//!
//! The receipt of each domain block contains all the intermediate state roots during the block
//! execution, which will be gossiped in the executor network. All executors whether running as an
//! authority or a full node will compute each block and generate an execution receipt independently,
//! once the execution receipt received from the network does not match the one produced locally,
//! a [`FraudProof`] will be generated and reported to the consensus chain accordingly.
//!
//! [Computation section]: https://subspace.network/news/subspace-network-whitepaper
//! [`BlockBuilder`]: ../domain_block_builder/struct.BlockBuilder.html
//! [`FraudProof`]: ../sp_domains/struct.FraudProof.html

#![feature(array_windows)]
#![feature(drain_filter)]

mod aux_schema;
mod bundle_election_solver;
mod core_bundle_processor;
mod core_domain_worker;
mod core_executor;
mod core_gossip_message_validator;
mod domain_block_processor;
mod domain_bundle_producer;
mod domain_bundle_proposer;
mod domain_worker;
mod fraud_proof;
mod gossip_message_validator;
mod merkle_tree;
mod parent_chain;
mod system_bundle_processor;
mod system_domain_worker;
mod system_executor;
mod system_gossip_message_validator;
#[cfg(test)]
mod tests;
mod utils;
pub mod xdm_validator;

pub use self::core_executor::Executor as CoreExecutor;
pub use self::core_gossip_message_validator::CoreGossipMessageValidator;
pub use self::system_executor::Executor as SystemExecutor;
pub use self::system_gossip_message_validator::SystemGossipMessageValidator;
use crate::utils::BlockInfo;
use futures::channel::mpsc;
use futures::Stream;
use sc_consensus::ForkChoiceStrategy;
use sc_network::NetworkService;
use sc_utils::mpsc::TracingUnboundedSender;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::SelectChain;
use sp_consensus_slots::Slot;
use sp_core::traits::SpawnNamed;
use sp_domains::{ExecutionReceipt, SignedBundle};
use sp_keystore::SyncCryptoStorePtr;
use sp_runtime::traits::{
    Block as BlockT, HashFor, Header as HeaderT, NumberFor, One, Saturating, Zero,
};
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;

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

pub struct EssentialExecutorParams<
    Block,
    PBlock,
    Client,
    PClient,
    TransactionPool,
    Backend,
    E,
    IBNS,
    NSNS,
> where
    Block: BlockT,
    PBlock: BlockT,
    IBNS: Stream<Item = (NumberFor<PBlock>, ForkChoiceStrategy, mpsc::Sender<()>)> + Send + 'static,
    NSNS: Stream<Item = (Slot, Blake2b256Hash)> + Send + 'static,
{
    pub primary_chain_client: Arc<PClient>,
    pub primary_network: Arc<NetworkService<PBlock, PBlock::Hash>>,
    pub client: Arc<Client>,
    pub transaction_pool: Arc<TransactionPool>,
    pub backend: Arc<Backend>,
    pub code_executor: Arc<E>,
    pub is_authority: bool,
    pub keystore: SyncCryptoStorePtr,
    pub spawner: Box<dyn SpawnNamed + Send + Sync>,
    pub bundle_sender: Arc<BundleSender<Block, PBlock>>,
    pub block_import_throttling_buffer_size: u32,
    pub imported_block_notification_stream: IBNS,
    pub new_slot_notification_stream: NSNS,
}

/// Returns the active leaves the overseer should start with.
///
/// The longest chain is used as the fork choice for the leaves as the primary block's fork choice
/// is only available in the imported primary block notifications.
async fn active_leaves<PBlock, PClient, SC>(
    client: &PClient,
    select_chain: &SC,
) -> Result<Vec<BlockInfo<PBlock>>, sp_consensus::Error>
where
    PBlock: BlockT,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    SC: SelectChain<PBlock>,
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
                fork_choice: ForkChoiceStrategy::LongestChain,
            })
        })
        .collect::<Vec<_>>();

    // Sort by block number and get the maximum number of leaves
    leaves.sort_by_key(|b| b.number);

    leaves.push(BlockInfo {
        hash: best_block.hash(),
        parent_hash: *best_block.parent_hash(),
        number: *best_block.number(),
        fork_choice: ForkChoiceStrategy::LongestChain,
    });

    /// The maximum number of active leaves we forward to the [`Overseer`] on startup.
    const MAX_ACTIVE_LEAVES: usize = 4;

    Ok(leaves.into_iter().rev().take(MAX_ACTIVE_LEAVES).collect())
}
