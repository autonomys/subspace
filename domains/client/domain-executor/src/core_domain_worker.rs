// Copyright 2020 Parity Technologies (UK) Ltd.
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

use crate::core_bundle_processor::CoreBundleProcessor;
use crate::core_bundle_producer::CoreBundleProducer;
use crate::domain_worker::{handle_block_import_notifications, handle_slot_notifications};
use crate::parent_chain::CoreDomainParentChain;
use crate::utils::{BlockInfo, ExecutorSlotInfo};
use crate::TransactionFor;
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use futures::channel::mpsc;
use futures::{future, FutureExt, Stream, StreamExt, TryFutureExt};
use sc_client_api::{AuxStore, BlockBackend, ProofProvider, StateBackendFor};
use sc_consensus::{BlockImport, ForkChoiceStrategy};
use sp_api::{BlockT, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderBackend;
use sp_consensus_slots::Slot;
use sp_core::traits::CodeExecutor;
use sp_domains::{DomainId, ExecutorApi};
use sp_runtime::traits::{HashFor, NumberFor};
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;
use system_runtime_primitives::SystemDomainApi;
use tracing::Instrument;

#[allow(clippy::too_many_arguments)]
pub(super) async fn start_worker<
    Block,
    SBlock,
    PBlock,
    Client,
    SClient,
    PClient,
    TransactionPool,
    Backend,
    IBNS,
    NSNS,
    E,
>(
    domain_id: DomainId,
    primary_chain_client: Arc<PClient>,
    client: Arc<Client>,
    bundle_producer: CoreBundleProducer<Block, SBlock, PBlock, Client, SClient, TransactionPool>,
    bundle_processor: CoreBundleProcessor<
        Block,
        SBlock,
        PBlock,
        Client,
        SClient,
        PClient,
        Backend,
        E,
    >,
    imported_block_notification_stream: IBNS,
    new_slot_notification_stream: NSNS,
    active_leaves: Vec<BlockInfo<PBlock>>,
    block_import_throttling_buffer_size: u32,
) where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + 'static,
    Client::Api: DomainCoreApi<Block, AccountId>
        + BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    for<'b> &'b Client: BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + ProofProvider<SBlock> + 'static,
    SClient::Api:
        DomainCoreApi<SBlock, AccountId> + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    IBNS: Stream<Item = (NumberFor<PBlock>, ForkChoiceStrategy, mpsc::Sender<()>)> + Send + 'static,
    NSNS: Stream<Item = (Slot, Blake2b256Hash)> + Send + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    E: CodeExecutor,
{
    let span = tracing::Span::current();

    let handle_block_import_notifications_fut =
        handle_block_import_notifications::<Block, PBlock, _, _, _>(
            domain_id,
            primary_chain_client.as_ref(),
            client.info().best_number,
            {
                let span = span.clone();

                move |primary_info, bundles, shuffling_seed, maybe_new_runtime| {
                    bundle_processor
                        .clone()
                        .process_bundles(primary_info, bundles, shuffling_seed, maybe_new_runtime)
                        .instrument(span.clone())
                        .boxed()
                }
            },
            active_leaves
                .into_iter()
                .map(
                    |BlockInfo {
                         hash,
                         parent_hash: _,
                         number,
                         fork_choice,
                     }| (hash, number, fork_choice),
                )
                .collect(),
            Box::pin(imported_block_notification_stream),
            block_import_throttling_buffer_size,
        );
    let handle_slot_notifications_fut = handle_slot_notifications::<Block, PBlock, _, _>(
        primary_chain_client.as_ref(),
        move |primary_info, slot_info| {
            let parent_chain = CoreDomainParentChain::<SClient, SBlock, PBlock>::new(
                bundle_producer.system_domain_client.clone(),
                bundle_producer.domain_id,
            );
            bundle_producer
                .clone()
                .produce_bundle(primary_info, slot_info, parent_chain)
                .instrument(span.clone())
                .unwrap_or_else(move |error| {
                    tracing::error!(?primary_info, ?error, "Error at producing bundle.");
                    None
                })
                .boxed()
        },
        Box::pin(
            new_slot_notification_stream.map(|(slot, global_challenge)| ExecutorSlotInfo {
                slot,
                global_challenge,
            }),
        ),
    );

    let _ = future::select(
        Box::pin(handle_block_import_notifications_fut),
        Box::pin(handle_slot_notifications_fut),
    )
    .await;
}
