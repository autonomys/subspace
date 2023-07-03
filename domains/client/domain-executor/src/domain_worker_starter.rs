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

use crate::bundle_processor::BundleProcessor;
use crate::domain_bundle_producer::DomainBundleProducer;
use crate::domain_worker::{handle_block_import_notifications, handle_slot_notifications};
use crate::parent_chain::DomainParentChain;
use crate::utils::{BlockInfo, ExecutorSlotInfo};
use crate::{ExecutorStreams, TransactionFor};
use domain_runtime_primitives::{DomainCoreApi, InherentExtrinsicApi};
use futures::channel::mpsc;
use futures::{future, FutureExt, Stream, StreamExt, TryFutureExt};
use sc_client_api::{
    AuxStore, BlockBackend, BlockImportNotification, BlockchainEvents, Finalizer, ProofProvider,
    StateBackendFor,
};
use sc_consensus::BlockImport;
use sp_api::{BlockT, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_consensus_slots::Slot;
use sp_core::traits::{CodeExecutor, SpawnEssentialNamed};
use sp_domains::ExecutorApi;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{HashFor, NumberFor};
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;
use tracing::Instrument;

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub(super) async fn start_worker<
    Block,
    PBlock,
    Client,
    PClient,
    TransactionPool,
    Backend,
    IBNS,
    CIBNS,
    NSNS,
    E,
    BI,
>(
    spawn_essential: Box<dyn SpawnEssentialNamed>,
    primary_chain_client: Arc<PClient>,
    client: Arc<Client>,
    is_authority: bool,
    bundle_producer: DomainBundleProducer<
        Block,
        PBlock,
        PBlock,
        Client,
        PClient,
        DomainParentChain<Block, PBlock, PClient>,
        TransactionPool,
    >,
    bundle_processor: BundleProcessor<Block, PBlock, Client, PClient, Backend, E, BI>,
    executor_streams: ExecutorStreams<PBlock, IBNS, CIBNS, NSNS>,
    active_leaves: Vec<BlockInfo<PBlock>>,
) where
    Block: BlockT,
    PBlock: BlockT,
    NumberFor<PBlock>: From<NumberFor<Block>> + Into<NumberFor<Block>>,
    PBlock::Hash: From<Block::Hash>,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + Finalizer<Block, Backend>
        + 'static,
    Client::Api: DomainCoreApi<Block>
        + MessengerApi<Block, NumberFor<Block>>
        + InherentExtrinsicApi<Block>
        + BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    for<'b> &'b BI: BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    BI: Send + Sync + 'static,
    PClient: HeaderBackend<PBlock>
        + HeaderMetadata<PBlock, Error = sp_blockchain::Error>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + BlockchainEvents<PBlock>
        + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    IBNS: Stream<Item = (NumberFor<PBlock>, mpsc::Sender<()>)> + Send + 'static,
    CIBNS: Stream<Item = BlockImportNotification<PBlock>> + Send + 'static,
    NSNS: Stream<Item = (Slot, Blake2b256Hash, Option<mpsc::Sender<()>>)> + Send + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    E: CodeExecutor,
{
    let span = tracing::Span::current();

    let ExecutorStreams {
        primary_block_import_throttling_buffer_size,
        block_importing_notification_stream,
        imported_block_notification_stream,
        new_slot_notification_stream,
        _phantom,
    } = executor_streams;

    let handle_block_import_notifications_fut =
        handle_block_import_notifications::<Block, _, _, _, _, _>(
            spawn_essential,
            primary_chain_client.as_ref(),
            client.info().best_number,
            {
                let span = span.clone();

                move |primary_info| {
                    bundle_processor
                        .clone()
                        .process_bundles(primary_info)
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
                     }| (hash, number),
                )
                .collect(),
            Box::pin(block_importing_notification_stream),
            Box::pin(imported_block_notification_stream),
            primary_block_import_throttling_buffer_size,
        );
    let handle_slot_notifications_fut = handle_slot_notifications::<Block, PBlock, _, _>(
        primary_chain_client.as_ref(),
        move |primary_info, slot_info| {
            bundle_producer
                .clone()
                .produce_bundle(primary_info, slot_info)
                .instrument(span.clone())
                .unwrap_or_else(move |error| {
                    tracing::error!(?primary_info, ?error, "Error at producing bundle.");
                    None
                })
                .boxed()
        },
        Box::pin(new_slot_notification_stream.map(
            |(slot, global_challenge, acknowledgement_sender)| {
                (
                    ExecutorSlotInfo {
                        slot,
                        global_challenge,
                    },
                    acknowledgement_sender,
                )
            },
        )),
    );

    if is_authority {
        let _ = future::select(
            Box::pin(handle_block_import_notifications_fut),
            Box::pin(handle_slot_notifications_fut),
        )
        .await;
    } else {
        drop(handle_slot_notifications_fut);
        handle_block_import_notifications_fut.await
    }
}
