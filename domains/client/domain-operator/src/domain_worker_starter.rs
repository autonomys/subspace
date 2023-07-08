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
use crate::utils::{BlockInfo, OperatorSlotInfo};
use crate::{OperatorStreams, TransactionFor};
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
use sp_domains::DomainsApi;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{HashFor, NumberFor};
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;
use tracing::Instrument;

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub(super) async fn start_worker<
    Block,
    CBlock,
    Client,
    CClient,
    TransactionPool,
    Backend,
    IBNS,
    CIBNS,
    NSNS,
    E,
    BI,
>(
    spawn_essential: Box<dyn SpawnEssentialNamed>,
    consensus_client: Arc<CClient>,
    client: Arc<Client>,
    is_authority: bool,
    bundle_producer: DomainBundleProducer<
        Block,
        CBlock,
        CBlock,
        Client,
        CClient,
        DomainParentChain<Block, CBlock, CClient>,
        TransactionPool,
    >,
    bundle_processor: BundleProcessor<Block, CBlock, Client, CClient, Backend, E, BI>,
    operator_streams: OperatorStreams<CBlock, IBNS, CIBNS, NSNS>,
    active_leaves: Vec<BlockInfo<CBlock>>,
) where
    Block: BlockT,
    CBlock: BlockT,
    NumberFor<CBlock>: From<NumberFor<Block>> + Into<NumberFor<Block>>,
    CBlock::Hash: From<Block::Hash>,
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
    CClient: HeaderBackend<CBlock>
        + HeaderMetadata<CBlock, Error = sp_blockchain::Error>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + BlockchainEvents<CBlock>
        + 'static,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    IBNS: Stream<Item = (NumberFor<CBlock>, mpsc::Sender<()>)> + Send + 'static,
    CIBNS: Stream<Item = BlockImportNotification<CBlock>> + Send + 'static,
    NSNS: Stream<Item = (Slot, Blake2b256Hash, Option<mpsc::Sender<()>>)> + Send + 'static,
    E: CodeExecutor,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    for<'b> &'b BI: BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    BI: Send + Sync + 'static,
{
    let span = tracing::Span::current();

    let OperatorStreams {
        consensus_block_import_throttling_buffer_size,
        block_importing_notification_stream,
        imported_block_notification_stream,
        new_slot_notification_stream,
        _phantom,
    } = operator_streams;

    let handle_block_import_notifications_fut =
        handle_block_import_notifications::<Block, _, _, _, _, _>(
            spawn_essential,
            consensus_client.as_ref(),
            client.info().best_number,
            {
                let span = span.clone();

                move |consensus_block_info| {
                    bundle_processor
                        .clone()
                        .process_bundles(consensus_block_info)
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
                         is_new_best,
                     }| (hash, number, is_new_best),
                )
                .collect(),
            Box::pin(block_importing_notification_stream),
            Box::pin(imported_block_notification_stream),
            consensus_block_import_throttling_buffer_size,
        );
    let handle_slot_notifications_fut = handle_slot_notifications::<Block, CBlock, _, _>(
        consensus_client.as_ref(),
        move |consensus_block_info, slot_info| {
            bundle_producer
                .clone()
                .produce_bundle(consensus_block_info.clone(), slot_info)
                .instrument(span.clone())
                .unwrap_or_else(move |error| {
                    tracing::error!(?consensus_block_info, ?error, "Error at producing bundle.");
                    None
                })
                .boxed()
        },
        Box::pin(new_slot_notification_stream.map(
            |(slot, global_challenge, acknowledgement_sender)| {
                (
                    OperatorSlotInfo {
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
