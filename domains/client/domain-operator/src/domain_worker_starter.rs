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
use crate::domain_worker::{on_new_slot, throttling_block_import_notifications};
use crate::parent_chain::DomainParentChain;
use crate::utils::OperatorSlotInfo;
use crate::{NewSlotNotification, OperatorStreams};
use domain_runtime_primitives::DomainCoreApi;
use futures::channel::mpsc;
use futures::{FutureExt, SinkExt, Stream, StreamExt, TryFutureExt};
use sc_client_api::{
    AuxStore, BlockBackend, BlockImportNotification, BlockchainEvents, Finalizer, ProofProvider,
};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sp_api::{BlockT, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_core::traits::{CodeExecutor, SpawnEssentialNamed};
use sp_core::H256;
use sp_domains::{BundleProducerElectionApi, DomainsApi};
use sp_messenger::MessengerApi;
use sp_runtime::traits::NumberFor;
use std::sync::Arc;
use subspace_runtime_primitives::Balance;
use tracing::{info, Instrument};

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
    ASS,
    E,
>(
    spawn_essential: Box<dyn SpawnEssentialNamed>,
    consensus_client: Arc<CClient>,
    consensus_offchain_tx_pool_factory: OffchainTransactionPoolFactory<CBlock>,
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
    bundle_processor: BundleProcessor<Block, CBlock, Client, CClient, Backend, E>,
    operator_streams: OperatorStreams<CBlock, IBNS, CIBNS, NSNS, ASS>,
) where
    Block: BlockT,
    Block::Hash: Into<H256>,
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
        + BlockBuilder<Block>
        + sp_api::ApiExt<Block>,
    CClient: HeaderBackend<CBlock>
        + HeaderMetadata<CBlock, Error = sp_blockchain::Error>
        + BlockBackend<CBlock>
        + ProofProvider<CBlock>
        + ProvideRuntimeApi<CBlock>
        + BlockchainEvents<CBlock>
        + 'static,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>
        + MessengerApi<CBlock, NumberFor<CBlock>>
        + BundleProducerElectionApi<CBlock, Balance>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    IBNS: Stream<Item = (NumberFor<CBlock>, mpsc::Sender<()>)> + Send + 'static,
    CIBNS: Stream<Item = BlockImportNotification<CBlock>> + Send + 'static,
    NSNS: Stream<Item = NewSlotNotification> + Send + 'static,
    ASS: Stream<Item = mpsc::Sender<()>> + Send + 'static,
    E: CodeExecutor,
{
    let span = tracing::Span::current();

    let OperatorStreams {
        consensus_block_import_throttling_buffer_size,
        block_importing_notification_stream,
        imported_block_notification_stream,
        new_slot_notification_stream,
        acknowledgement_sender_stream,
        _phantom,
    } = operator_streams;

    let mut throttled_block_import_notification_stream =
        throttling_block_import_notifications::<Block, _, _, _, _>(
            spawn_essential,
            consensus_client.clone(),
            Box::pin(block_importing_notification_stream),
            Box::pin(imported_block_notification_stream),
            consensus_block_import_throttling_buffer_size,
        );

    if !is_authority {
        info!("🧑‍ Running as Full node...");
        drop(new_slot_notification_stream);
        drop(acknowledgement_sender_stream);
        while let Some(maybe_block_info) = throttled_block_import_notification_stream.next().await {
            if let Some(block_info) = maybe_block_info {
                if let Err(error) = bundle_processor
                    .clone()
                    .process_bundles((block_info.hash, block_info.number, block_info.is_new_best))
                    .instrument(span.clone())
                    .await
                {
                    tracing::error!(?error, "Failed to process consensus block");
                    // Bring down the service as bundles processor is an essential task.
                    // TODO: more graceful shutdown.
                    break;
                }
            }
        }
    } else {
        info!("🧑‍🌾 Running as Operator...");
        let bundler_fn = {
            let span = span.clone();
            move |consensus_block_info: sp_blockchain::HashAndNumber<CBlock>, slot_info| {
                bundle_producer
                    .clone()
                    .produce_bundle(consensus_block_info.clone(), slot_info)
                    .instrument(span.clone())
                    .unwrap_or_else(move |error| {
                        tracing::error!(
                            ?consensus_block_info,
                            ?error,
                            "Error at producing bundle."
                        );
                        None
                    })
                    .boxed()
            }
        };
        let mut new_slot_notification_stream = Box::pin(new_slot_notification_stream);
        let mut acknowledgement_sender_stream = Box::pin(acknowledgement_sender_stream);
        loop {
            tokio::select! {
                // Ensure any new slot/block import must handle first before the `acknowledgement_sender_stream`
                // NOTE: this is only necessary for the test.
                biased;

                Some((slot, global_randomness)) = new_slot_notification_stream.next() => {
                    if let Err(error) = on_new_slot::<Block, CBlock, _, _>(
                        consensus_client.as_ref(),
                        consensus_offchain_tx_pool_factory.clone(),
                        &bundler_fn,
                        OperatorSlotInfo {
                            slot,
                            global_randomness,
                        },
                    )
                    .await
                    {
                        tracing::error!(
                            ?error,
                            "Error occurred on producing a bundle at slot {slot}"
                        );
                        break;
                    }
                }
                Some(maybe_block_info) = throttled_block_import_notification_stream.next() => {
                    if let Some(block_info) = maybe_block_info {
                        if let Err(error) = bundle_processor
                            .clone()
                            .process_bundles((
                                block_info.hash,
                                block_info.number,
                                block_info.is_new_best,
                            ))
                            .instrument(span.clone())
                            .await
                        {
                            tracing::error!(?error, "Failed to process consensus block");
                            // Bring down the service as bundles processor is an essential task.
                            // TODO: more graceful shutdown.
                            break;
                        }
                    }
                }
                // In production the `acknowledgement_sender_stream` is an empty stream, it only set to
                // real stream in test
                Some(mut acknowledgement_sender) = acknowledgement_sender_stream.next() => {
                    if let Err(err) = acknowledgement_sender.send(()).await {
                        tracing::error!(
                            ?err,
                            "Failed to send acknowledgement"
                        );
                    }
                }
            }
        }
    }
}
