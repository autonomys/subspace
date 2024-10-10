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
use crate::domain_bundle_producer::{DomainBundleProducer, DomainProposal};
use crate::snap_sync::{snap_sync, SyncParams};
use crate::utils::{BlockInfo, OperatorSlotInfo};
use crate::{NewSlotNotification, OperatorStreams};
use futures::channel::mpsc;
use futures::{SinkExt, Stream, StreamExt};
use sc_client_api::{
    AuxStore, BlockBackend, BlockImportNotification, BlockchainEvents, Finalizer, ProofProvider,
};
use sc_consensus::BlockImport;
use sc_network::NetworkRequest;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_core::traits::{CodeExecutor, SpawnEssentialNamed};
use sp_core::H256;
use sp_domains::core_api::DomainCoreApi;
use sp_domains::{BundleProducerElectionApi, DomainsApi, OpaqueBundle, OperatorId};
use sp_domains_fraud_proof::FraudProofApi;
use sp_messenger::MessengerApi;
use sp_mmr_primitives::MmrApi;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::collections::VecDeque;
use std::future::pending;
use std::pin::pin;
use std::sync::Arc;
use subspace_core_primitives::BlockNumber;
use subspace_runtime_primitives::Balance;
use subspace_service::domains::snap_sync_orchestrator::SnapSyncOrchestrator;
use tracing::{debug, error, info, trace, Instrument, Span};

pub type OpaqueBundleFor<Block, CBlock> =
    OpaqueBundle<NumberFor<CBlock>, <CBlock as BlockT>::Hash, <Block as BlockT>::Header, Balance>;

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
    CNR,
    AS,
>(
    spawn_essential: Box<dyn SpawnEssentialNamed>,
    consensus_client: Arc<CClient>,
    consensus_offchain_tx_pool_factory: OffchainTransactionPoolFactory<CBlock>,
    maybe_operator_id: Option<OperatorId>,
    mut bundle_producer: DomainBundleProducer<Block, CBlock, Client, CClient, TransactionPool>,
    bundle_processor: BundleProcessor<Block, CBlock, Client, CClient, Backend, E>,
    operator_streams: OperatorStreams<CBlock, IBNS, CIBNS, NSNS, ASS>,
    sync_params: Option<SyncParams<Client, CClient, Block, CBlock, CNR, AS>>,
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
        + BlockImport<Block>
        + BlockchainEvents<Block>
        + 'static,
    for<'a> &'a Client: BlockImport<Block>,
    Client::Api: DomainCoreApi<Block>
        + MessengerApi<Block, NumberFor<CBlock>, CBlock::Hash>
        + BlockBuilder<Block>
        + sp_api::ApiExt<Block>
        + TaggedTransactionQueue<Block>,
    CClient: HeaderBackend<CBlock>
        + HeaderMetadata<CBlock, Error = sp_blockchain::Error>
        + BlockBackend<CBlock>
        + ProofProvider<CBlock>
        + ProvideRuntimeApi<CBlock>
        + BlockchainEvents<CBlock>
        + 'static,
    CClient::Api: DomainsApi<CBlock, Block::Header>
        + MessengerApi<CBlock, NumberFor<CBlock>, CBlock::Hash>
        + BundleProducerElectionApi<CBlock, Balance>
        + FraudProofApi<CBlock, Block::Header>
        + MmrApi<CBlock, H256, NumberFor<CBlock>>,
    TransactionPool:
        sc_transaction_pool_api::TransactionPool<Block = Block, Hash = Block::Hash> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    IBNS: Stream<Item = (NumberFor<CBlock>, mpsc::Sender<()>)> + Send + 'static,
    CIBNS: Stream<Item = BlockImportNotification<CBlock>> + Send + 'static,
    NSNS: Stream<Item = NewSlotNotification> + Send + 'static,
    ASS: Stream<Item = mpsc::Sender<()>> + Send + 'static,
    E: CodeExecutor,
    CNR: NetworkRequest + Send + Sync + 'static,
    AS: AuxStore + Send + Sync + 'static,
{
    let span = Span::current();
    let snap_sync_orchestrator = sync_params.as_ref().map(|params| {
        params
            .consensus_chain_sync_params
            .snap_sync_orchestrator
            .clone()
    });

    if let Some(sync_params) = sync_params {
        let snap_sync_orchestrator = sync_params
            .consensus_chain_sync_params
            .snap_sync_orchestrator
            .clone();
        let domain_sync_task = {
            async move {
                let info = sync_params.domain_client.info();
                // Only attempt snap sync with genesis state
                // TODO: Support snap sync from any state once
                //  https://github.com/paritytech/polkadot-sdk/issues/5366 is resolved
                if info.best_hash == info.genesis_hash {
                    info!("Starting domain snap sync...");

                    let result = snap_sync(sync_params).await;

                    match result {
                        Ok(_) => {
                            info!("Domain snap sync completed.");
                        }
                        Err(err) => {
                            snap_sync_orchestrator.unblock_all();

                            error!(%err, "Domain snap sync failed.");

                            // essential task failed
                            return;
                        }
                    };
                } else {
                    debug!("Snap sync can only work with genesis state, skipping");

                    snap_sync_orchestrator.unblock_all();
                }

                // Don't exit essential task.
                pending().await
            }
        };

        spawn_essential.spawn_essential("domain-sync", None, Box::pin(domain_sync_task));
    }

    let mut block_queue = VecDeque::<BlockInfo<CBlock>>::new();
    let mut target_block_number = None;

    if let Some(ref snap_sync_orchestrator) = snap_sync_orchestrator {
        snap_sync_orchestrator.consensus_snap_sync_unblocked().await;
        target_block_number = snap_sync_orchestrator.target_consensus_snap_sync_block_number();
    }

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

    if let Some(operator_id) = maybe_operator_id {
        info!("👷 Running as Operator[{operator_id}]...");
        let mut new_slot_notification_stream = pin!(new_slot_notification_stream);
        let mut acknowledgement_sender_stream = pin!(acknowledgement_sender_stream);
        loop {
            tokio::select! {
                // Ensure any new slot/block import must handle first before the `acknowledgement_sender_stream`
                // NOTE: this is only necessary for the test.
                biased;

                Some((slot, proof_of_time)) = new_slot_notification_stream.next() => {
                    if let Some(ref snap_sync_orchestrator) = snap_sync_orchestrator {
                        if !snap_sync_orchestrator.domain_snap_sync_finished(){
                            debug!(
                                "Domain snap sync: skipping bundle production on slot {slot}"
                            );

                            continue
                        }
                    }

                    let res = bundle_producer
                        .produce_bundle(
                            operator_id,
                            OperatorSlotInfo {
                                slot,
                                proof_of_time,
                            },
                        )
                        .instrument(span.clone())
                        .await;
                    match res {
                        Err(err) => {
                            tracing::error!(?slot, ?err, "Error at producing bundle.");
                        }
                        Ok(Some(domain_proposal)) => {
                            let best_hash = consensus_client.info().best_hash;
                            let mut runtime_api = consensus_client.runtime_api();
                            runtime_api.register_extension(consensus_offchain_tx_pool_factory.offchain_transaction_pool(best_hash));

                            match domain_proposal {
                                DomainProposal::Bundle(opaque_bundle) => {
                                    if let Err(err) = runtime_api.submit_bundle_unsigned(best_hash, opaque_bundle) {
                                        tracing::error!(?slot, ?err, "Error at submitting bundle.");
                                    }
                                },
                                DomainProposal::Receipt(singleton_receipt) => {
                                    if let Err(err) = runtime_api.submit_receipt_unsigned(best_hash, singleton_receipt) {
                                        tracing::error!(?slot, ?err, "Error at submitting receipt.");
                                    }
                                },
                            }
                        }
                        Ok(None) => {}
                    }
                }
                Some(maybe_block_info) = throttled_block_import_notification_stream.next() => {
                    if let Some(block_info) = maybe_block_info {
                        let cache_result = maybe_cache_block_info(
                            block_info.clone(),
                            target_block_number,
                            snap_sync_orchestrator.clone(),
                            &mut block_queue,
                            &bundle_processor,
                            span.clone(),
                        )
                        .await;

                        match cache_result {
                            CacheBlockInfoResult::Cached => continue,
                            CacheBlockInfoResult::Error => break,
                            CacheBlockInfoResult::NotCached => {}
                        };

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
    } else {
        info!("🧑‍ Running as Full node...");
        drop(new_slot_notification_stream);
        drop(acknowledgement_sender_stream);

        'import_loop: while let Some(maybe_block_info) =
            throttled_block_import_notification_stream.next().await
        {
            if let Some(block_info) = maybe_block_info {
                println!("Inside operator processing: {block_info:?}");

                let cache_result = maybe_cache_block_info(
                    block_info.clone(),
                    target_block_number,
                    snap_sync_orchestrator.clone(),
                    &mut block_queue,
                    &bundle_processor,
                    span.clone(),
                )
                .await;

                match cache_result {
                    CacheBlockInfoResult::Cached => continue 'import_loop,
                    CacheBlockInfoResult::Error => break 'import_loop,
                    CacheBlockInfoResult::NotCached => {}
                };

                if let Err(error) = bundle_processor
                    .clone()
                    .process_bundles((block_info.hash, block_info.number, block_info.is_new_best))
                    .instrument(span.clone())
                    .await
                {
                    tracing::error!(?error, "Failed to process consensus block");
                    // Bring down the service as bundles processor is an essential task.
                    // TODO: more graceful shutdown.
                    break 'import_loop;
                }
            }
        }
    }
}

enum CacheBlockInfoResult {
    Error,
    Cached,
    NotCached,
}

async fn maybe_cache_block_info<Block, CBlock, Client, CClient, Backend, E>(
    block_info: BlockInfo<CBlock>,
    target_block_number: Option<BlockNumber>,
    snap_sync_orchestrator: Option<Arc<SnapSyncOrchestrator>>,
    block_queue: &mut VecDeque<BlockInfo<CBlock>>,
    bundle_processor: &BundleProcessor<Block, CBlock, Client, CClient, Backend, E>,
    span: Span,
) -> CacheBlockInfoResult
where
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
        + BlockImport<Block>
        + 'static,
    for<'a> &'a Client: BlockImport<Block>,
    Client::Api: DomainCoreApi<Block>
        + MessengerApi<Block, NumberFor<CBlock>, CBlock::Hash>
        + BlockBuilder<Block>
        + sp_api::ApiExt<Block>
        + TaggedTransactionQueue<Block>,
    CClient: HeaderBackend<CBlock>
        + HeaderMetadata<CBlock, Error = sp_blockchain::Error>
        + BlockBackend<CBlock>
        + ProofProvider<CBlock>
        + ProvideRuntimeApi<CBlock>
        + BlockchainEvents<CBlock>
        + 'static,
    CClient::Api: DomainsApi<CBlock, Block::Header>
        + MessengerApi<CBlock, NumberFor<CBlock>, CBlock::Hash>
        + BundleProducerElectionApi<CBlock, Balance>
        + FraudProofApi<CBlock, Block::Header>
        + MmrApi<CBlock, H256, NumberFor<CBlock>>,
    Backend: sc_client_api::Backend<Block> + 'static,
    E: CodeExecutor,
{
    trace!(?target_block_number, ?block_info, "Maybe cache block info.");

    let target_block_number: NumberFor<CBlock> = {
        if let Some(target_block_number) = target_block_number {
            target_block_number.into()
        } else {
            return CacheBlockInfoResult::NotCached;
        }
    };

    if let Some(ref snap_sync_orchestrator) = snap_sync_orchestrator {
        if snap_sync_orchestrator.domain_snap_sync_finished() && !block_queue.is_empty() {
            while !block_queue.is_empty() {
                if let Some(cached_block_info) = block_queue.pop_front() {
                    debug!(?cached_block_info, "Processing cached block info.");

                    if let Err(error) = bundle_processor
                        .clone()
                        .process_bundles((
                            cached_block_info.hash,
                            cached_block_info.number,
                            cached_block_info.is_new_best,
                        ))
                        .instrument(span.clone())
                        .await
                    {
                        error!(?error, "Failed to process consensus block");
                        return CacheBlockInfoResult::Error;
                    }
                }
            }
        } else if !snap_sync_orchestrator.domain_snap_sync_finished() {
            if target_block_number >= block_info.number {
                debug!(%target_block_number, "Skipped consensus block: {:?}", block_info);
            } else {
                debug!(%target_block_number, "Cached consensus block: {:?}", block_info);
                block_queue.push_back(block_info);
            }

            return CacheBlockInfoResult::Cached;
        }
    }

    CacheBlockInfoResult::NotCached
}

/// Throttle the consensus block import notification based on the `consensus_block_import_throttling_buffer_size`
/// to pause the consensus block import in case the consensus chain runs much faster than the domain.
///
/// Return the throttled block import notification stream
#[allow(clippy::too_many_arguments)]
fn throttling_block_import_notifications<Block, CBlock, CClient, BlocksImporting, BlocksImported>(
    spawn_essential: Box<dyn SpawnEssentialNamed>,
    consensus_client: Arc<CClient>,
    mut blocks_importing: BlocksImporting,
    mut blocks_imported: BlocksImported,
    consensus_block_import_throttling_buffer_size: u32,
) -> mpsc::Receiver<Option<BlockInfo<CBlock>>>
where
    Block: BlockT,
    CBlock: BlockT,
    CClient: HeaderBackend<CBlock>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + BlockchainEvents<CBlock>
        + 'static,
    CClient::Api: DomainsApi<CBlock, Block::Header>,
    BlocksImporting: Stream<Item = (NumberFor<CBlock>, mpsc::Sender<()>)> + Unpin + Send + 'static,
    BlocksImported: Stream<Item = BlockImportNotification<CBlock>> + Unpin + Send + 'static,
{
    // The consensus chain can be ahead of the domain by up to `block_import_throttling_buffer_size/2`
    // blocks, for there are two notifications per block sent to this buffer (one will be actually
    // consumed by the domain processor, the other from `sc-consensus-subspace` is used to discontinue
    // the consensus block import in case the consensus chain runs much faster than the domain.).
    let (mut block_info_sender, block_info_receiver) = mpsc::channel::<Option<BlockInfo<CBlock>>>(
        consensus_block_import_throttling_buffer_size as usize,
    );

    spawn_essential.spawn_essential(
        "consensus-block-import-throttler",
        None,
        Box::pin(async move {
            loop {
                tokio::select! {
                    // Ensure the `blocks_imported` branch will be checked before the `blocks_importing` branch.
                    // Currently this is only necessary for the test to ensure when both `block_imported` notification
                    // and `blocks_importing` notification are arrived, the `block_imported` notification will be processed
                    // first, such that we can ensure when the `blocks_importing` acknowledgement is responded, the
                    // imported block must being processed by the executor.
                    // Please see https://github.com/autonomys/subspace/pull/1363#discussion_r1162571291 for more details.
                    biased;

                    maybe_block_imported = blocks_imported.next() => {
                        let block_imported = match maybe_block_imported {
                            Some(block_imported) => block_imported,
                            None => {
                                // Can be None on graceful shutdown.
                                break;
                            }
                        };
                        let header = match consensus_client.header(block_imported.hash) {
                            Ok(Some(header)) => header,
                            res => {
                                tracing::error!(
                                    result = ?res,
                                    header = ?block_imported.header,
                                    "Imported consensus block header not found",
                                );
                                return;
                            }
                        };
                        let block_info = BlockInfo {
                            hash: header.hash(),
                            number: *header.number(),
                            is_new_best: block_imported.is_new_best,
                        };
                        let _ = block_info_sender.feed(Some(block_info)).await;
                    }
                    maybe_block_importing = blocks_importing.next() => {
                        // TODO: remove the `block_number` from the notification since it is not used
                        let (_block_number, mut acknowledgement_sender) =
                            match maybe_block_importing {
                                Some(block_importing) => block_importing,
                                None => {
                                    // Can be None on graceful shutdown.
                                    break;
                                }
                            };
                        // Pause the consensus block import when the sink is full.
                        let _ = block_info_sender.feed(None).await;
                        let _ = acknowledgement_sender.send(()).await;
                    }
                }
            }
        }),
    );

    block_info_receiver
}
