//! Shared domain worker functions.

use crate::utils::{to_number_primitive, BlockInfo, OperatorSlotInfo};
use futures::channel::mpsc;
use futures::{SinkExt, Stream, StreamExt};
use sc_client_api::{BlockBackend, BlockImportNotification, BlockchainEvents};
use sp_api::{ApiError, BlockT, ProvideRuntimeApi};
use sp_blockchain::{HashAndNumber, HeaderBackend};
use sp_core::traits::SpawnEssentialNamed;
use sp_domains::{DomainsApi, OpaqueBundle};
use sp_runtime::traits::{Header as HeaderT, NumberFor, One, Saturating};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

pub(crate) async fn handle_slot_notifications<Block, CBlock, CClient, BundlerFn>(
    consensus_client: &CClient,
    bundler: BundlerFn,
    mut slots: impl Stream<Item = (OperatorSlotInfo, Option<mpsc::Sender<()>>)> + Unpin,
) where
    Block: BlockT,
    CBlock: BlockT,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock>,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>,
    BundlerFn: Fn(
            HashAndNumber<CBlock>,
            OperatorSlotInfo,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Option<
                            OpaqueBundle<
                                NumberFor<CBlock>,
                                CBlock::Hash,
                                NumberFor<Block>,
                                Block::Hash,
                            >,
                        >,
                    > + Send,
            >,
        > + Send
        + Sync,
{
    while let Some((operator_slot_info, slot_acknowledgement_sender)) = slots.next().await {
        let slot = operator_slot_info.slot;
        if let Err(error) =
            on_new_slot::<Block, CBlock, _, _>(consensus_client, &bundler, operator_slot_info).await
        {
            tracing::error!(
                ?error,
                "Error occurred on producing a bundle at slot {slot}"
            );
            break;
        }
        if let Some(mut sender) = slot_acknowledgement_sender {
            let _ = sender.send(()).await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_block_import_notifications<
    Block,
    CBlock,
    CClient,
    ProcessorFn,
    BlocksImporting,
    BlocksImported,
>(
    spawn_essential: Box<dyn SpawnEssentialNamed>,
    consensus_client: &CClient,
    best_domain_number: NumberFor<Block>,
    processor: ProcessorFn,
    mut leaves: Vec<(CBlock::Hash, NumberFor<CBlock>, bool)>,
    mut blocks_importing: BlocksImporting,
    mut blocks_imported: BlocksImported,
    consensus_block_import_throttling_buffer_size: u32,
) where
    Block: BlockT,
    CBlock: BlockT,
    CClient: HeaderBackend<CBlock>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + BlockchainEvents<CBlock>,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>,
    ProcessorFn: Fn(
            (CBlock::Hash, NumberFor<CBlock>, bool),
        ) -> Pin<Box<dyn Future<Output = Result<(), sp_blockchain::Error>> + Send>>
        + Send
        + Sync
        + 'static,
    BlocksImporting: Stream<Item = (NumberFor<CBlock>, mpsc::Sender<()>)> + Unpin,
    BlocksImported: Stream<Item = BlockImportNotification<CBlock>> + Unpin,
{
    let mut active_leaves = HashMap::with_capacity(leaves.len());

    let best_domain_number = to_number_primitive(best_domain_number);

    // Notify about active leaves on startup before starting the loop
    for (hash, number, is_new_best) in std::mem::take(&mut leaves) {
        let _ = active_leaves.insert(hash, number);
        // Skip the blocks that have been processed by the execution chain.
        if number > best_domain_number.into() {
            if let Err(error) = processor((hash, number, is_new_best)).await {
                tracing::error!(?error, "Failed to process consensus block on startup");
                // Bring down the service as bundles processor is an essential task.
                // TODO: more graceful shutdown.
                return;
            }
        }
    }

    // The consensus chain can be ahead of the domain by up to `block_import_throttling_buffer_size/2`
    // blocks, for there are two notifications per block sent to this buffer (one will be actually
    // consumed by the domain processor, the other from `sc-consensus-subspace` is used to discontinue
    // the consensus block import in case the consensus chain runs much faster than the domain.).
    let (mut block_info_sender, mut block_info_receiver) =
        mpsc::channel(consensus_block_import_throttling_buffer_size as usize);

    // Run the actual processor in a dedicated task, otherwise `tokio::select!` might hang forever
    // when the throttling buffer is full.
    spawn_essential.spawn_essential_blocking(
        "consensus-block-processor",
        None,
        Box::pin(async move {
            while let Some(maybe_block_info) = block_info_receiver.next().await {
                if let Some(block_info) = maybe_block_info {
                    if let Err(error) =
                        block_imported::<CBlock, _>(&processor, &mut active_leaves, block_info)
                            .await
                    {
                        tracing::error!(?error, "Failed to process consensus block");
                        // Bring down the service as bundles processor is an essential task.
                        // TODO: more graceful shutdown.
                        break;
                    }
                }
            }
        }),
    );

    loop {
        tokio::select! {
            // Ensure the `blocks_imported` branch will be checked before the `blocks_importing` branch.
            // Currently this is only necessary for the test to ensure when both `block_imported` notification
            // and `blocks_importing` notification are arrived, the `block_imported` notification will be processed
            // first, such that we can ensure when the `blocks_importing` acknowledgement is responded, the
            // imported block must being processed by the executor.
            // Please see https://github.com/subspace/subspace/pull/1363#discussion_r1162571291 for more details.
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
                    parent_hash: *header.parent_hash(),
                    number: *header.number(),
                    is_new_best: block_imported.is_new_best,
                };
                let _ = block_info_sender.feed(Some(block_info)).await;
            }
            maybe_block_importing = blocks_importing.next() => {
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
}

async fn on_new_slot<Block, CBlock, CClient, BundlerFn>(
    consensus_client: &CClient,
    bundler: &BundlerFn,
    operator_slot_info: OperatorSlotInfo,
) -> Result<(), ApiError>
where
    Block: BlockT,
    CBlock: BlockT,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock>,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>,
    BundlerFn: Fn(
            HashAndNumber<CBlock>,
            OperatorSlotInfo,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Option<
                            OpaqueBundle<
                                NumberFor<CBlock>,
                                CBlock::Hash,
                                NumberFor<Block>,
                                Block::Hash,
                            >,
                        >,
                    > + Send,
            >,
        > + Send
        + Sync,
{
    let best_hash = consensus_client.info().best_hash;
    let best_number = consensus_client.info().best_number;

    let consensus_block_info = HashAndNumber {
        number: best_number,
        hash: best_hash,
    };

    let slot = operator_slot_info.slot;
    let opaque_bundle = match bundler(consensus_block_info, operator_slot_info).await {
        Some(opaque_bundle) => opaque_bundle,
        None => {
            tracing::debug!("No bundle produced on slot {slot}");
            return Ok(());
        }
    };

    consensus_client
        .runtime_api()
        .submit_bundle_unsigned(best_hash, opaque_bundle)?;

    Ok(())
}

async fn block_imported<CBlock, ProcessorFn>(
    processor: &ProcessorFn,
    active_leaves: &mut HashMap<CBlock::Hash, NumberFor<CBlock>>,
    block_info: BlockInfo<CBlock>,
) -> Result<(), ApiError>
where
    CBlock: BlockT,
    ProcessorFn: Fn(
            (CBlock::Hash, NumberFor<CBlock>, bool),
        ) -> Pin<Box<dyn Future<Output = Result<(), sp_blockchain::Error>> + Send>>
        + Send
        + Sync,
{
    match active_leaves.entry(block_info.hash) {
        Entry::Vacant(entry) => entry.insert(block_info.number),
        Entry::Occupied(entry) => {
            debug_assert_eq!(*entry.get(), block_info.number);
            return Ok(());
        }
    };

    if let Some(number) = active_leaves.remove(&block_info.parent_hash) {
        debug_assert_eq!(block_info.number.saturating_sub(One::one()), number);
    }

    processor((block_info.hash, block_info.number, block_info.is_new_best)).await?;

    Ok(())
}
