use crate::utils::{to_number_primitive, BlockInfo, ExecutorSlotInfo};
use codec::{Decode, Encode};
use futures::channel::mpsc;
use futures::{SinkExt, Stream, StreamExt};
use sc_client_api::{BlockBackend, BlockImportNotification, BlockchainEvents};
use sp_api::{ApiError, BlockT, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::traits::SpawnEssentialNamed;
use sp_domains::{ExecutorApi, SignedOpaqueBundle};
use sp_runtime::traits::{Header as HeaderT, NumberFor, One, Saturating};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

pub(crate) async fn handle_slot_notifications<Block, PBlock, PClient, BundlerFn>(
    primary_chain_client: &PClient,
    bundler: BundlerFn,
    mut slots: impl Stream<Item = (ExecutorSlotInfo, Option<mpsc::Sender<()>>)> + Unpin,
) where
    Block: BlockT,
    PBlock: BlockT,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock>,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    BundlerFn: Fn(
            (PBlock::Hash, NumberFor<PBlock>),
            ExecutorSlotInfo,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Option<
                            SignedOpaqueBundle<NumberFor<PBlock>, PBlock::Hash, Block::Hash>,
                        >,
                    > + Send,
            >,
        > + Send
        + Sync,
{
    while let Some((executor_slot_info, slot_acknowledgement_sender)) = slots.next().await {
        if let Err(error) =
            on_new_slot::<Block, PBlock, _, _>(primary_chain_client, &bundler, executor_slot_info)
                .await
        {
            tracing::error!(?error, "Failed to submit bundle");
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
    PBlock,
    PClient,
    ProcessorFn,
    BlocksImporting,
    BlocksImported,
>(
    spawn_essential: Box<dyn SpawnEssentialNamed>,
    primary_chain_client: &PClient,
    best_domain_number: NumberFor<Block>,
    processor: ProcessorFn,
    mut leaves: Vec<(PBlock::Hash, NumberFor<PBlock>)>,
    mut blocks_importing: BlocksImporting,
    mut blocks_imported: BlocksImported,
    primary_block_import_throttling_buffer_size: u32,
) where
    Block: BlockT,
    PBlock: BlockT,
    PClient: HeaderBackend<PBlock>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + BlockchainEvents<PBlock>,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    ProcessorFn: Fn(
            (PBlock::Hash, NumberFor<PBlock>),
        ) -> Pin<Box<dyn Future<Output = Result<(), sp_blockchain::Error>> + Send>>
        + Send
        + Sync
        + 'static,
    BlocksImporting: Stream<Item = (NumberFor<PBlock>, mpsc::Sender<()>)> + Unpin,
    BlocksImported: Stream<Item = BlockImportNotification<PBlock>> + Unpin,
{
    let mut active_leaves = HashMap::with_capacity(leaves.len());

    let best_domain_number = to_number_primitive(best_domain_number);

    // Notify about active leaves on startup before starting the loop
    for (hash, number) in std::mem::take(&mut leaves) {
        let _ = active_leaves.insert(hash, number);
        // Skip the blocks that have been processed by the execution chain.
        if number > best_domain_number.into() {
            if let Err(error) = processor((hash, number)).await {
                tracing::error!(?error, "Failed to process primary block on startup");
                // Bring down the service as bundles processor is an essential task.
                // TODO: more graceful shutdown.
                return;
            }
        }
    }

    // The primary chain can be ahead of the domain by up to `block_import_throttling_buffer_size/2`
    // blocks, for there are two notifications per block sent to this buffer (one will be actually
    // consumed by the domain processor, the other from `sc-consensus-subspace` is used to discontinue
    // the primary block import in case the primary chain runs much faster than the domain.).
    let (mut block_info_sender, mut block_info_receiver) =
        mpsc::channel(primary_block_import_throttling_buffer_size as usize);

    // Run the actual processor in a dedicated task, otherwise `tokio::select!` might hang forever
    // when the throttling buffer is full.
    spawn_essential.spawn_essential_blocking(
        "primary-block-processor",
        None,
        Box::pin(async move {
            while let Some(maybe_block_info) = block_info_receiver.next().await {
                if let Some(block_info) = maybe_block_info {
                    if let Err(error) =
                        block_imported::<PBlock, _>(&processor, &mut active_leaves, block_info)
                            .await
                    {
                        tracing::error!(?error, "Failed to process primary block");
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
            maybe_block_imported = blocks_imported.next() => {
                let block_imported = match maybe_block_imported {
                    Some(block_imported) => block_imported,
                    None => {
                        // Can be None on graceful shutdown.
                        break;
                    }
                };
                let header = match primary_chain_client.header(block_imported.hash) {
                    Ok(Some(header)) => header,
                    res => {
                        tracing::error!(
                            result = ?res,
                            header = ?block_imported.header,
                            "Imported primary block header not found",
                        );
                        return;
                    }
                };
                let block_info = BlockInfo {
                    hash: header.hash(),
                    parent_hash: *header.parent_hash(),
                    number: *header.number(),
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
                // Pause the primary block import when the sink is full.
                let _ = block_info_sender.feed(None).await;
                let _ = acknowledgement_sender.send(()).await;
            }
        }
    }
}

async fn on_new_slot<Block, PBlock, PClient, BundlerFn>(
    primary_chain_client: &PClient,
    bundler: &BundlerFn,
    executor_slot_info: ExecutorSlotInfo,
) -> Result<(), ApiError>
where
    Block: BlockT,
    PBlock: BlockT,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock>,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    BundlerFn: Fn(
            (PBlock::Hash, NumberFor<PBlock>),
            ExecutorSlotInfo,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Option<
                            SignedOpaqueBundle<NumberFor<PBlock>, PBlock::Hash, Block::Hash>,
                        >,
                    > + Send,
            >,
        > + Send
        + Sync,
{
    let best_hash = primary_chain_client.info().best_hash;
    let best_number = primary_chain_client.info().best_number;

    let best_hash = PBlock::Hash::decode(&mut best_hash.encode().as_slice())
        .expect("Hash type must be correct");
    let best_number = crate::utils::translate_number_type(best_number);

    let opaque_bundle = match bundler((best_hash, best_number), executor_slot_info).await {
        Some(opaque_bundle) => opaque_bundle,
        None => {
            tracing::debug!("executor returned no bundle on bundling");
            return Ok(());
        }
    };

    primary_chain_client
        .runtime_api()
        .submit_bundle_unsigned(best_hash, opaque_bundle)?;

    Ok(())
}

async fn block_imported<PBlock, ProcessorFn>(
    processor: &ProcessorFn,
    active_leaves: &mut HashMap<PBlock::Hash, NumberFor<PBlock>>,
    block_info: BlockInfo<PBlock>,
) -> Result<(), ApiError>
where
    PBlock: BlockT,
    ProcessorFn: Fn(
            (PBlock::Hash, NumberFor<PBlock>),
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

    processor((block_info.hash, block_info.number)).await?;

    Ok(())
}
