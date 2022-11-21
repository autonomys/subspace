use crate::utils::{BlockInfo, DomainBundles, ExecutorSlotInfo};
use crate::LOG_TARGET;
use codec::{Decode, Encode};
use futures::channel::mpsc;
use futures::{SinkExt, Stream, StreamExt};
use sc_client_api::BlockBackend;
use sc_consensus::ForkChoiceStrategy;
use sp_api::{ApiError, BlockT, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_domains::{DomainId, ExecutorApi, SignedOpaqueBundle};
use sp_runtime::generic::{BlockId, DigestItem};
use sp_runtime::traits::{Header as HeaderT, NumberFor, One, Saturating};
use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use subspace_core_primitives::{BlockNumber, Randomness};

pub(crate) async fn handle_slot_notifications<Block, PBlock, PClient, BundlerFn>(
    primary_chain_client: &PClient,
    bundler: BundlerFn,
    mut slots: impl Stream<Item = ExecutorSlotInfo> + Unpin,
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
    while let Some(executor_slot_info) = slots.next().await {
        if let Err(error) =
            on_new_slot::<Block, PBlock, _, _>(primary_chain_client, &bundler, executor_slot_info)
                .await
        {
            tracing::error!(
                target: LOG_TARGET,
                error = ?error,
                "Failed to submit transaction bundle"
            );
            break;
        }
    }
}

pub(crate) async fn handle_block_import_notifications<
    Block,
    PBlock,
    PClient,
    ProcessorFn,
    BlockImports,
>(
    domain_id: DomainId,
    primary_chain_client: &PClient,
    best_secondary_number: NumberFor<Block>,
    processor: ProcessorFn,
    mut leaves: Vec<(PBlock::Hash, NumberFor<PBlock>, ForkChoiceStrategy)>,
    mut block_imports: BlockImports,
    block_import_throttling_buffer_size: u32,
) where
    Block: BlockT,
    PBlock: BlockT,
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock>,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    ProcessorFn: Fn(
            (PBlock::Hash, NumberFor<PBlock>, ForkChoiceStrategy),
            DomainBundles<Block, PBlock>,
            Randomness,
            Option<Cow<'static, [u8]>>,
        ) -> Pin<Box<dyn Future<Output = Result<(), sp_blockchain::Error>> + Send>>
        + Send
        + Sync,
    BlockImports: Stream<Item = (NumberFor<PBlock>, ForkChoiceStrategy, mpsc::Sender<()>)> + Unpin,
{
    let mut active_leaves = HashMap::with_capacity(leaves.len());

    let best_secondary_number: BlockNumber = best_secondary_number
        .try_into()
        .unwrap_or_else(|_| panic!("Secondary number must fit into u32; qed"));

    // Notify about active leaves on startup before starting the loop
    for (hash, number, fork_choice) in std::mem::take(&mut leaves) {
        let _ = active_leaves.insert(hash, number);
        // Skip the blocks that have been processed by the execution chain.
        if number > best_secondary_number.into() {
            if let Err(error) = process_primary_block::<Block, PBlock, _, _>(
                domain_id,
                primary_chain_client,
                &processor,
                (hash, number, fork_choice),
            )
            .await
            {
                tracing::error!(
                    target: LOG_TARGET,
                    ?error,
                    "Failed to process primary block on startup"
                );
                // Bring down the service as bundles processor is an essential task.
                // TODO: more graceful shutdown.
                return;
            }
        }
    }

    // Pause the primary block import once this channel is full.
    let (mut block_info_sender, mut block_info_receiver) =
        mpsc::channel(block_import_throttling_buffer_size as usize);

    loop {
        tokio::select! {
            maybe_block_import = block_imports.next() => {
                let (block_number, fork_choice, mut block_import_acknowledgement_sender) = match maybe_block_import {
                    Some(block_import) => block_import,
                    None => {
                        // Can be None on graceful shutdown.
                        break;
                    }
                };
                let header = primary_chain_client
                    .header(BlockId::Number(block_number))
                    .expect("Header of imported block must exist; qed")
                    .expect("Header of imported block must exist; qed");
                let block_info = BlockInfo {
                    hash: header.hash(),
                    parent_hash: *header.parent_hash(),
                    number: *header.number(),
                    fork_choice
                };
                let _ = block_info_sender.feed(block_info).await;
                let _ = block_import_acknowledgement_sender.send(()).await;
            }
            Some(block_info) = block_info_receiver.next() => {
                if let Err(error) = block_imported::<Block, PBlock, _, _>(
                    domain_id,
                    primary_chain_client,
                    &processor,
                    &mut active_leaves,
                    block_info,
                ).await {
                    tracing::error!(
                        target: LOG_TARGET,
                        ?error,
                        "Failed to process primary block"
                    );
                    // Bring down the service as bundles processor is an essential task.
                    // TODO: more graceful shutdown.
                    break;
                }
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
            tracing::debug!(
                target: LOG_TARGET,
                "executor returned no bundle on bundling",
            );
            return Ok(());
        }
    };

    primary_chain_client
        .runtime_api()
        .submit_bundle_unsigned(&BlockId::Hash(best_hash), opaque_bundle)?;

    Ok(())
}

async fn block_imported<Block, PBlock, PClient, ProcessorFn>(
    domain_id: DomainId,
    primary_chain_client: &PClient,
    processor: &ProcessorFn,
    active_leaves: &mut HashMap<PBlock::Hash, NumberFor<PBlock>>,
    block_info: BlockInfo<PBlock>,
) -> Result<(), ApiError>
where
    Block: BlockT,
    PBlock: BlockT,
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock> + Send + Sync,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    ProcessorFn: Fn(
            (PBlock::Hash, NumberFor<PBlock>, ForkChoiceStrategy),
            DomainBundles<Block, PBlock>,
            Randomness,
            Option<Cow<'static, [u8]>>,
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

    process_primary_block::<Block, PBlock, _, _>(
        domain_id,
        primary_chain_client,
        processor,
        (block_info.hash, block_info.number, block_info.fork_choice),
    )
    .await?;

    Ok(())
}

/// Apply the transaction bundles for given primary block as follows:
///
/// 1. Extract the transaction bundles from the block.
/// 2. Pass the bundles to secondary node and do the computation there.
async fn process_primary_block<Block, PBlock, PClient, ProcessorFn>(
    domain_id: DomainId,
    primary_chain_client: &PClient,
    processor: &ProcessorFn,
    (block_hash, block_number, fork_choice): (PBlock::Hash, NumberFor<PBlock>, ForkChoiceStrategy),
) -> Result<(), ApiError>
where
    Block: BlockT,
    PBlock: BlockT,
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock> + Send + Sync,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    ProcessorFn: Fn(
            (PBlock::Hash, NumberFor<PBlock>, ForkChoiceStrategy),
            DomainBundles<Block, PBlock>,
            Randomness,
            Option<Cow<'static, [u8]>>,
        ) -> Pin<Box<dyn Future<Output = Result<(), sp_blockchain::Error>> + Send>>
        + Send
        + Sync,
{
    let block_id = BlockId::Hash(block_hash);
    let extrinsics = match primary_chain_client.block_body(block_hash) {
        Err(err) => {
            tracing::error!(
                target: LOG_TARGET,
                ?err,
                "Failed to get block body from primary chain"
            );
            return Ok(());
        }
        Ok(None) => {
            tracing::error!(target: LOG_TARGET, ?block_hash, "BlockBody unavailable");
            return Ok(());
        }
        Ok(Some(body)) => body,
    };

    let header = match primary_chain_client.header(block_id) {
        Err(err) => {
            tracing::error!(
                target: LOG_TARGET,
                ?err,
                "Failed to get block from primary chain"
            );
            return Ok(());
        }
        Ok(None) => {
            tracing::error!(target: LOG_TARGET, ?block_hash, "BlockHeader unavailable");
            return Ok(());
        }
        Ok(Some(header)) => header,
    };

    let maybe_new_runtime = if header
        .digest()
        .logs
        .iter()
        .any(|item| *item == DigestItem::RuntimeEnvironmentUpdated)
    {
        Some(
            primary_chain_client
                .runtime_api()
                .execution_wasm_bundle(&block_id)?,
        )
    } else {
        None
    };

    let shuffling_seed = primary_chain_client
        .runtime_api()
        .extrinsics_shuffling_seed(&block_id, header)?;

    let domain_bundles = if domain_id.is_system() {
        todo!("Migrate system_domain_worker to be based on domain_worker")
    } else if domain_id.is_core() {
        let core_bundles = primary_chain_client
            .runtime_api()
            .extract_core_bundles(&block_id, extrinsics, domain_id)?;
        DomainBundles::Core(core_bundles)
    } else {
        unreachable!("Open domains are unsupported")
    };

    processor(
        (block_hash, block_number, fork_choice),
        domain_bundles,
        shuffling_seed,
        maybe_new_runtime,
    )
    .await?;

    Ok(())
}
