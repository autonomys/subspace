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

use crate::{BundleProcessor, BundleProducer, TransactionFor};
use cirrus_primitives::{AccountId, SecondaryApi};
use codec::{Decode, Encode};
use futures::channel::mpsc;
use futures::{future, FutureExt, SinkExt, Stream, StreamExt, TryFutureExt};
use sc_client_api::{AuxStore, BlockBackend};
use sc_consensus::BlockImport;
use sp_api::{ApiError, BlockT, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderBackend;
use sp_consensus_slots::Slot;
use sp_core::traits::CodeExecutor;
use sp_executor::{ExecutorApi, OpaqueBundle, SignedOpaqueBundle};
use sp_runtime::generic::{BlockId, DigestItem};
use sp_runtime::traits::{HashFor, Header as HeaderT, NumberFor, One, Saturating};
use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use subspace_core_primitives::{BlockNumber, Randomness, Sha256Hash};
use subspace_runtime_primitives::Hash as PHash;
use tracing::Instrument;

const LOG_TARGET: &str = "executor-worker";

/// Data required to produce bundles on executor node.
#[derive(PartialEq, Clone, Debug)]
pub(super) struct ExecutorSlotInfo {
    /// Slot
    pub(super) slot: Slot,
    /// Global slot challenge
    pub(super) global_challenge: Sha256Hash,
}

/// An event telling the `Overseer` on the particular block
/// that has been imported or finalized.
///
/// This structure exists solely for the purposes of decoupling
/// `Overseer` code from the client code and the necessity to call
/// `HeaderBackend::block_number_from_id()`.
#[derive(Debug, Clone)]
pub struct BlockInfo<Block>
where
    Block: BlockT,
{
    /// hash of the block.
    pub hash: Block::Hash,
    /// hash of the parent block.
    pub parent_hash: Block::Hash,
    /// block's number.
    pub number: NumberFor<Block>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn start_worker<
    Block,
    PBlock,
    Client,
    PClient,
    TransactionPool,
    Backend,
    IBNS,
    NSNS,
    E,
>(
    primary_chain_client: Arc<PClient>,
    client: Arc<Client>,
    bundle_producer: BundleProducer<Block, PBlock, Client, PClient, TransactionPool>,
    bundle_processor: BundleProcessor<Block, PBlock, Client, PClient, Backend, E>,
    imported_block_notification_stream: IBNS,
    new_slot_notification_stream: NSNS,
    active_leaves: Vec<BlockInfo<PBlock>>,
    block_import_throttling_buffer_size: u32,
) where
    Block: BlockT,
    PBlock: BlockT,
    Client:
        HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block> + 'static,
    Client::Api: SecondaryApi<Block, AccountId>
        + BlockBuilder<Block>
        + sp_api::ApiExt<
            Block,
            StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
        >,
    for<'b> &'b Client: BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    IBNS: Stream<Item = (NumberFor<PBlock>, mpsc::Sender<()>)> + Send + 'static,
    NSNS: Stream<Item = (Slot, Sha256Hash)> + Send + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    E: CodeExecutor,
{
    let span = tracing::Span::current();

    let handle_block_import_notifications_fut =
        handle_block_import_notifications::<Block, _, _, _, _, _>(
            primary_chain_client.as_ref(),
            client.info().best_number,
            {
                let span = span.clone();

                move |primary_hash, bundles, shuffling_seed, maybe_new_runtime| {
                    bundle_processor
                        .clone()
                        .process_bundles(primary_hash, bundles, shuffling_seed, maybe_new_runtime)
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
            Box::pin(imported_block_notification_stream),
            block_import_throttling_buffer_size,
        );
    let handle_slot_notifications_fut = handle_slot_notifications(
        primary_chain_client.as_ref(),
        move |primary_hash, slot_info| {
            bundle_producer
                .clone()
                .produce_bundle(primary_hash, slot_info)
                .instrument(span.clone())
                .unwrap_or_else(move |error| {
                    tracing::error!(
                        target: LOG_TARGET,
                        relay_parent = ?primary_hash,
                        error = ?error,
                        "Error at producing bundle.",
                    );
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

async fn handle_slot_notifications<PBlock, PClient, BundlerFn, SecondaryHash>(
    primary_chain_client: &PClient,
    bundler: BundlerFn,
    mut slots: impl Stream<Item = ExecutorSlotInfo> + Unpin,
) where
    PBlock: BlockT,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock>,
    PClient::Api: ExecutorApi<PBlock, SecondaryHash>,
    BundlerFn: Fn(
            PHash,
            ExecutorSlotInfo,
        ) -> Pin<Box<dyn Future<Output = Option<SignedOpaqueBundle>> + Send>>
        + Send
        + Sync,
    SecondaryHash: Encode + Decode,
{
    while let Some(executor_slot_info) = slots.next().await {
        if let Err(error) = on_new_slot(primary_chain_client, &bundler, executor_slot_info).await {
            tracing::error!(
                target: LOG_TARGET,
                error = ?error,
                "Failed to submit transaction bundle"
            );
            break;
        }
    }
}

async fn handle_block_import_notifications<
    Block,
    PBlock,
    PClient,
    ProcessorFn,
    SecondaryHash,
    BlockImports,
>(
    primary_chain_client: &PClient,
    best_secondary_number: NumberFor<Block>,
    processor: ProcessorFn,
    mut leaves: Vec<(PBlock::Hash, NumberFor<PBlock>)>,
    mut block_imports: BlockImports,
    block_import_throttling_buffer_size: u32,
) where
    Block: BlockT,
    PBlock: BlockT,
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock>,
    PClient::Api: ExecutorApi<PBlock, SecondaryHash>,
    ProcessorFn: Fn(
            (PBlock::Hash, NumberFor<PBlock>),
            Vec<OpaqueBundle>,
            Randomness,
            Option<Cow<'static, [u8]>>,
        ) -> Pin<Box<dyn Future<Output = Result<(), sp_blockchain::Error>> + Send>>
        + Send
        + Sync,
    SecondaryHash: Encode + Decode,
    BlockImports: Stream<Item = (NumberFor<PBlock>, mpsc::Sender<()>)> + Unpin,
{
    let mut active_leaves = HashMap::with_capacity(leaves.len());

    let best_secondary_number: BlockNumber = best_secondary_number
        .try_into()
        .unwrap_or_else(|_| panic!("Secondary number must fit into u32; qed"));

    // Notify about active leaves on startup before starting the loop
    for (hash, number) in std::mem::take(&mut leaves) {
        let _ = active_leaves.insert(hash, number);
        // Skip the blocks that have been processed by the execution chain.
        if number > best_secondary_number.into() {
            if let Err(error) =
                process_primary_block(primary_chain_client, &processor, (hash, number)).await
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
            Some((block_number, mut block_import_throttling_sender)) = block_imports.next() => {
                let header = primary_chain_client
                    .header(BlockId::Number(block_number))
                    .expect("Header of imported block must exist; qed")
                    .expect("Header of imported block must exist; qed");
                let block_info = BlockInfo {
                    hash: header.hash(),
                    parent_hash: *header.parent_hash(),
                    number: *header.number(),
                };
                let _ = block_info_sender.feed(block_info).await;
                let _ = block_import_throttling_sender.send(()).await;
            }
            Some(block_info) = block_info_receiver.next() => {
                if let Err(error) = block_imported(
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

async fn on_new_slot<PBlock, PClient, BundlerFn, SecondaryHash>(
    primary_chain_client: &PClient,
    bundler: &BundlerFn,
    executor_slot_info: ExecutorSlotInfo,
) -> Result<(), ApiError>
where
    PBlock: BlockT,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock>,
    PClient::Api: ExecutorApi<PBlock, SecondaryHash>,
    BundlerFn: Fn(
            PHash,
            ExecutorSlotInfo,
        ) -> Pin<Box<dyn Future<Output = Option<SignedOpaqueBundle>> + Send>>
        + Send
        + Sync,
    SecondaryHash: Encode + Decode,
{
    let best_hash = primary_chain_client.info().best_hash;

    let non_generic_best_hash =
        PHash::decode(&mut best_hash.encode().as_slice()).expect("Hash type must be correct");

    let opaque_bundle = match bundler(non_generic_best_hash, executor_slot_info).await {
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
        .submit_transaction_bundle_unsigned(&BlockId::Hash(best_hash), opaque_bundle)?;

    Ok(())
}

async fn block_imported<PBlock, PClient, ProcessorFn, SecondaryHash>(
    primary_chain_client: &PClient,
    processor: &ProcessorFn,
    active_leaves: &mut HashMap<PBlock::Hash, NumberFor<PBlock>>,
    block_info: BlockInfo<PBlock>,
) -> Result<(), ApiError>
where
    PBlock: BlockT,
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock> + Send + Sync,
    PClient::Api: ExecutorApi<PBlock, SecondaryHash>,
    ProcessorFn: Fn(
            (PBlock::Hash, NumberFor<PBlock>),
            Vec<OpaqueBundle>,
            Randomness,
            Option<Cow<'static, [u8]>>,
        ) -> Pin<Box<dyn Future<Output = Result<(), sp_blockchain::Error>> + Send>>
        + Send
        + Sync,
    SecondaryHash: Encode + Decode,
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

    process_primary_block(
        primary_chain_client,
        processor,
        (block_info.hash, block_info.number),
    )
    .await?;

    Ok(())
}

/// Apply the transaction bundles for given primary block as follows:
///
/// 1. Extract the transaction bundles from the block.
/// 2. Pass the bundles to secondary node and do the computation there.
async fn process_primary_block<PBlock, PClient, ProcessorFn, SecondaryHash>(
    primary_chain_client: &PClient,
    processor: &ProcessorFn,
    (block_hash, block_number): (PBlock::Hash, NumberFor<PBlock>),
) -> Result<(), ApiError>
where
    PBlock: BlockT,
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock> + Send + Sync,
    PClient::Api: ExecutorApi<PBlock, SecondaryHash>,
    ProcessorFn: Fn(
            (PBlock::Hash, NumberFor<PBlock>),
            Vec<OpaqueBundle>,
            Randomness,
            Option<Cow<'static, [u8]>>,
        ) -> Pin<Box<dyn Future<Output = Result<(), sp_blockchain::Error>> + Send>>
        + Send
        + Sync,
    SecondaryHash: Encode + Decode,
{
    let block_id = BlockId::Hash(block_hash);
    let extrinsics = match primary_chain_client.block_body(&block_id) {
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

    let bundles = primary_chain_client
        .runtime_api()
        .extract_bundles(&block_id, extrinsics)?;

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

    processor(
        (block_hash, block_number),
        bundles,
        shuffling_seed,
        maybe_new_runtime,
    )
    .await?;

    Ok(())
}
