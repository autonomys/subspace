//! Shared domain worker functions.

use crate::utils::{BlockInfo, OperatorSlotInfo};
use futures::channel::mpsc;
use futures::{SinkExt, Stream, StreamExt};
use sc_client_api::{BlockBackend, BlockImportNotification, BlockchainEvents};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sp_api::{ApiError, ApiExt, BlockT, ProvideRuntimeApi};
use sp_blockchain::{HashAndNumber, HeaderBackend};
use sp_core::traits::SpawnEssentialNamed;
use sp_domains::{DomainsApi, OpaqueBundle};
use sp_runtime::traits::{Header as HeaderT, NumberFor};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use subspace_runtime_primitives::Balance;

pub type OpaqueBundleFor<Block, CBlock> =
    OpaqueBundle<NumberFor<CBlock>, <CBlock as BlockT>::Hash, <Block as BlockT>::Header, Balance>;

/// Throttle the consensus block import notification based on the `consensus_block_import_throttling_buffer_size`
/// to pause the consensus block import in case the consensus chain runs much faster than the domain.
///
/// Return the throttled block import notification stream
#[allow(clippy::too_many_arguments)]
pub(crate) fn throttling_block_import_notifications<
    Block,
    CBlock,
    CClient,
    BlocksImporting,
    BlocksImported,
>(
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

pub(crate) async fn on_new_slot<Block, CBlock, CClient, BundlerFn>(
    consensus_client: &CClient,
    consensus_offchain_tx_pool_factory: OffchainTransactionPoolFactory<CBlock>,
    bundler: &BundlerFn,
    operator_slot_info: OperatorSlotInfo,
) -> Result<(), ApiError>
where
    Block: BlockT,
    CBlock: BlockT,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock>,
    CClient::Api: DomainsApi<CBlock, Block::Header>,
    BundlerFn: Fn(
            HashAndNumber<CBlock>,
            OperatorSlotInfo,
        ) -> Pin<Box<dyn Future<Output = Option<OpaqueBundleFor<Block, CBlock>>> + Send>>
        + Send
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

    let mut runtime_api = consensus_client.runtime_api();
    // Register the offchain tx pool to be able to use it from the runtime.
    runtime_api.register_extension(
        consensus_offchain_tx_pool_factory.offchain_transaction_pool(best_hash),
    );
    runtime_api.submit_bundle_unsigned(best_hash, opaque_bundle)?;

    Ok(())
}
