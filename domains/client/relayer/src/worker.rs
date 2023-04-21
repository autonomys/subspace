use crate::{BlockT, Error, GossipMessageSink, HeaderBackend, HeaderT, Relayer, LOG_TARGET};
use futures::StreamExt;
use parity_scale_codec::{Decode, Encode, FullCodec};
use sc_client_api::{AuxStore, BlockchainEvents, ProofProvider};
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_consensus::SyncOracle;
use sp_domains::DomainId;
use sp_messenger::RelayerApi;
use sp_runtime::scale_info::TypeInfo;
use sp_runtime::traits::{CheckedSub, NumberFor, Zero};
use std::sync::Arc;
use system_runtime_primitives::SystemDomainApi;

/// Starts relaying system domain messages to other domains.
/// If the node is in major sync, worker waits waits until the sync is finished.
pub async fn relay_system_domain_messages<Client, Block, SO, RelayerId>(
    relayer_id: RelayerId,
    system_domain_client: Arc<Client>,
    system_domain_sync_oracle: SO,
    gossip_message_sink: GossipMessageSink,
) where
    Block: BlockT,
    Client: BlockchainEvents<Block>
        + HeaderBackend<Block>
        + AuxStore
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, RelayerId, NumberFor<Block>>,
    RelayerId: Encode + Decode + Clone,
    SO: SyncOracle,
{
    // there is not confirmation depth for relayer on system domain
    // since all the relayers will haven embed client to known the canonical chain.
    let result = relay_domain_messages(
        relayer_id,
        NumberFor::<Block>::zero(),
        system_domain_client,
        |relayer_id, client, block_hash| {
            Relayer::submit_messages_from_system_domain(
                relayer_id,
                client,
                block_hash,
                &gossip_message_sink,
            )
        },
        system_domain_sync_oracle,
        |_domain_id, _block_number| -> Result<bool, ApiError> {
            // since we just need to provide a storage proof with the state root of system domain
            // proof can always be generated for any system domain block.
            // So we can always relay messages.
            Ok(true)
        },
    )
    .await;

    if let Err(err) = result {
        tracing::error!(
            target: LOG_TARGET,
            ?err,
            "Failed to start relayer for system domain"
        )
    }
}

/// Starts relaying core domain messages to other domains.
/// If the either system domain or core domain node is in major sync,
/// worker waits waits until the sync is finished.
pub async fn relay_core_domain_messages<CDC, SDC, PBlock, SBlock, Block, SDSO, CDSO, RelayerId>(
    relayer_id: RelayerId,
    core_domain_client: Arc<CDC>,
    system_domain_client: Arc<SDC>,
    system_domain_sync_oracle: SDSO,
    core_domain_sync_oracle: CDSO,
    gossip_message_sink: GossipMessageSink,
) where
    Block: BlockT,
    PBlock: BlockT,
    SBlock: BlockT,
    Block::Hash: FullCodec,
    NumberFor<Block>: FullCodec + TypeInfo,
    NumberFor<SBlock>: From<NumberFor<Block>> + Into<NumberFor<Block>>,
    SBlock::Hash: Into<Block::Hash> + From<Block::Hash>,
    CDC: BlockchainEvents<Block>
        + HeaderBackend<Block>
        + AuxStore
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    CDC::Api: RelayerApi<Block, RelayerId, NumberFor<Block>>,
    SDC: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + ProofProvider<SBlock>,
    SDC::Api: RelayerApi<SBlock, domain_runtime_primitives::AccountId, NumberFor<SBlock>>
        + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    SDSO: SyncOracle + Send,
    CDSO: SyncOracle + Send,
    RelayerId: Encode + Decode + Clone,
{
    let combined_sync_oracle =
        CombinedSyncOracle::new(system_domain_sync_oracle, core_domain_sync_oracle);

    let relay_confirmation_depth = match Relayer::relay_confirmation_depth(&core_domain_client) {
        Ok(depth) => depth,
        Err(err) => {
            tracing::error!(target: LOG_TARGET, ?err, "Failed to get confirmation depth");
            return;
        }
    };

    let result = relay_domain_messages(
        relayer_id,
        relay_confirmation_depth,
        core_domain_client,
        |relayer_id, client, block_hash| {
            Relayer::submit_messages_from_core_domain(
                relayer_id,
                client,
                &system_domain_client,
                block_hash,
                &gossip_message_sink,
                relay_confirmation_depth.into(),
            )
        },
        combined_sync_oracle,
        |domain_id, block_number| -> Result<bool, ApiError> {
            let api = system_domain_client.runtime_api();
            let at = system_domain_client.info().best_hash;
            let oldest_tracked_number = api.oldest_receipt_number(at, domain_id)?;
            // ensure block number is at least the oldest tracked number
            Ok(block_number >= oldest_tracked_number.into())
        },
    )
    .await;
    if let Err(err) = result {
        tracing::error!(
            target: LOG_TARGET,
            ?err,
            "Failed to start relayer for core domain"
        )
    }
}

async fn relay_domain_messages<Client, Block, MP, SO, SRM, RelayerId>(
    relayer_id: RelayerId,
    relay_confirmation_depth: NumberFor<Block>,
    domain_client: Arc<Client>,
    message_processor: MP,
    sync_oracle: SO,
    can_relay_message_from_block: SRM,
) -> Result<(), Error>
where
    Block: BlockT,
    Client: BlockchainEvents<Block>
        + HeaderBackend<Block>
        + AuxStore
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, RelayerId, NumberFor<Block>>,
    MP: Fn(RelayerId, &Arc<Client>, Block::Hash) -> Result<(), Error>,
    SO: SyncOracle,
    SRM: Fn(DomainId, NumberFor<Block>) -> Result<bool, ApiError>,
    RelayerId: Encode + Decode + Clone,
{
    let domain_id = Relayer::domain_id(&domain_client)?;
    tracing::info!(
        target: LOG_TARGET,
        "Starting relayer for domain: {:?}",
        domain_id,
    );
    let mut domain_block_import = domain_client.import_notification_stream();

    // from the start block, start processing all the messages assigned
    // wait for new block import of system domain,
    // then fetch new messages assigned to to relayer from system domain
    // construct proof of each message to be relayed
    // submit XDM as unsigned extrinsic.
    while let Some(block) = domain_block_import.next().await {
        // if the client is in major sync, wait until sync is complete
        if sync_oracle.is_major_syncing() {
            tracing::info!(target: LOG_TARGET, "Client is in major sync. Skipping...");
            continue;
        }

        let relay_block_until = match block.header.number().checked_sub(&relay_confirmation_depth) {
            None => {
                // not enough confirmed blocks.
                tracing::info!(
                    target: LOG_TARGET,
                    "Not enough confirmed blocks for domain: {:?}. Skipping...",
                    domain_id
                );
                continue;
            }
            Some(confirmed_block) => confirmed_block,
        };

        let (number, hash) = (*block.header.number(), block.header.hash());
        let blocks_to_process: Vec<(NumberFor<Block>, Block::Hash)> =
            Relayer::fetch_unprocessed_blocks_until(&domain_client, domain_id, number, hash)?
                .into_iter()
                .filter(|(number, _)| *number <= relay_block_until)
                .collect();

        for (number, hash) in blocks_to_process {
            tracing::info!(
                target: LOG_TARGET,
                "Checking messages to be submitted from domain: {domain_id:?} at block: ({number:?}, {hash:?})",
            );

            // check if the message is ready to be relayed.
            // if not, the node is lagging behind and/or there is no way to generate a proof.
            // mark this block processed and continue to next one.
            if !can_relay_message_from_block(domain_id, number)? {
                tracing::info!(
                    target: LOG_TARGET,
                    "Domain({domain_id:?}) messages in the Block ({number:?}, {hash:?}) cannot be relayed. Skipping...",
                );
            } else if let Err(err) = message_processor(relayer_id.clone(), &domain_client, hash) {
                tracing::error!(
                target: LOG_TARGET,
                ?err,
                "Failed to submit messages from the domain {domain_id:?} at the block ({number:?}, {hash:?})"
            );
                break;
            }

            // TODO: at the moment the aux storage grows as the chain grows
            // We can prune the the storage by doing another round of check for any undelivered messages
            // and then prune the storage.
            // We can use Finalize event but its not triggered yet as we dont finalize.
            // Other option would be to use fraud proof period.
            Relayer::store_relayed_block(&domain_client, domain_id, number, hash)?;
        }
    }

    Ok(())
}

/// Combines both system and core domain sync oracles into one.
struct CombinedSyncOracle<SDSO, CDSO> {
    system_domain_sync_oracle: SDSO,
    core_domain_sync_oracle: CDSO,
}

impl<SDSO, CDSO> SyncOracle for CombinedSyncOracle<SDSO, CDSO>
where
    SDSO: SyncOracle,
    CDSO: SyncOracle,
{
    /// Returns true if either of the domains are in major sync.
    fn is_major_syncing(&self) -> bool {
        self.system_domain_sync_oracle.is_major_syncing()
            || self.core_domain_sync_oracle.is_major_syncing()
    }

    /// Returns true if either of the domains are offline.
    fn is_offline(&self) -> bool {
        self.system_domain_sync_oracle.is_offline() || self.core_domain_sync_oracle.is_offline()
    }
}

impl<SDSO, CDSO> CombinedSyncOracle<SDSO, CDSO> {
    /// Returns a new sync oracle that wraps system domain and core domain sync oracle.
    fn new(system_domain_sync_oracle: SDSO, core_domain_sync_oracle: CDSO) -> Self {
        CombinedSyncOracle {
            system_domain_sync_oracle,
            core_domain_sync_oracle,
        }
    }
}
