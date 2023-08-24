use crate::{BlockT, Error, GossipMessageSink, HeaderBackend, HeaderT, Relayer, LOG_TARGET};
use futures::StreamExt;
use sc_client_api::{AuxStore, BlockchainEvents, ProofProvider};
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_consensus::SyncOracle;
use sp_messenger::messages::ChainId;
use sp_messenger::RelayerApi;
use sp_runtime::traits::{CheckedSub, NumberFor, Zero};
use std::sync::Arc;

/// Starts relaying consensus chain messages to other domains.
/// If the node is in major sync, worker waits waits until the sync is finished.
pub async fn relay_domain_messages<Client, Block, SO>(
    domain_client: Arc<Client>,
    domain_sync_oracle: SO,
    gossip_message_sink: GossipMessageSink,
) where
    Block: BlockT,
    Client: BlockchainEvents<Block>
        + HeaderBackend<Block>
        + AuxStore
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>>,
    SO: SyncOracle,
{
    // there is not confirmation depth for relayer on system domain
    // since all the relayers will haven embed client to known the canonical chain.
    let result = start_relaying_domain_messages(
        NumberFor::<Block>::zero(),
        domain_client,
        |client, block_hash| {
            // TODO: this is incorrect and should instead expect a primary client.
            //  Will be fixed in coming prs
            Relayer::submit_messages_from_system_domain(client, block_hash, &gossip_message_sink)
        },
        domain_sync_oracle,
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

async fn start_relaying_domain_messages<Client, Block, MP, SO, SRM>(
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
    Client::Api: RelayerApi<Block, NumberFor<Block>>,
    MP: Fn(&Arc<Client>, Block::Hash) -> Result<(), Error>,
    SO: SyncOracle,
    SRM: Fn(ChainId, NumberFor<Block>) -> Result<bool, ApiError>,
{
    let chain_id = Relayer::chain_id(&domain_client)?;
    tracing::info!(
        target: LOG_TARGET,
        "Starting relayer for domain: {:?}",
        chain_id,
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
                    chain_id
                );
                continue;
            }
            Some(confirmed_block) => confirmed_block,
        };

        let (number, hash) = (*block.header.number(), block.header.hash());
        let blocks_to_process: Vec<(NumberFor<Block>, Block::Hash)> =
            Relayer::fetch_unprocessed_blocks_until(&domain_client, chain_id, number, hash)?
                .into_iter()
                .filter(|(number, _)| *number <= relay_block_until)
                .collect();

        for (number, hash) in blocks_to_process {
            tracing::info!(
                target: LOG_TARGET,
                "Checking messages to be submitted from chain: {chain_id:?} at block: ({number:?}, {hash:?})",
            );

            // check if the message is ready to be relayed.
            // if not, the node is lagging behind and/or there is no way to generate a proof.
            // mark this block processed and continue to next one.
            if !can_relay_message_from_block(chain_id, number)? {
                Relayer::store_relayed_block(&domain_client, chain_id, number, hash)?;
                tracing::info!(
                    target: LOG_TARGET,
                    "Chain({chain_id:?}) messages in the Block ({number:?}, {hash:?}) cannot be relayed. Skipping...",
                );
            } else {
                match message_processor(&domain_client, hash) {
                    Ok(_) => {
                        Relayer::store_relayed_block(&domain_client, chain_id, number, hash)?;
                        tracing::info!(
                            target: LOG_TARGET,
                            "Messages from {chain_id:?} at block({number:?}, {hash:?}) are processed."
                        )
                    }
                    Err(err) => {
                        match err {
                            Error::CoreDomainNonConfirmedOnSystemDomain => {
                                tracing::info!(
                                    target: LOG_TARGET,
                                    "Waiting for Domain[{chain_id:?}] block({number:?}, {hash:?}) to be confirmed on Consensus chain."
                                )
                            }
                            _ => {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    ?err,
                                    "Failed to submit messages from the chain {chain_id:?} at the block ({number:?}, {hash:?})"
                                );
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Combines both system and core domain sync oracles into one.
struct CombinedSyncOracle<CCSO, DSO> {
    consensus_chain_sync_oracle: CCSO,
    domain_sync_oracle: DSO,
}

impl<CCSO, DSO> SyncOracle for CombinedSyncOracle<CCSO, DSO>
where
    CCSO: SyncOracle,
    DSO: SyncOracle,
{
    /// Returns true if either of the domains are in major sync.
    fn is_major_syncing(&self) -> bool {
        self.consensus_chain_sync_oracle.is_major_syncing()
            || self.domain_sync_oracle.is_major_syncing()
    }

    /// Returns true if either of the domains are offline.
    fn is_offline(&self) -> bool {
        self.consensus_chain_sync_oracle.is_offline() || self.domain_sync_oracle.is_offline()
    }
}

impl<SDSO, CDSO> CombinedSyncOracle<SDSO, CDSO> {
    /// Returns a new sync oracle that wraps system domain and core domain sync oracle.
    // TODO: Remove or make use of it.
    #[allow(unused)]
    fn new(consensus_chain_sync_oracle: SDSO, core_domain_sync_oracle: CDSO) -> Self {
        CombinedSyncOracle {
            consensus_chain_sync_oracle,
            domain_sync_oracle: core_domain_sync_oracle,
        }
    }
}
