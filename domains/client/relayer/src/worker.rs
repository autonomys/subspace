use crate::{BlockT, Error, GossipMessageSink, HeaderBackend, HeaderT, Relayer, LOG_TARGET};
use cross_domain_message_gossip::{ChannelUpdate, Message as GossipMessage, MessageData};
use futures::StreamExt;
use sc_client_api::{AuxStore, BlockchainEvents, ProofProvider};
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_consensus::SyncOracle;
use sp_domains::{DomainId, DomainsApi};
use sp_messenger::messages::ChainId;
use sp_messenger::{MessengerApi, RelayerApi};
use sp_mmr_primitives::MmrApi;
use sp_runtime::traits::{CheckedSub, NumberFor, One, Zero};
use sp_runtime::SaturatedConversion;
use std::sync::Arc;

pub async fn gossip_channel_updates<Client, Block, CBlock, SO>(
    chain_id: ChainId,
    client: Arc<Client>,
    sync_oracle: SO,
    gossip_message_sink: GossipMessageSink,
) where
    Block: BlockT,
    CBlock: BlockT,
    Client: BlockchainEvents<Block>
        + HeaderBackend<Block>
        + AuxStore
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>,
    SO: SyncOracle,
{
    tracing::info!(
        target: LOG_TARGET,
        "Starting Channel updates for chain: {:?}",
        chain_id,
    );
    let mut chain_block_imported = client.every_import_notification_stream();
    while let Some(imported_block) = chain_block_imported.next().await {
        // if the client is in major sync, wait until sync is complete
        if sync_oracle.is_major_syncing() {
            tracing::debug!(target: LOG_TARGET, "Client is in major sync. Skipping...");
            continue;
        }

        if !imported_block.is_new_best {
            tracing::debug!(target: LOG_TARGET, "Imported non-best block. Skipping...");
            continue;
        }

        let (block_hash, block_number) = match chain_id {
            ChainId::Consensus => (
                imported_block.header.hash(),
                *imported_block.header.number(),
            ),
            ChainId::Domain(_) => {
                // for domains, we gossip channel updates of imported block - 1
                // since the execution receipt of the imported block is not registered on consensus
                // without the execution receipt, we would not be able to verify the storage proof
                let number = match imported_block.header.number().checked_sub(&One::one()) {
                    None => continue,
                    Some(number) => number,
                };

                let hash = match client.hash(number).ok().flatten() {
                    Some(hash) => hash,
                    None => {
                        tracing::debug!(target: LOG_TARGET, "Missing block hash for number: {:?}", number);
                        continue;
                    }
                };

                (hash, number)
            }
        };

        if let Err(err) = do_gossip_channel_updates::<_, _, CBlock>(
            chain_id,
            &client,
            &gossip_message_sink,
            block_number,
            block_hash,
        ) {
            tracing::error!(target: LOG_TARGET, ?err, "failed to gossip channel update");
        }
    }
}

fn do_gossip_channel_updates<Client, Block, CBlock>(
    src_chain_id: ChainId,
    client: &Arc<Client>,
    gossip_message_sink: &GossipMessageSink,
    block_number: NumberFor<Block>,
    block_hash: Block::Hash,
) -> Result<(), Error>
where
    Block: BlockT,
    CBlock: BlockT,
    Client: BlockchainEvents<Block>
        + HeaderBackend<Block>
        + AuxStore
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>,
{
    let api = client.runtime_api();

    let channels_status_to_broadcast = {
        let updated_channels = api.updated_channels(block_hash)?;

        // TODO: remove version check before next network
        let relayer_api_version = api
            .api_version::<dyn RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>>(block_hash)?
            // It is safe to return a default version of 1, since there will always be version 1.
            .unwrap_or(1);

        // if there are no channel updates, broadcast channel's status for every 300 blocks
        if updated_channels.is_empty()
            && relayer_api_version >= 2
            && block_number % 300u32.into() == Zero::zero()
        {
            api.open_channels(block_hash)?
        } else {
            updated_channels
        }
    };

    for (dst_chain_id, channel_id) in channels_status_to_broadcast {
        let storage_key = api.channel_storage_key(block_hash, dst_chain_id, channel_id)?;
        let proof = client
            .read_proof(block_hash, &mut [storage_key.as_ref()].into_iter())
            .map_err(|_| Error::ConstructStorageProof)?;

        let gossip_message = GossipMessage {
            chain_id: dst_chain_id,
            data: MessageData::ChannelUpdate(ChannelUpdate {
                src_chain_id,
                channel_id,
                block_number: block_number.saturated_into(),
                storage_proof: proof,
            }),
        };

        gossip_message_sink
            .unbounded_send(gossip_message)
            .map_err(Error::UnableToSubmitCrossDomainMessage)?;
    }

    Ok(())
}

pub async fn start_relaying_messages<CClient, Client, CBlock, Block, SO>(
    domain_id: DomainId,
    consensus_client: Arc<CClient>,
    domain_client: Arc<Client>,
    confirmation_depth_k: NumberFor<CBlock>,
    sync_oracle: SO,
    gossip_message_sink: GossipMessageSink,
) where
    Block: BlockT,
    CBlock: BlockT,
    Client: HeaderBackend<Block> + AuxStore + ProofProvider<Block> + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>,
    CClient: BlockchainEvents<CBlock>
        + HeaderBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + ProofProvider<CBlock>
        + AuxStore,
    CClient::Api: DomainsApi<CBlock, Block::Header>
        + MessengerApi<CBlock, NumberFor<CBlock>, CBlock::Hash>
        + MmrApi<CBlock, sp_core::H256, NumberFor<CBlock>>
        + RelayerApi<CBlock, NumberFor<CBlock>, NumberFor<CBlock>, CBlock::Hash>,
    SO: SyncOracle + Send,
{
    tracing::info!(
        target: LOG_TARGET,
        "Starting relayer for domain: {domain_id:?} and the consensus chain",
    );
    let mut chain_block_imported = consensus_client.every_import_notification_stream();

    // from the start block, start processing all the messages assigned
    // wait for new block finalization of the chain,
    // then fetch new messages in the block
    // construct proof of each message to be relayed
    // submit XDM as unsigned extrinsic.
    while let Some(imported_block) = chain_block_imported.next().await {
        // if the client is in major sync, wait until sync is complete
        if sync_oracle.is_major_syncing() {
            tracing::debug!(target: LOG_TARGET, "Client is in major sync. Skipping...");
            continue;
        }

        if !imported_block.is_new_best {
            tracing::debug!(target: LOG_TARGET, "Imported non-best block. Skipping...");
            continue;
        }

        let Some(confirmed_block_number) = imported_block
            .header
            .number()
            .checked_sub(&confirmation_depth_k)
        else {
            tracing::debug!(target: LOG_TARGET, "Not enough confirmed blocks. Skipping...");
            continue;
        };

        for chain_id in [ChainId::Consensus, ChainId::Domain(domain_id)] {
            let res = Relayer::construct_and_submit_xdm(
                chain_id,
                &domain_client,
                &consensus_client,
                confirmed_block_number,
                &gossip_message_sink,
            );

            if let Err(err) = res {
                tracing::error!(
                    target: LOG_TARGET,
                    ?err,
                    "Failed to submit messages from the chain {chain_id:?} at the block ({confirmed_block_number:?}"
                );
                continue;
            }
        }
    }
}
