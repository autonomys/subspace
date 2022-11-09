use crate::{BlockT, Error, HeaderBackend, HeaderT, Relayer, StateBackend, LOG_TARGET};
use futures::{Stream, StreamExt};
use sc_client_api::{AuxStore, ProofProvider};
use sp_api::ProvideRuntimeApi;
use sp_domain_tracker::DomainTrackerApi;
use sp_messenger::RelayerApi;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{CheckedAdd, CheckedSub, NumberFor, One, Zero};
use sp_runtime::ArithmeticError;
use std::sync::Arc;
use system_runtime_primitives::RelayerId;

// TODO(ved): ensure the client is not in major sync before relayer is ready to process the blocks
pub async fn relay_system_domain_messages<Client, Block, DBI>(
    relayer_id: RelayerId,
    domain_client: Arc<Client>,
    domain_block_import: DBI,
) -> Result<(), Error>
where
    Block: BlockT,
    Client: HeaderBackend<Block>
        + AuxStore
        + StateBackend<<Block::Header as HeaderT>::Hashing>
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, RelayerId, NumberFor<Block>>,
    DBI: Stream<Item = NumberFor<Block>> + Unpin,
{
    relay_domain_messages(
        relayer_id,
        domain_client,
        domain_block_import,
        Relayer::submit_messages_from_system_domain,
    )
    .await
}

pub async fn relay_core_domain_messages<CDC, SDC, Block, DBI>(
    relayer_id: RelayerId,
    core_domain_client: Arc<CDC>,
    system_domain_client: Arc<SDC>,
    core_domain_block_import: DBI,
) -> Result<(), Error>
where
    Block: BlockT,
    CDC: HeaderBackend<Block>
        + AuxStore
        + StateBackend<<Block::Header as HeaderT>::Hashing>
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    CDC::Api: RelayerApi<Block, RelayerId, NumberFor<Block>>,
    DBI: Stream<Item = NumberFor<Block>> + Unpin,
    SDC: HeaderBackend<Block> + ProvideRuntimeApi<Block> + ProofProvider<Block>,
    SDC::Api: DomainTrackerApi<Block, NumberFor<Block>>,
{
    relay_domain_messages(
        relayer_id,
        core_domain_client,
        core_domain_block_import,
        |relayer_id, client, block_id| {
            Relayer::submit_messages_from_core_domain(
                relayer_id,
                client,
                &system_domain_client,
                block_id,
            )
        },
    )
    .await
}

async fn relay_domain_messages<Client, Block, SDBI, MP>(
    relayer_id: RelayerId,
    domain_client: Arc<Client>,
    mut domain_block_import: SDBI,
    message_processor: MP,
) -> Result<(), Error>
where
    Block: BlockT,
    Client: HeaderBackend<Block>
        + AuxStore
        + StateBackend<<Block::Header as HeaderT>::Hashing>
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, RelayerId, NumberFor<Block>>,
    SDBI: Stream<Item = NumberFor<Block>> + Unpin,
    MP: Fn(RelayerId, &Arc<Client>, Block::Hash) -> Result<(), Error>,
{
    let domain_id = Relayer::domain_id(&domain_client)?;
    let relay_confirmation_depth = Relayer::relay_confirmation_depth(&domain_client)?;
    let maybe_last_relayed_block = Relayer::fetch_last_relayed_block(&domain_client, domain_id);
    let mut relay_block_from = match maybe_last_relayed_block {
        None => Zero::zero(),
        Some(last_block_number) => last_block_number
            .checked_add(&One::one())
            .ok_or(ArithmeticError::Overflow)?,
    };

    // from the start block, start processing all the messages assigned
    // wait for new block import of system domain,
    // then fetch new messages assigned to to relayer from system domain
    // construct proof of each message to be relayed
    // submit XDM as unsigned extrinsic.
    while let Some(block_number) = domain_block_import.next().await {
        let relay_block_until = match block_number.checked_sub(&relay_confirmation_depth) {
            None => {
                // not enough confirmed blocks.
                continue;
            }
            Some(confirmed_block) => confirmed_block,
        };

        while relay_block_from <= relay_block_until {
            let block_hash = domain_client
                .header(BlockId::Number(relay_block_from))?
                .ok_or(Error::UnableToFetchBlockNumber)?
                .hash();
            if let Err(err) = message_processor(relayer_id.clone(), &domain_client, block_hash) {
                tracing::error!(
                    target: LOG_TARGET,
                    ?err,
                    "Failed to submit messages from the domain {domain_id:?} at the block {relay_block_from:?}"
                );
                break;
            };

            Relayer::store_last_relayed_block(&domain_client, domain_id, relay_block_from)?;
            relay_block_from = relay_block_from
                .checked_add(&One::one())
                .ok_or(ArithmeticError::Overflow)?;
        }
    }

    Ok(())
}
