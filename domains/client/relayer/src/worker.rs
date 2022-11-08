use crate::{BlockT, Error, HeaderBackend, HeaderT, Relayer, StateBackend, LOG_TARGET};
use futures::{Stream, StreamExt};
use sc_client_api::{AuxStore, ProofProvider};
use sp_api::ProvideRuntimeApi;
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

async fn relay_domain_messages<Client, Block, SDBI, MP>(
    relayer_id: RelayerId,
    system_domain_client: Arc<Client>,
    mut system_domain_block_import: SDBI,
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
    MP: Fn(RelayerId, &Arc<Client>, BlockId<Block>) -> Result<(), Error>,
{
    let domain_id = Relayer::domain_id(&system_domain_client)?;
    let relay_confirmation_depth = Relayer::relay_confirmation_depth(&system_domain_client)?;
    let maybe_last_relayed_block =
        Relayer::fetch_last_relayed_block(&system_domain_client, domain_id);
    let mut relay_block_from = match maybe_last_relayed_block {
        None => Zero::zero(),
        Some(block_id) => {
            let last_block_number = system_domain_client
                .block_number_from_id(&block_id)?
                .ok_or(Error::UnableToFetchProcessedBlockId)?;
            last_block_number
                .checked_add(&One::one())
                .ok_or(ArithmeticError::Overflow)?
        }
    };

    // from the start block, start processing all the messages assigned
    // wait for new block import of system domain,
    // then fetch new messages assigned to to relayer from system domain
    // construct proof of each message to be relayed
    // submit XDM as unsigned extrinsic.
    while let Some(block_number) = system_domain_block_import.next().await {
        let relay_block_until = match block_number.checked_sub(&relay_confirmation_depth) {
            None => {
                // not enough confirmed blocks.
                continue;
            }
            Some(confirmed_block) => confirmed_block,
        };

        while relay_block_from <= relay_block_until {
            let block_id = BlockId::Number(relay_block_from);
            if let Err(err) = message_processor(relayer_id.clone(), &system_domain_client, block_id)
            {
                tracing::error!(
                    target: LOG_TARGET,
                    ?err,
                    "Failed to submit messages from the domain {domain_id:?} at the block {relay_block_from:?}"
                );
                break;
            };

            Relayer::store_last_relayed_block(&system_domain_client, domain_id, block_id)?;
            relay_block_from = relay_block_from
                .checked_add(&One::one())
                .ok_or(ArithmeticError::Overflow)?;
        }
    }

    Ok(())
}
