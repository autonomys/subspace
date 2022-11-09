use crate::{BlockT, Error, HeaderBackend, HeaderT, Relayer, StateBackend};
use futures::{Stream, StreamExt};
use sc_client_api::{AuxStore, ProofProvider};
use sp_api::ProvideRuntimeApi;
use sp_messenger::RelayerApi;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{CheckedAdd, CheckedSub, NumberFor, One, Zero};
use sp_runtime::ArithmeticError;
use std::sync::Arc;
use system_runtime_primitives::RelayerId;

pub async fn relay_system_domain_messages<Client, Block, SDBI>(
    relayer_id: RelayerId,
    system_domain_client: Arc<Client>,
    mut system_domain_block_import: SDBI,
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
{
    let relayer = Relayer {
        domain_client: system_domain_client,
        relayer_id,
        _phantom_data: Default::default(),
    };
    let domain_id = relayer.domain_id()?;
    let relay_confirmation_depth = relayer.relay_confirmation_depth()?;
    let maybe_last_relayed_block = relayer.fetch_last_relayed_block(domain_id);
    let mut relay_block_from = match maybe_last_relayed_block {
        None => Zero::zero(),
        Some(block_id) => {
            let last_block_number = relayer
                .domain_client
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
            let block_hash = relayer
                .domain_client
                .block_hash_from_id(&block_id)?
                .ok_or(Error::UnableToFetchBlockHash)?;
            relayer.submit_unsigned_messages(block_hash)?;
            relayer.store_last_relayed_block(domain_id, block_id)?;
            relay_block_from = relay_block_from
                .checked_add(&One::one())
                .ok_or(ArithmeticError::Overflow)?;
        }
    }

    Ok(())
}
