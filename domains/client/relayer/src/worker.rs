use crate::{BlockT, Error, HeaderBackend, HeaderT, Relayer, StateBackend};
use futures::channel::mpsc;
use futures::{Stream, StreamExt};
use sc_client_api::{AuxStore, ProofProvider};
use sc_consensus::ForkChoiceStrategy;
use sp_api::ProvideRuntimeApi;
use sp_messenger::RelayerApi;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{CheckedAdd, CheckedSub, NumberFor, One, Zero};
use sp_runtime::ArithmeticError;
use std::sync::Arc;
use system_runtime_primitives::{DomainId, RelayerId};

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
    Client::Api: RelayerApi<Block, RelayerId, DomainId, NumberFor<Block>>,
    SDBI: Stream<Item = (NumberFor<Block>, ForkChoiceStrategy, mpsc::Sender<()>)> + Unpin,
{
    let relayer = Relayer {
        domain_client: system_domain_client,
        relayer_id,
        _phantom_data: Default::default(),
    };
    let domain_id = relayer.domain_id()?;
    let relay_confirmation_depth = relayer.relay_confirmation_depth()?;
    let maybe_last_processed_block = relayer.fetch_last_processed_block(domain_id);
    let mut process_block_from = match maybe_last_processed_block {
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
    while let Some((block_number, _, sender)) = system_domain_block_import.next().await {
        drop(sender);
        let process_block_until = match block_number.checked_sub(&relay_confirmation_depth) {
            None => {
                // not enough confirmed blocks.
                continue;
            }
            Some(confirmed_block) => confirmed_block,
        };

        while process_block_from <= process_block_until {
            let block_id = BlockId::Number(process_block_from);
            relayer.submit_unsigned_messages(block_id)?;
            relayer.store_last_processed_block(domain_id, block_id)?;
            process_block_from = process_block_from
                .checked_add(&One::one())
                .ok_or(ArithmeticError::Overflow)?;
        }
    }

    Ok(())
}
