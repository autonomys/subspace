use futures::StreamExt;
use sc_client_api::BlockchainEvents;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use tracing::{debug, trace};

pub async fn wait_for_block_import<Block, Client>(
    client: &Client,
    waiting_block_number: NumberFor<Block>,
) where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockchainEvents<Block>,
{
    let mut blocks_stream = client.every_import_notification_stream();

    let info = client.info();
    debug!(
        %waiting_block_number,
        "Waiting client info: {:?}", info
    );

    if info.best_number >= waiting_block_number {
        return;
    }

    while let Some(block) = blocks_stream.next().await {
        let current_block_number = *block.header.number();
        trace!(%current_block_number, %waiting_block_number, "Waiting for the target block");

        if current_block_number >= waiting_block_number {
            return;
        }
    }
}
