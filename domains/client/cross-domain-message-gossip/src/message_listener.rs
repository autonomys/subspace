use crate::ChainTxPoolMsg;
use futures::{Stream, StreamExt};
use sc_network::NetworkPeers;
use sc_transaction_pool_api::{TransactionPool, TransactionSource};
use sp_blockchain::HeaderBackend;
use sp_messenger::messages::ChainId;
use sp_runtime::codec::Decode;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

const LOG_TARGET: &str = "domain_message_listener";

type BlockOf<T> = <T as TransactionPool>::Block;
type ExtrinsicOf<T> = <<T as TransactionPool>::Block as BlockT>::Extrinsic;

pub async fn start_cross_chain_message_listener<Client, TxPool, TxnListener>(
    chain_id: ChainId,
    client: Arc<Client>,
    tx_pool: Arc<TxPool>,
    network: Arc<dyn NetworkPeers + Send + Sync>,
    mut listener: TxnListener,
) where
    TxPool: TransactionPool + 'static,
    Client: HeaderBackend<BlockOf<TxPool>>,
    TxnListener: Stream<Item = ChainTxPoolMsg> + Unpin,
{
    tracing::info!(
        target: LOG_TARGET,
        "Starting transaction listener for Chain: {:?}",
        chain_id
    );

    while let Some(msg) = listener.next().await {
        tracing::debug!(
            target: LOG_TARGET,
            "Extrinsic received for Chain: {:?}",
            chain_id,
        );

        let ext = match ExtrinsicOf::<TxPool>::decode(&mut msg.encoded_data.as_ref()) {
            Ok(ext) => ext,
            Err(_) => {
                if let Some(peer_id) = msg.maybe_peer {
                    network.report_peer(peer_id, crate::gossip_worker::rep::GOSSIP_NOT_DECODABLE);
                } else {
                    tracing::error!(
                        target: LOG_TARGET,
                        "Failed to decode extrinsic from unknown sender: {:?}",
                        msg.encoded_data
                    );
                }
                continue;
            }
        };

        let at = client.info().best_hash;
        tracing::debug!(
            target: LOG_TARGET,
            "Submitting extrinsic to tx pool at block: {:?}",
            at
        );

        let tx_pool_res = tx_pool
            .submit_one(at, TransactionSource::External, ext)
            .await;

        if let Err(err) = tx_pool_res {
            tracing::error!(
                target: LOG_TARGET,
                "Failed to submit extrinsic to tx pool for Chain {:?} with error: {:?}",
                chain_id,
                err
            );
        }
    }
}
