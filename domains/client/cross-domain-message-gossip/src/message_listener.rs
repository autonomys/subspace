use futures::{Stream, StreamExt};
use sc_transaction_pool_api::{TransactionPool, TransactionSource};
use sp_blockchain::HeaderBackend;
use sp_domains::DomainId;
use sp_runtime::codec::Decode;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

const LOG_TARGET: &str = "domain_message_listener";

type DomainBlockOf<T> = <T as TransactionPool>::Block;
type DomainExtrinsicOf<T> = <<T as TransactionPool>::Block as BlockT>::Extrinsic;

pub async fn start_domain_message_listener<Client, TxPool, TxnListener>(
    domain_id: DomainId,
    client: Arc<Client>,
    tx_pool: Arc<TxPool>,
    mut listener: TxnListener,
) where
    TxPool: TransactionPool + 'static,
    Client: HeaderBackend<DomainBlockOf<TxPool>>,
    TxnListener: Stream<Item = Vec<u8>> + Unpin,
{
    tracing::info!(
        target: LOG_TARGET,
        "Starting transaction listener for domain: {:?}",
        domain_id
    );

    while let Some(encoded_ext) = listener.next().await {
        tracing::debug!(
            target: LOG_TARGET,
            "Extrinsic received for domain: {:?}",
            domain_id,
        );

        let ext = match DomainExtrinsicOf::<TxPool>::decode(&mut encoded_ext.as_ref()) {
            Ok(ext) => ext,
            Err(_) => {
                tracing::error!(
                    target: LOG_TARGET,
                    "Failed to decode extrinsic: {:?}",
                    encoded_ext
                );
                continue;
            }
        };

        let at = BlockId::Hash(client.info().best_hash);
        tracing::debug!(
            target: LOG_TARGET,
            "Submitting extrinsic to tx pool at block: {:?}",
            at
        );

        let tx_pool_res = tx_pool
            .submit_one(&at, TransactionSource::External, ext)
            .await;

        if let Err(err) = tx_pool_res {
            tracing::error!(
                target: LOG_TARGET,
                "Failed to submit extrinsic to tx pool for domain {:?} with error: {:?}",
                domain_id,
                err
            );
        }
    }
}
