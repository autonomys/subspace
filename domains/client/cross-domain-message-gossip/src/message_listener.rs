use futures::{Stream, StreamExt};
use sc_transaction_pool_api::{TransactionPool, TransactionSource, TxHash};
use sp_blockchain::HeaderBackend;
use sp_domains::DomainId;
use sp_runtime::codec::Decode;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

const LOG_TARGET: &str = "domain_message_listener";
type DomainBlockOf<T> = <T as TransactionPool>::Block;
type DomainExtrinsicOf<T> = <<T as TransactionPool>::Block as BlockT>::Extrinsic;

#[derive(Debug)]
enum Error<TxPoolError> {
    /// Failed to decode extrinsic.
    FailedToDecodeExtrinsic,
    /// Transaction Pool error.
    TxPool(TxPoolError),
}

/// Submits the encoded extrinsic to the provided tx pool.
async fn submit_one<Client, TxPool>(
    client: &Arc<Client>,
    pool: &Arc<TxPool>,
    ext_encoded: Vec<u8>,
) -> Result<TxHash<TxPool>, Error<TxPool::Error>>
where
    TxPool: TransactionPool + 'static,
    Client: HeaderBackend<DomainBlockOf<TxPool>>,
{
    let pool = pool.clone();
    let ext = DomainExtrinsicOf::<TxPool>::decode(&mut ext_encoded.as_ref())
        .map_err(|_| Error::FailedToDecodeExtrinsic)?;

    let at = BlockId::Hash(client.info().best_hash);
    pool.submit_one(&at, TransactionSource::External, ext)
        .await
        .map_err(Error::TxPool)
}

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
        let res = submit_one(&client, &tx_pool, encoded_ext).await;
        if let Err(err) = res {
            tracing::error!(
                target: LOG_TARGET,
                "Failed to submit extrinsic to tx pool for domain {:?} with error: {:?}",
                domain_id,
                err
            );
        }
    }
}
