use crate::system_domain::{FullClient, FullPool};
use crate::{CorePaymentsDomainExecutorDispatch, SystemDomainExecutorDispatch};
use codec::Decode;
use core_payments_domain_runtime::RuntimeApi as CorePaymentsRuntimeApi;
use frame_benchmarking::frame_support::inherent::BlockT;
use sc_transaction_pool_api::error::Error as TxPoolError;
use sc_transaction_pool_api::{PoolFuture, TransactionPool, TxHash};
use sp_blockchain::HeaderBackend;
use sp_domains::DomainId;
use sp_runtime::generic::BlockId;
use sp_runtime::transaction_validity::TransactionSource;
use std::marker::PhantomData;
use std::sync::Arc;
use system_domain_runtime::RuntimeApi;

pub type SystemDomainTxPool = FullPool<FullClient<RuntimeApi, SystemDomainExecutorDispatch>>;
pub type CorePaymentsDomainTxPool =
    FullPool<FullClient<CorePaymentsRuntimeApi, CorePaymentsDomainExecutorDispatch>>;

type SystemDomainComponent = (
    Arc<FullClient<RuntimeApi, SystemDomainExecutorDispatch>>,
    Arc<SystemDomainTxPool>,
);

type CorePaymentsDomainComponent = (
    Arc<FullClient<CorePaymentsRuntimeApi, CorePaymentsDomainExecutorDispatch>>,
    Arc<CorePaymentsDomainTxPool>,
);

/// Routes the Extrinsics bound to specific domain_id.
pub struct DomainTransactionPoolRouter<Hash> {
    _phantom_data: PhantomData<Hash>,
    pub system_domain: Option<SystemDomainComponent>,
    pub core_payments_domain: Option<CorePaymentsDomainComponent>,
}

type DomainBlockOf<T> = <T as TransactionPool>::Block;
type DomainExtrinsicOf<T> = <<T as TransactionPool>::Block as BlockT>::Extrinsic;

impl<Hash> Default for DomainTransactionPoolRouter<Hash>
where
    Hash: Default + From<TxHash<SystemDomainTxPool>> + From<TxHash<CorePaymentsDomainTxPool>>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Hash> DomainTransactionPoolRouter<Hash>
where
    Hash: Default + From<TxHash<SystemDomainTxPool>> + From<TxHash<CorePaymentsDomainTxPool>>,
{
    pub fn new() -> Self {
        DomainTransactionPoolRouter {
            _phantom_data: Default::default(),
            system_domain: None,
            core_payments_domain: None,
        }
    }

    pub fn submit_domain_extrinsic(
        &self,
        domain_id: DomainId,
        tx_source: TransactionSource,
        ext_encoded: Vec<u8>,
    ) -> PoolFuture<Hash, TxPoolError> {
        if domain_id.is_system() {
            Self::submit_extrinsic_to_txpool(&self.system_domain, tx_source, ext_encoded)
        } else if domain_id == DomainId::CORE_PAYMENTS {
            Self::submit_extrinsic_to_txpool(&self.core_payments_domain, tx_source, ext_encoded)
        } else {
            Box::pin(async move { Err(TxPoolError::ImmediatelyDropped) })
        }
    }

    fn submit_extrinsic_to_txpool<Client, TxPool>(
        maybe_client_and_pool: &Option<(Arc<Client>, Arc<TxPool>)>,
        tx_source: TransactionSource,
        ext_encoded: Vec<u8>,
    ) -> PoolFuture<Hash, TxPoolError>
    where
        TxPool: TransactionPool + 'static,
        Client: HeaderBackend<DomainBlockOf<TxPool>>,
        Hash: From<TxHash<TxPool>>,
    {
        if let Some((client, pool)) = maybe_client_and_pool {
            let pool = pool.clone();
            let ext = match DomainExtrinsicOf::<TxPool>::decode(&mut ext_encoded.as_ref()) {
                Ok(ext) => ext,
                Err(_) => return Box::pin(async move { Err(TxPoolError::ImmediatelyDropped) }),
            };

            let at = BlockId::Hash(client.info().best_hash);
            Box::pin(async move {
                let res = pool.submit_one(&at, tx_source, ext).await;
                match res {
                    Ok(hash) => Ok(hash.into()),
                    Err(_err) => Err(TxPoolError::ImmediatelyDropped),
                }
            })
        } else {
            Box::pin(async move { Err(TxPoolError::ImmediatelyDropped) })
        }
    }
}
