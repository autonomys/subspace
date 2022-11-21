use crate::system_domain::{FullClient, FullPool};
use crate::{CorePaymentsDomainExecutorDispatch, SystemDomainExecutorDispatch};
use codec::Decode;
use core_payments_domain_runtime::RuntimeApi as CorePaymentsRuntimeApi;
use frame_benchmarking::frame_support::inherent::BlockT;
use sc_transaction_pool_api::error::Error as TxPoolError;
use sc_transaction_pool_api::{PoolFuture, TransactionPool};
use sp_domains::DomainId;
use sp_runtime::generic::BlockId;
use sp_runtime::transaction_validity::TransactionSource;
use std::marker::PhantomData;
use std::sync::Arc;
use system_domain_runtime::RuntimeApi;

pub type SystemDomainTxPool = FullPool<FullClient<RuntimeApi, SystemDomainExecutorDispatch>>;
pub type CorePaymentsDomainTxPool =
    FullPool<FullClient<CorePaymentsRuntimeApi, CorePaymentsDomainExecutorDispatch>>;

pub struct DomainTransactionPoolWrapper<Hash> {
    _phantom_data: PhantomData<Hash>,
    pub system_domain_tx_pool: Option<Arc<SystemDomainTxPool>>,
    pub core_payments_domain_tx_pool: Option<Arc<CorePaymentsDomainTxPool>>,
}

type DomainExtrinsicOf<T> = <<T as TransactionPool>::Block as BlockT>::Extrinsic;

impl<Hash> Default for DomainTransactionPoolWrapper<Hash>
where
    Hash: Default,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Hash> DomainTransactionPoolWrapper<Hash>
where
    Hash: Default,
{
    pub fn new() -> Self {
        DomainTransactionPoolWrapper {
            _phantom_data: Default::default(),
            system_domain_tx_pool: None,
            core_payments_domain_tx_pool: None,
        }
    }

    pub fn submit_domain_extrinsic(
        &self,
        domain_id: DomainId,
        tx_source: TransactionSource,
        ext_encoded: Vec<u8>,
    ) -> PoolFuture<Hash, TxPoolError> {
        if domain_id.is_system() {
            return Self::submit_extrinsic_to_txpool(
                &self.system_domain_tx_pool,
                tx_source,
                ext_encoded,
            );
        }
        if domain_id == DomainId::CORE_PAYMENTS {
            return Self::submit_extrinsic_to_txpool(
                &self.core_payments_domain_tx_pool,
                tx_source,
                ext_encoded,
            );
        } else {
            Box::pin(async move { Err(TxPoolError::ImmediatelyDropped) })
        }
    }

    fn submit_extrinsic_to_txpool<TxPool: TransactionPool + 'static>(
        maybe_pool: &Option<Arc<TxPool>>,
        tx_source: TransactionSource,
        ext_encoded: Vec<u8>,
    ) -> PoolFuture<Hash, TxPoolError> {
        if let Some(pool) = maybe_pool {
            // TODO: get latest block id from the secondary client
            let pool = pool.clone();
            let at = BlockId::Hash(Default::default());
            let ext = match DomainExtrinsicOf::<TxPool>::decode(&mut ext_encoded.as_ref()) {
                Ok(ext) => ext,
                Err(_) => return Box::pin(async move { Err(TxPoolError::ImmediatelyDropped) }),
            };

            Box::pin(async move {
                let res = pool.submit_one(&at, tx_source, ext).await;
                // TODO: dont know what to do with tx hash of the domain pool yet
                match res {
                    Ok(_) => Ok(Default::default()),
                    Err(_err) => Err(TxPoolError::ImmediatelyDropped),
                }
            })
        } else {
            Box::pin(async move { Err(TxPoolError::ImmediatelyDropped) })
        }
    }
}
