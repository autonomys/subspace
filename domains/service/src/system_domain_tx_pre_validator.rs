use futures::channel::oneshot;
use futures::future::FutureExt;
use sc_transaction_pool::error::Result as TxPoolResult;
use sc_transaction_pool_api::error::Error as TxPoolError;
use sc_transaction_pool_api::TransactionSource;
use sp_api::ProvideRuntimeApi;
use sp_core::traits::SpawnNamed;
use sp_domains::transaction::{
    InvalidTransactionCode, PreValidationObject, PreValidationObjectApi,
};
use sp_runtime::traits::Block as BlockT;
use sp_runtime::transaction_validity::UnknownTransaction;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_fraud_proof::VerifyFraudProof;
use subspace_transaction_pool::PreValidateTransaction;

pub struct SystemDomainTxPreValidator<Block, Client, Verifier> {
    client: Arc<Client>,
    spawner: Box<dyn SpawnNamed>,
    fraud_proof_verifier: Verifier,
    _phantom_data: PhantomData<Block>,
}

impl<Block, Client, Verifier> Clone for SystemDomainTxPreValidator<Block, Client, Verifier>
where
    Verifier: Clone,
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            spawner: self.spawner.clone(),
            fraud_proof_verifier: self.fraud_proof_verifier.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, Client, Verifier> SystemDomainTxPreValidator<Block, Client, Verifier> {
    pub fn new(
        client: Arc<Client>,
        spawner: Box<dyn SpawnNamed>,
        fraud_proof_verifier: Verifier,
    ) -> Self {
        Self {
            client,
            spawner,
            fraud_proof_verifier,
            _phantom_data: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl<Block, Client, Verifier> PreValidateTransaction
    for SystemDomainTxPreValidator<Block, Client, Verifier>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + Send + Sync,
    Client::Api: PreValidationObjectApi<Block, domain_runtime_primitives::Hash>,
    Verifier: VerifyFraudProof<Block> + Clone + Send + Sync + 'static,
{
    type Block = Block;
    async fn pre_validate_transaction(
        &self,
        at: Block::Hash,
        _source: TransactionSource,
        uxt: Block::Extrinsic,
    ) -> TxPoolResult<()> {
        let pre_validation_object = self
            .client
            .runtime_api()
            .extract_pre_validation_object(at, uxt.clone())
            .map_err(|err| sc_transaction_pool::error::Error::Blockchain(err.into()))?;

        match pre_validation_object {
            PreValidationObject::Null | PreValidationObject::Bundle(_) => {
                // No pre-validation is required.
            }
            PreValidationObject::FraudProof(fraud_proof) => {
                let spawner = self.spawner.clone();
                let fraud_proof_verifier = self.fraud_proof_verifier.clone();

                let (verified_result_sender, verified_result_receiver) = oneshot::channel();

                // Verify the fraud proof in another blocking task as it might be pretty heavy.
                spawner.spawn_blocking(
                    "txpool-fraud-proof-verification",
                    None,
                    async move {
                        let verified_result = fraud_proof_verifier.verify_fraud_proof(&fraud_proof);
                        verified_result_sender
                            .send(verified_result)
                            .expect("Failed to send the verified fraud proof result");
                    }
                    .boxed(),
                );

                match verified_result_receiver.await {
                    Ok(verified_result) => {
                        match verified_result {
                            Ok(_) => {
                                // Continue the regular `validate_transaction`
                            }
                            Err(err) => {
                                tracing::debug!(target: "txpool", error = ?err, "Invalid fraud proof");
                                return Err(TxPoolError::InvalidTransaction(
                                    InvalidTransactionCode::FraudProof.into(),
                                )
                                .into());
                            }
                        }
                    }
                    Err(err) => {
                        tracing::debug!(target: "txpool", error = ?err, "Failed to receive the fraud proof verified result");
                        return Err(TxPoolError::UnknownTransaction(
                            UnknownTransaction::CannotLookup,
                        )
                        .into());
                    }
                }
            }
        }

        Ok(())
    }
}
