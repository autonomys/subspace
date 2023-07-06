use domain_runtime_primitives::{BlockNumber as DomainNumber, Hash as DomainHash};
use sc_transaction_pool::error::Result as TxPoolResult;
use sc_transaction_pool_api::error::Error as TxPoolError;
use sc_transaction_pool_api::TransactionSource;
use sp_api::ProvideRuntimeApi;
use sp_core::traits::SpawnNamed;
use sp_domains::transaction::{
    InvalidTransactionCode, PreValidationObject, PreValidationObjectApi,
};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_fraud_proof::VerifyFraudProof;
use subspace_transaction_pool::bundle_validator::ValidateBundle;
use subspace_transaction_pool::PreValidateTransaction;

pub struct ConsensusChainTxPreValidator<Block, Client, Verifier, BundleValidator> {
    client: Arc<Client>,
    spawner: Box<dyn SpawnNamed>,
    fraud_proof_verifier: Verifier,
    bundle_validator: BundleValidator,
    _phantom_data: PhantomData<Block>,
}

impl<Block, Client, Verifier, BundleValidator> Clone
    for ConsensusChainTxPreValidator<Block, Client, Verifier, BundleValidator>
where
    Verifier: Clone,
    BundleValidator: Clone,
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            spawner: self.spawner.clone(),
            fraud_proof_verifier: self.fraud_proof_verifier.clone(),
            bundle_validator: self.bundle_validator.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, Client, Verifier, BundleValidator>
    ConsensusChainTxPreValidator<Block, Client, Verifier, BundleValidator>
{
    pub fn new(
        client: Arc<Client>,
        spawner: Box<dyn SpawnNamed>,
        fraud_proof_verifier: Verifier,
        bundle_validator: BundleValidator,
    ) -> Self {
        Self {
            client,
            spawner,
            fraud_proof_verifier,
            bundle_validator,
            _phantom_data: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl<Block, Client, Verifier, BundleValidator> PreValidateTransaction
    for ConsensusChainTxPreValidator<Block, Client, Verifier, BundleValidator>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + Send + Sync,
    Client::Api: PreValidationObjectApi<Block, DomainNumber, DomainHash>,
    Verifier: VerifyFraudProof<Block> + Clone + Send + Sync + 'static,
    BundleValidator:
        ValidateBundle<Block, DomainNumber, DomainHash> + Clone + Send + Sync + 'static,
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
            PreValidationObject::Null => {
                // No pre-validation is required.
            }
            PreValidationObject::Bundle(bundle) => {
                if let Err(err) = self
                    .bundle_validator
                    .validate_bundle(&BlockId::Hash(at), &bundle)
                {
                    tracing::trace!(target: "txpool", error = ?err, "Dropped `submit_bundle` extrinsic");
                    return Err(TxPoolError::ImmediatelyDropped.into());
                }
            }
            PreValidationObject::FraudProof(fraud_proof) => {
                subspace_fraud_proof::validate_fraud_proof_in_tx_pool(
                    &self.spawner,
                    self.fraud_proof_verifier.clone(),
                    fraud_proof,
                )
                .await
                .map_err(|err| {
                    tracing::debug!(target: "txpool", error = ?err, "Invalid fraud proof");
                    TxPoolError::InvalidTransaction(InvalidTransactionCode::FraudProof.into())
                })?;
            }
        }

        Ok(())
    }
}
