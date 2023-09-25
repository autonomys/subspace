use sc_transaction_pool::error::Result as TxPoolResult;
use sc_transaction_pool_api::error::Error as TxPoolError;
use sc_transaction_pool_api::TransactionSource;
use sp_api::ProvideRuntimeApi;
use sp_core::traits::SpawnNamed;
use sp_domains::transaction::{
    InvalidTransactionCode, PreValidationObject, PreValidationObjectApi,
};
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_fraud_proof::VerifyFraudProof;
use subspace_transaction_pool::PreValidateTransaction;

pub struct ConsensusChainTxPreValidator<Block, DomainBlock, Client, Verifier> {
    client: Arc<Client>,
    spawner: Box<dyn SpawnNamed>,
    fraud_proof_verifier: Verifier,
    _phantom_data: PhantomData<(Block, DomainBlock)>,
}

impl<Block, DomainBlock, Client, Verifier> Clone
    for ConsensusChainTxPreValidator<Block, DomainBlock, Client, Verifier>
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

impl<Block, DomainBlock, Client, Verifier>
    ConsensusChainTxPreValidator<Block, DomainBlock, Client, Verifier>
{
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
impl<Block, DomainBlock, Client, Verifier> PreValidateTransaction
    for ConsensusChainTxPreValidator<Block, DomainBlock, Client, Verifier>
where
    Block: BlockT,
    DomainBlock: BlockT,
    Client: ProvideRuntimeApi<Block> + Send + Sync,
    Client::Api: PreValidationObjectApi<Block, NumberFor<DomainBlock>, DomainBlock::Hash>,
    Verifier: VerifyFraudProof<Block, DomainBlock> + Clone + Send + Sync + 'static,
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
            PreValidationObject::Bundle(_bundle) => {
                // TODO: perhaps move the bundle format check here
            }
            PreValidationObject::FraudProof(fraud_proof) => {
                subspace_fraud_proof::validate_fraud_proof_in_tx_pool::<Block, _, _>(
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
