use domain_client_block_preprocessor::xdm_verifier::verify_xdm_with_system_domain_client;
use sc_transaction_pool::error::Result as TxPoolResult;
use sc_transaction_pool_api::error::Error as TxPoolError;
use sc_transaction_pool_api::TransactionSource;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_transaction_pool::PreValidateTransaction;
use system_runtime_primitives::SystemDomainApi;

pub struct CoreDomainTxPreValidator<Block, SBlock, PBlock, SClient> {
    system_domain_client: Arc<SClient>,
    _phantom_data: PhantomData<(Block, SBlock, PBlock)>,
}

impl<Block, SBlock, PBlock, SClient> Clone
    for CoreDomainTxPreValidator<Block, SBlock, PBlock, SClient>
{
    fn clone(&self) -> Self {
        Self {
            system_domain_client: self.system_domain_client.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, SBlock, PBlock, SClient> CoreDomainTxPreValidator<Block, SBlock, PBlock, SClient> {
    pub fn new(system_domain_client: Arc<SClient>) -> Self {
        Self {
            system_domain_client,
            _phantom_data: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl<Block, SBlock, PBlock, SClient> PreValidateTransaction
    for CoreDomainTxPreValidator<Block, SBlock, PBlock, SClient>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
    Block::Extrinsic: Into<SBlock::Extrinsic>,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + Send + Sync + 'static,
    SClient::Api: MessengerApi<SBlock, NumberFor<SBlock>>
        + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
{
    type Block = Block;
    async fn pre_validate_transaction(
        &self,
        _at: Block::Hash,
        _source: TransactionSource,
        uxt: Block::Extrinsic,
    ) -> TxPoolResult<()> {
        if !verify_xdm_with_system_domain_client::<_, Block, SBlock, PBlock>(
            &self.system_domain_client,
            &(uxt.into()),
        )? {
            return Err(TxPoolError::ImmediatelyDropped.into());
        }
        Ok(())
    }
}
