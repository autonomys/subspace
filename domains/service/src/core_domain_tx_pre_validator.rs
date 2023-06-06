use domain_client_block_preprocessor::runtime_api_full::RuntimeApiFull;
use domain_client_block_preprocessor::xdm_verifier::verify_xdm_with_system_domain_client;
use sc_transaction_pool::error::Result as TxPoolResult;
use sc_transaction_pool_api::error::Error as TxPoolError;
use sc_transaction_pool_api::TransactionSource;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use sp_settlement::SettlementApi;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_transaction_pool::PreValidateTransaction;

pub struct CoreDomainTxPreValidator<Block, SBlock, PBlock, Client, SClient> {
    system_domain_client: Arc<SClient>,
    domain_client: RuntimeApiFull<Client>,
    _phantom_data: PhantomData<(Block, SBlock, PBlock)>,
}

impl<Block, SBlock, PBlock, Client, SClient> Clone
    for CoreDomainTxPreValidator<Block, SBlock, PBlock, Client, SClient>
{
    fn clone(&self) -> Self {
        Self {
            system_domain_client: self.system_domain_client.clone(),
            domain_client: self.domain_client.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, SBlock, PBlock, Client, SClient>
    CoreDomainTxPreValidator<Block, SBlock, PBlock, Client, SClient>
{
    pub fn new(client: Arc<Client>, system_domain_client: Arc<SClient>) -> Self {
        Self {
            system_domain_client,
            domain_client: RuntimeApiFull::new(client),
            _phantom_data: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl<Block, SBlock, PBlock, Client, SClient> PreValidateTransaction
    for CoreDomainTxPreValidator<Block, SBlock, PBlock, Client, SClient>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
    SBlock::Hash: From<Block::Hash>,
    NumberFor<SBlock>: From<NumberFor<Block>>,
    Client: ProvideRuntimeApi<Block> + Send + Sync + 'static,
    Client::Api: MessengerApi<Block, NumberFor<Block>>,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + Send + Sync + 'static,
    SClient::Api: MessengerApi<SBlock, NumberFor<SBlock>> + SettlementApi<SBlock, Block::Hash>,
{
    type Block = Block;
    async fn pre_validate_transaction(
        &self,
        at: Block::Hash,
        _source: TransactionSource,
        uxt: Block::Extrinsic,
    ) -> TxPoolResult<()> {
        if !verify_xdm_with_system_domain_client::<_, Block, SBlock, PBlock, _>(
            &self.system_domain_client,
            at,
            &uxt,
            &self.domain_client,
        )? {
            return Err(TxPoolError::ImmediatelyDropped.into());
        }
        Ok(())
    }
}
