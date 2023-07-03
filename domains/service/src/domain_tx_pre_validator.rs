use domain_client_block_preprocessor::runtime_api::StateRootExtractor;
use domain_client_block_preprocessor::xdm_verifier::verify_xdm_with_primary_chain_client;
use sc_transaction_pool::error::Result as TxPoolResult;
use sc_transaction_pool_api::error::Error as TxPoolError;
use sc_transaction_pool_api::TransactionSource;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::SpawnNamed;
use sp_domains::{DomainId, ExecutorApi};
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_transaction_pool::PreValidateTransaction;

pub struct DomainTxPreValidator<Block, PBlock, Client, PClient, SRE> {
    domain_id: DomainId,
    client: Arc<Client>,
    spawner: Box<dyn SpawnNamed>,
    primary_chain_client: Arc<PClient>,
    state_root_extractor: SRE,
    _phantom_data: PhantomData<(Block, PBlock)>,
}

impl<Block, PBlock, Client, PClient, SRE> Clone
    for DomainTxPreValidator<Block, PBlock, Client, PClient, SRE>
where
    SRE: Clone,
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            client: self.client.clone(),
            spawner: self.spawner.clone(),
            primary_chain_client: self.primary_chain_client.clone(),
            state_root_extractor: self.state_root_extractor.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, PBlock, Client, PClient, SRE>
    DomainTxPreValidator<Block, PBlock, Client, PClient, SRE>
{
    pub fn new(
        domain_id: DomainId,
        client: Arc<Client>,
        spawner: Box<dyn SpawnNamed>,
        primary_chain_client: Arc<PClient>,
        state_root_extractor: SRE,
    ) -> Self {
        Self {
            domain_id,
            client,
            spawner,
            primary_chain_client,
            state_root_extractor,
            _phantom_data: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl<Block, PBlock, Client, PClient, SRE> PreValidateTransaction
    for DomainTxPreValidator<Block, PBlock, Client, PClient, SRE>
where
    Block: BlockT,
    PBlock: BlockT,
    PBlock::Hash: From<Block::Hash>,
    NumberFor<PBlock>: From<NumberFor<Block>>,
    Client: ProvideRuntimeApi<Block> + Send + Sync,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    SRE: StateRootExtractor<Block> + Send + Sync,
{
    type Block = Block;
    async fn pre_validate_transaction(
        &self,
        at: Block::Hash,
        _source: TransactionSource,
        uxt: Block::Extrinsic,
    ) -> TxPoolResult<()> {
        if !verify_xdm_with_primary_chain_client::<PClient, PBlock, Block, SRE>(
            self.domain_id,
            &self.primary_chain_client,
            at,
            &self.state_root_extractor,
            &uxt,
        )? {
            return Err(TxPoolError::ImmediatelyDropped.into());
        }

        Ok(())
    }
}
