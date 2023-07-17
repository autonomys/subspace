use domain_client_block_preprocessor::runtime_api::StateRootExtractor;
use domain_client_block_preprocessor::xdm_verifier::verify_xdm_with_consensus_client;
use sc_transaction_pool::error::Result as TxPoolResult;
use sc_transaction_pool_api::error::Error as TxPoolError;
use sc_transaction_pool_api::TransactionSource;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::SpawnNamed;
use sp_domains::{DomainId, DomainsApi};
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_transaction_pool::PreValidateTransaction;

pub struct DomainTxPreValidator<Block, CBlock, Client, CClient, SRE> {
    domain_id: DomainId,
    client: Arc<Client>,
    spawner: Box<dyn SpawnNamed>,
    consensus_client: Arc<CClient>,
    state_root_extractor: SRE,
    _phantom_data: PhantomData<(Block, CBlock)>,
}

impl<Block, CBlock, Client, CClient, SRE> Clone
    for DomainTxPreValidator<Block, CBlock, Client, CClient, SRE>
where
    SRE: Clone,
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            client: self.client.clone(),
            spawner: self.spawner.clone(),
            consensus_client: self.consensus_client.clone(),
            state_root_extractor: self.state_root_extractor.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, CBlock, Client, CClient, SRE>
    DomainTxPreValidator<Block, CBlock, Client, CClient, SRE>
{
    pub fn new(
        domain_id: DomainId,
        client: Arc<Client>,
        spawner: Box<dyn SpawnNamed>,
        consensus_client: Arc<CClient>,
        state_root_extractor: SRE,
    ) -> Self {
        Self {
            domain_id,
            client,
            spawner,
            consensus_client,
            state_root_extractor,
            _phantom_data: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl<Block, CBlock, Client, CClient, SRE> PreValidateTransaction
    for DomainTxPreValidator<Block, CBlock, Client, CClient, SRE>
where
    Block: BlockT,
    CBlock: BlockT,
    CBlock::Hash: From<Block::Hash>,
    NumberFor<CBlock>: From<NumberFor<Block>>,
    Client: ProvideRuntimeApi<Block> + Send + Sync,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + 'static,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>,
    SRE: StateRootExtractor<Block> + Send + Sync,
{
    type Block = Block;
    async fn pre_validate_transaction(
        &self,
        at: Block::Hash,
        _source: TransactionSource,
        uxt: Block::Extrinsic,
    ) -> TxPoolResult<()> {
        if !verify_xdm_with_consensus_client::<CClient, CBlock, Block, SRE>(
            self.domain_id,
            &self.consensus_client,
            at,
            &self.state_root_extractor,
            &uxt,
        )? {
            return Err(TxPoolError::ImmediatelyDropped.into());
        }

        Ok(())
    }
}
