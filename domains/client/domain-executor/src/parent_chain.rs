use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_domains::fraud_proof::FraudProof;
use sp_domains::{DomainId, ExecutorApi};
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;
use std::sync::Arc;
use system_runtime_primitives::SystemDomainApi;

/// Trait for interacting between the domain and its corresponding parent chain, i.e. retrieving
/// the necessary info from the parent chain or submit extrinsics to the parent chain.
///
/// - The parent chain of System Domain => Primary Chain
/// - The parent chain of Core Domain => System Domain
pub trait ParentChainInterface<Block: BlockT, ParentChainBlock: BlockT> {
    fn best_hash(&self) -> ParentChainBlock::Hash;

    fn head_receipt_number(
        &self,
        at: ParentChainBlock::Hash,
    ) -> Result<NumberFor<Block>, sp_api::ApiError>;

    fn maximum_receipt_drift(
        &self,
        at: ParentChainBlock::Hash,
    ) -> Result<NumberFor<Block>, sp_api::ApiError>;

    fn submit_fraud_proof_unsigned(
        &self,
        fraud_proof: FraudProof<NumberFor<ParentChainBlock>, ParentChainBlock::Hash>,
    ) -> Result<(), sp_api::ApiError>;
}

/// The parent chain of the core domain
pub struct CoreDomainParentChain<Block, SBlock, PBlock, SClient> {
    /// Core domain id
    domain_id: DomainId,
    system_domain_client: Arc<SClient>,
    _phantom: PhantomData<(Block, SBlock, PBlock)>,
}

impl<Block, SBlock, PBlock, SClient> Clone
    for CoreDomainParentChain<Block, SBlock, PBlock, SClient>
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            system_domain_client: self.system_domain_client.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<Block, SBlock, PBlock, SClient> CoreDomainParentChain<Block, SBlock, PBlock, SClient> {
    pub fn new(domain_id: DomainId, system_domain_client: Arc<SClient>) -> Self {
        Self {
            domain_id,
            system_domain_client,
            _phantom: PhantomData,
        }
    }
}

impl<Block, SBlock, PBlock, SClient> ParentChainInterface<Block, SBlock>
    for CoreDomainParentChain<Block, SBlock, PBlock, SClient>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
    NumberFor<SBlock>: Into<NumberFor<Block>>,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock>,
    SClient::Api: SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
{
    fn best_hash(&self) -> SBlock::Hash {
        self.system_domain_client.info().best_hash
    }

    fn head_receipt_number(&self, at: SBlock::Hash) -> Result<NumberFor<Block>, sp_api::ApiError> {
        let head_receipt_number = self
            .system_domain_client
            .runtime_api()
            .head_receipt_number(at, self.domain_id)?;
        Ok(head_receipt_number.into())
    }

    fn maximum_receipt_drift(
        &self,
        at: SBlock::Hash,
    ) -> Result<NumberFor<Block>, sp_api::ApiError> {
        let max_drift = self
            .system_domain_client
            .runtime_api()
            .maximum_receipt_drift(at)?;
        Ok(max_drift.into())
    }

    fn submit_fraud_proof_unsigned(
        &self,
        fraud_proof: FraudProof<NumberFor<SBlock>, SBlock::Hash>,
    ) -> Result<(), sp_api::ApiError> {
        let at = self.system_domain_client.info().best_hash;
        self.system_domain_client
            .runtime_api()
            .submit_fraud_proof_unsigned(at, fraud_proof)?;
        Ok(())
    }
}

/// The parent chain of the system domain
pub struct SystemDomainParentChain<Block, PBlock, PClient> {
    primary_chain_client: Arc<PClient>,
    _phantom: PhantomData<(Block, PBlock)>,
}

impl<Block, PBlock, PClient> Clone for SystemDomainParentChain<Block, PBlock, PClient> {
    fn clone(&self) -> Self {
        Self {
            primary_chain_client: self.primary_chain_client.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<Block, PBlock, PClient> SystemDomainParentChain<Block, PBlock, PClient> {
    pub fn new(primary_chain_client: Arc<PClient>) -> Self {
        Self {
            primary_chain_client,
            _phantom: PhantomData,
        }
    }
}

impl<Block, PBlock, PClient> ParentChainInterface<Block, PBlock>
    for SystemDomainParentChain<Block, PBlock, PClient>
where
    Block: BlockT,
    PBlock: BlockT,
    NumberFor<PBlock>: Into<NumberFor<Block>>,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock>,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
{
    fn best_hash(&self) -> PBlock::Hash {
        self.primary_chain_client.info().best_hash
    }

    fn head_receipt_number(&self, at: PBlock::Hash) -> Result<NumberFor<Block>, sp_api::ApiError> {
        let head_receipt_number = self
            .primary_chain_client
            .runtime_api()
            .head_receipt_number(at)?;
        Ok(head_receipt_number.into())
    }

    fn maximum_receipt_drift(
        &self,
        at: PBlock::Hash,
    ) -> Result<NumberFor<Block>, sp_api::ApiError> {
        let max_drift = self
            .primary_chain_client
            .runtime_api()
            .maximum_receipt_drift(at)?;
        Ok(max_drift.into())
    }

    fn submit_fraud_proof_unsigned(
        &self,
        fraud_proof: FraudProof<NumberFor<PBlock>, PBlock::Hash>,
    ) -> Result<(), sp_api::ApiError> {
        let at = self.primary_chain_client.info().best_hash;
        self.primary_chain_client
            .runtime_api()
            .submit_fraud_proof_unsigned(at, fraud_proof)?;
        Ok(())
    }
}
