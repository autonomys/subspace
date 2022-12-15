use crate::utils::to_number_primitive;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_domains::fraud_proof::FraudProof;
use sp_domains::{DomainId, ExecutorApi};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::BlockNumber;
use system_runtime_primitives::SystemDomainApi;

/// Trait for interacting between the domain and its corresponding parent chain, i.e. retrieving
/// the necessary info from the parent chain or submit extrinsics to the parent chain.
///
/// - The parent chain of System Domain => Primary Chain
/// - The parent chain of Core Domain => System Domain
pub(crate) trait ParentChainInterface<Hash> {
    fn head_receipt_number(&self, at: Hash) -> Result<BlockNumber, sp_api::ApiError>;
    fn maximum_receipt_drift(&self, at: Hash) -> Result<BlockNumber, sp_api::ApiError>;
    fn submit_fraud_proof_unsigned(
        &self,
        at: Hash,
        fraud_proof: FraudProof,
    ) -> Result<(), sp_api::ApiError>;
}

/// The parent chain of the core domain
pub struct CoreDomainParentChain<SClient, SBlock, PBlock> {
    // The system domain client
    client: Arc<SClient>,
    // The id of the core domain
    domain_id: DomainId,
    _phantom: PhantomData<(SBlock, PBlock)>,
}

impl<SBlock, PBlock, SClient> CoreDomainParentChain<SClient, SBlock, PBlock> {
    pub fn new(client: Arc<SClient>, domain_id: DomainId) -> Self {
        CoreDomainParentChain {
            client,
            domain_id,
            _phantom: PhantomData::default(),
        }
    }
}

impl<SBlock, PBlock, SClient> ParentChainInterface<SBlock::Hash>
    for CoreDomainParentChain<SClient, SBlock, PBlock>
where
    SBlock: BlockT,
    PBlock: BlockT,
    SClient: ProvideRuntimeApi<SBlock>,
    SClient::Api: SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
{
    fn head_receipt_number(&self, at: SBlock::Hash) -> Result<BlockNumber, sp_api::ApiError> {
        let head_receipt_number = self
            .client
            .runtime_api()
            .head_receipt_number(&BlockId::Hash(at), self.domain_id)?;
        Ok(to_number_primitive(head_receipt_number))
    }

    fn maximum_receipt_drift(&self, at: SBlock::Hash) -> Result<BlockNumber, sp_api::ApiError> {
        let max_drift = self
            .client
            .runtime_api()
            .maximum_receipt_drift(&BlockId::Hash(at))?;
        Ok(to_number_primitive(max_drift))
    }

    fn submit_fraud_proof_unsigned(
        &self,
        at: SBlock::Hash,
        fraud_proof: FraudProof,
    ) -> Result<(), sp_api::ApiError> {
        self.client
            .runtime_api()
            .submit_fraud_proof_unsigned(&BlockId::Hash(at), fraud_proof)?;
        Ok(())
    }
}

/// The parent chain of the system domain
pub struct SystemDomainParentChain<PClient, Block, PBlock> {
    // The primary chain client
    client: Arc<PClient>,
    _phantom: PhantomData<(Block, PBlock)>,
}

impl<PClient, Block, PBlock> SystemDomainParentChain<PClient, Block, PBlock> {
    pub fn new(client: Arc<PClient>) -> Self {
        SystemDomainParentChain {
            client,
            _phantom: PhantomData::default(),
        }
    }
}

impl<Block, PBlock, PClient> ParentChainInterface<PBlock::Hash>
    for SystemDomainParentChain<PClient, Block, PBlock>
where
    Block: BlockT,
    PBlock: BlockT,
    PClient: ProvideRuntimeApi<PBlock>,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
{
    fn head_receipt_number(&self, at: PBlock::Hash) -> Result<BlockNumber, sp_api::ApiError> {
        let head_receipt_number = self
            .client
            .runtime_api()
            .head_receipt_number(&BlockId::Hash(at))?;
        Ok(to_number_primitive(head_receipt_number))
    }

    fn maximum_receipt_drift(&self, at: PBlock::Hash) -> Result<BlockNumber, sp_api::ApiError> {
        let max_drift = self
            .client
            .runtime_api()
            .maximum_receipt_drift(&BlockId::Hash(at))?;
        Ok(to_number_primitive(max_drift))
    }

    fn submit_fraud_proof_unsigned(
        &self,
        at: PBlock::Hash,
        fraud_proof: FraudProof,
    ) -> Result<(), sp_api::ApiError> {
        self.client
            .runtime_api()
            .submit_fraud_proof_unsigned(&BlockId::Hash(at), fraud_proof)?;
        Ok(())
    }
}
