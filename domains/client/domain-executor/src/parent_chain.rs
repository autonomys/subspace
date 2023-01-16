use crate::utils::to_number_primitive;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::{HeaderBackend, Info};
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
pub(crate) trait ParentChainInterface<Block: BlockT> {
    fn info(&self) -> Info<Block>;
    fn head_receipt_number(&self, at: Block::Hash) -> Result<BlockNumber, sp_api::ApiError>;
    fn maximum_receipt_drift(&self, at: Block::Hash) -> Result<BlockNumber, sp_api::ApiError>;
    fn submit_fraud_proof_unsigned(&self, fraud_proof: FraudProof) -> Result<(), sp_api::ApiError>;
}

/// The parent chain of the core domain
pub struct CoreDomainParentChain<SClient, SBlock, PBlock> {
    system_domain_client: Arc<SClient>,
    // Core domain id
    domain_id: DomainId,
    _phantom: PhantomData<(SBlock, PBlock)>,
}

impl<SClient, SBlock, PBlock> Clone for CoreDomainParentChain<SClient, SBlock, PBlock> {
    fn clone(&self) -> Self {
        CoreDomainParentChain {
            system_domain_client: self.system_domain_client.clone(),
            domain_id: self.domain_id,
            _phantom: self._phantom,
        }
    }
}

impl<SBlock, PBlock, SClient> CoreDomainParentChain<SClient, SBlock, PBlock> {
    pub fn new(system_domain_client: Arc<SClient>, domain_id: DomainId) -> Self {
        CoreDomainParentChain {
            system_domain_client,
            domain_id,
            _phantom: PhantomData::default(),
        }
    }
}

impl<SBlock, PBlock, SClient> ParentChainInterface<SBlock>
    for CoreDomainParentChain<SClient, SBlock, PBlock>
where
    SBlock: BlockT,
    PBlock: BlockT,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock>,
    SClient::Api: SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
{
    fn info(&self) -> Info<SBlock> {
        self.system_domain_client.info()
    }

    fn head_receipt_number(&self, at: SBlock::Hash) -> Result<BlockNumber, sp_api::ApiError> {
        let head_receipt_number = self
            .system_domain_client
            .runtime_api()
            .head_receipt_number(&BlockId::Hash(at), self.domain_id)?;
        Ok(to_number_primitive(head_receipt_number))
    }

    fn maximum_receipt_drift(&self, at: SBlock::Hash) -> Result<BlockNumber, sp_api::ApiError> {
        let max_drift = self
            .system_domain_client
            .runtime_api()
            .maximum_receipt_drift(&BlockId::Hash(at))?;
        Ok(to_number_primitive(max_drift))
    }

    fn submit_fraud_proof_unsigned(&self, fraud_proof: FraudProof) -> Result<(), sp_api::ApiError> {
        let at = self.system_domain_client.info().best_hash;
        self.system_domain_client
            .runtime_api()
            .submit_fraud_proof_unsigned(&BlockId::Hash(at), fraud_proof)?;
        Ok(())
    }
}

/// The parent chain of the system domain
pub struct SystemDomainParentChain<PClient, Block, PBlock> {
    primary_chain_client: Arc<PClient>,
    _phantom: PhantomData<(Block, PBlock)>,
}

impl<PClient, Block, PBlock> Clone for SystemDomainParentChain<PClient, Block, PBlock> {
    fn clone(&self) -> Self {
        SystemDomainParentChain {
            primary_chain_client: self.primary_chain_client.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<PClient, Block, PBlock> SystemDomainParentChain<PClient, Block, PBlock> {
    pub fn new(primary_chain_client: Arc<PClient>) -> Self {
        SystemDomainParentChain {
            primary_chain_client,
            _phantom: PhantomData::default(),
        }
    }
}

impl<Block, PBlock, PClient> ParentChainInterface<PBlock>
    for SystemDomainParentChain<PClient, Block, PBlock>
where
    Block: BlockT,
    PBlock: BlockT,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock>,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
{
    fn info(&self) -> Info<PBlock> {
        self.primary_chain_client.info()
    }

    fn head_receipt_number(&self, at: PBlock::Hash) -> Result<BlockNumber, sp_api::ApiError> {
        let head_receipt_number = self
            .primary_chain_client
            .runtime_api()
            .head_receipt_number(&BlockId::Hash(at))?;
        Ok(to_number_primitive(head_receipt_number))
    }

    fn maximum_receipt_drift(&self, at: PBlock::Hash) -> Result<BlockNumber, sp_api::ApiError> {
        let max_drift = self
            .primary_chain_client
            .runtime_api()
            .maximum_receipt_drift(&BlockId::Hash(at))?;
        Ok(to_number_primitive(max_drift))
    }

    fn submit_fraud_proof_unsigned(&self, fraud_proof: FraudProof) -> Result<(), sp_api::ApiError> {
        let at = self.primary_chain_client.info().best_hash;
        self.primary_chain_client
            .runtime_api()
            .submit_fraud_proof_unsigned(&BlockId::Hash(at), fraud_proof)?;
        Ok(())
    }
}
