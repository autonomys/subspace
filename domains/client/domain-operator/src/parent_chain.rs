use crate::ExecutionReceiptFor;
use sc_client_api::BlockBackend;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_domains::fraud_proof::FraudProof;
use sp_domains::{DomainId, DomainsApi};
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;
use std::sync::Arc;

type FraudProofFor<ParentChainBlock> =
    FraudProof<NumberFor<ParentChainBlock>, <ParentChainBlock as BlockT>::Hash>;

/// Trait for interacting between the domain and its corresponding parent chain, i.e. retrieving
/// the necessary info from the parent chain or submit extrinsics to the parent chain.
pub trait ParentChainInterface<Block: BlockT, ParentChainBlock: BlockT> {
    fn best_hash(&self) -> ParentChainBlock::Hash;

    fn block_body(
        &self,
        at: ParentChainBlock::Hash,
    ) -> sp_blockchain::Result<Vec<ParentChainBlock::Extrinsic>>;

    fn oldest_receipt_number(
        &self,
        at: ParentChainBlock::Hash,
    ) -> Result<NumberFor<Block>, sp_api::ApiError>;

    fn head_receipt_number(
        &self,
        at: ParentChainBlock::Hash,
    ) -> Result<NumberFor<Block>, sp_api::ApiError>;

    fn maximum_receipt_drift(
        &self,
        at: ParentChainBlock::Hash,
    ) -> Result<NumberFor<Block>, sp_api::ApiError>;

    fn extract_receipts(
        &self,
        at: ParentChainBlock::Hash,
        extrinsics: Vec<ParentChainBlock::Extrinsic>,
    ) -> Result<Vec<ExecutionReceiptFor<Block, ParentChainBlock>>, sp_api::ApiError>;

    fn extract_fraud_proofs(
        &self,
        at: ParentChainBlock::Hash,
        extrinsics: Vec<ParentChainBlock::Extrinsic>,
    ) -> Result<Vec<FraudProofFor<ParentChainBlock>>, sp_api::ApiError>;

    fn submit_fraud_proof_unsigned(
        &self,
        fraud_proof: FraudProof<NumberFor<ParentChainBlock>, ParentChainBlock::Hash>,
    ) -> Result<(), sp_api::ApiError>;
}

/// The parent chain of the domain.
pub struct DomainParentChain<Block, CBlock, CClient> {
    domain_id: DomainId,
    consensus_client: Arc<CClient>,
    _phantom: PhantomData<(Block, CBlock)>,
}

impl<Block, CBlock, CClient> Clone for DomainParentChain<Block, CBlock, CClient> {
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            consensus_client: self.consensus_client.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<Block, CBlock, CClient> DomainParentChain<Block, CBlock, CClient> {
    pub fn new(domain_id: DomainId, consensus_client: Arc<CClient>) -> Self {
        Self {
            domain_id,
            consensus_client,
            _phantom: PhantomData,
        }
    }
}

impl<Block, CBlock, CClient> ParentChainInterface<Block, CBlock>
    for DomainParentChain<Block, CBlock, CClient>
where
    Block: BlockT,
    CBlock: BlockT,
    NumberFor<CBlock>: Into<NumberFor<Block>>,
    CClient: HeaderBackend<CBlock> + BlockBackend<CBlock> + ProvideRuntimeApi<CBlock>,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>,
{
    fn best_hash(&self) -> CBlock::Hash {
        self.consensus_client.info().best_hash
    }

    fn block_body(&self, at: CBlock::Hash) -> sp_blockchain::Result<Vec<CBlock::Extrinsic>> {
        self.consensus_client.block_body(at)?.ok_or_else(|| {
            sp_blockchain::Error::Backend(format!("Consensus block body for {at} not found"))
        })
    }

    fn oldest_receipt_number(
        &self,
        _at: CBlock::Hash,
    ) -> Result<NumberFor<Block>, sp_api::ApiError> {
        // TODO: Implement when block tree is ready.
        Ok(0u32.into())
        // let oldest_receipt_number = self
        // .consensus_client
        // .runtime_api()
        // .oldest_receipt_number(at, self.domain_id)?;
        // Ok(oldest_receipt_number.into())
    }

    fn head_receipt_number(&self, _at: CBlock::Hash) -> Result<NumberFor<Block>, sp_api::ApiError> {
        // TODO: Implement when block tree is ready.
        unimplemented!("Retrieve from consensus chain runtime")
        // let head_receipt_number = self
        // .consensus_client
        // .runtime_api()
        // .head_receipt_number(at, self.domain_id)?;
        // Ok(head_receipt_number.into())
    }

    fn maximum_receipt_drift(
        &self,
        _at: CBlock::Hash,
    ) -> Result<NumberFor<Block>, sp_api::ApiError> {
        // TODO: Implement when block tree is ready.
        Ok(256u32.into())
        // let max_drift = self
        // .consensus_client
        // .runtime_api()
        // .maximum_receipt_drift(at)?;
        // Ok(max_drift.into())
    }

    fn extract_receipts(
        &self,
        _at: CBlock::Hash,
        _extrinsics: Vec<CBlock::Extrinsic>,
    ) -> Result<Vec<ExecutionReceiptFor<Block, CBlock>>, sp_api::ApiError> {
        // TODO: Implement when proceeding to fraud proof v2.
        Ok(Vec::new())
        // self.consensus_client
        // .runtime_api()
        // .extract_receipts(at, extrinsics, self.domain_id)
    }

    fn extract_fraud_proofs(
        &self,
        _at: CBlock::Hash,
        _extrinsics: Vec<CBlock::Extrinsic>,
    ) -> Result<Vec<FraudProofFor<CBlock>>, sp_api::ApiError> {
        // TODO: Implement when proceeding to fraud proof v2.
        Ok(Vec::new())
        // self.consensus_client
        // .runtime_api()
        // .extract_fraud_proofs(at, extrinsics, self.domain_id)
    }

    fn submit_fraud_proof_unsigned(
        &self,
        _fraud_proof: FraudProof<NumberFor<CBlock>, CBlock::Hash>,
    ) -> Result<(), sp_api::ApiError> {
        // TODO: Implement when proceeding to fraud proof v2.
        // let at = self.consensus_client.info().best_hash;
        // self.consensus_client
        // .runtime_api()
        // .submit_fraud_proof_unsigned(at, fraud_proof)?;
        Ok(())
    }
}
