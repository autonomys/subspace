use crate::ExecutionReceiptFor;
use sc_client_api::BlockBackend;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_domains::fraud_proof::FraudProof;
use sp_domains::DomainId;
use sp_runtime::traits::Block as BlockT;
use sp_settlement::SettlementApi;
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
    ) -> Result<Vec<ExecutionReceiptFor<ParentChainBlock, Block::Hash>>, sp_api::ApiError>;

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
pub struct DomainParentChain<Block, PBlock, PClient> {
    domain_id: DomainId,
    primary_chain_client: Arc<PClient>,
    _phantom: PhantomData<(Block, PBlock)>,
}

impl<Block, PBlock, PClient> Clone for DomainParentChain<Block, PBlock, PClient> {
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            primary_chain_client: self.primary_chain_client.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<Block, PBlock, PClient> DomainParentChain<Block, PBlock, PClient> {
    pub fn new(domain_id: DomainId, primary_chain_client: Arc<PClient>) -> Self {
        Self {
            domain_id,
            primary_chain_client,
            _phantom: PhantomData,
        }
    }
}

impl<Block, PBlock, PClient> ParentChainInterface<Block, PBlock>
    for DomainParentChain<Block, PBlock, PClient>
where
    Block: BlockT,
    PBlock: BlockT,
    NumberFor<PBlock>: Into<NumberFor<Block>>,
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock>,
    PClient::Api: SettlementApi<PBlock, Block::Hash>,
{
    fn best_hash(&self) -> PBlock::Hash {
        self.primary_chain_client.info().best_hash
    }

    fn block_body(&self, at: PBlock::Hash) -> sp_blockchain::Result<Vec<PBlock::Extrinsic>> {
        self.primary_chain_client.block_body(at)?.ok_or_else(|| {
            sp_blockchain::Error::Backend(format!("Primary block body for {at} not found"))
        })
    }

    fn oldest_receipt_number(
        &self,
        at: PBlock::Hash,
    ) -> Result<NumberFor<Block>, sp_api::ApiError> {
        let oldest_receipt_number = self
            .primary_chain_client
            .runtime_api()
            .oldest_receipt_number(at, self.domain_id)?;
        Ok(oldest_receipt_number.into())
    }

    fn head_receipt_number(&self, at: PBlock::Hash) -> Result<NumberFor<Block>, sp_api::ApiError> {
        let head_receipt_number = self
            .primary_chain_client
            .runtime_api()
            .head_receipt_number(at, self.domain_id)?;
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

    fn extract_receipts(
        &self,
        at: PBlock::Hash,
        extrinsics: Vec<PBlock::Extrinsic>,
    ) -> Result<Vec<ExecutionReceiptFor<PBlock, Block::Hash>>, sp_api::ApiError> {
        self.primary_chain_client
            .runtime_api()
            .extract_receipts(at, extrinsics, self.domain_id)
    }

    fn extract_fraud_proofs(
        &self,
        at: PBlock::Hash,
        extrinsics: Vec<PBlock::Extrinsic>,
    ) -> Result<Vec<FraudProofFor<PBlock>>, sp_api::ApiError> {
        self.primary_chain_client
            .runtime_api()
            .extract_fraud_proofs(at, extrinsics, self.domain_id)
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
