//! This module defines a trait for building the domain extrinsics from the original
//! primary block and provides the implementation for both system domain and core domain.

use domain_block_preprocessor::runtime_api_light::RuntimeApiLight;
use domain_block_preprocessor::DomainBlockPreprocessor;
use domain_runtime_primitives::opaque::Block;
use sc_client_api::{BlockBackend, HeaderBackend};
use sp_api::ProvideRuntimeApi;
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domains::{DomainId, DomainsApi};
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;
use std::sync::Arc;

/// Trait to build the extrinsics of domain block derived from the original primary block.
pub trait BuildDomainExtrinsics<CBlock: BlockT> {
    /// Returns the final list of encoded domain-specific extrinsics.
    fn build_domain_extrinsics(
        &self,
        domain_id: DomainId,
        consensus_block_hash: CBlock::Hash,
        domain_runtime: Vec<u8>,
    ) -> sp_blockchain::Result<Vec<Vec<u8>>>;
}

/// Utility to build the system domain extrinsics.
pub struct DomainExtrinsicsBuilder<CBlock, PClient, Executor> {
    consensus_client: Arc<PClient>,
    executor: Arc<Executor>,
    _phantom: PhantomData<CBlock>,
}

impl<CBlock, PClient, Executor> Clone for DomainExtrinsicsBuilder<CBlock, PClient, Executor> {
    fn clone(&self) -> Self {
        Self {
            consensus_client: self.consensus_client.clone(),
            executor: self.executor.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<CBlock, PClient, Executor> DomainExtrinsicsBuilder<CBlock, PClient, Executor>
where
    CBlock: BlockT,
    CBlock::Hash: From<H256>,
    PClient: HeaderBackend<CBlock>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api:
        DomainsApi<CBlock, domain_runtime_primitives::BlockNumber, domain_runtime_primitives::Hash>,
    Executor: CodeExecutor,
{
    /// Constructs a new instance of [`DomainExtrinsicsBuilder`].
    pub fn new(consensus_client: Arc<PClient>, executor: Arc<Executor>) -> Self {
        Self {
            consensus_client,
            executor,
            _phantom: Default::default(),
        }
    }
}

impl<CBlock, PClient, Executor> BuildDomainExtrinsics<CBlock>
    for DomainExtrinsicsBuilder<CBlock, PClient, Executor>
where
    CBlock: BlockT,
    CBlock::Hash: From<H256>,
    PClient: HeaderBackend<CBlock>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api:
        DomainsApi<CBlock, domain_runtime_primitives::BlockNumber, domain_runtime_primitives::Hash>,
    Executor: CodeExecutor,
{
    fn build_domain_extrinsics(
        &self,
        domain_id: DomainId,
        consensus_block_hash: <CBlock as BlockT>::Hash,
        domain_runtime: Vec<u8>,
    ) -> sp_blockchain::Result<Vec<Vec<u8>>> {
        let domain_runtime_api_light =
            RuntimeApiLight::new(self.executor.clone(), domain_runtime.into());
        let domain_extrinsics = DomainBlockPreprocessor::<Block, _, _, _>::new(
            domain_id,
            self.consensus_client.clone(),
            domain_runtime_api_light,
        )
        .preprocess_consensus_block_for_verifier(consensus_block_hash)?;
        Ok(domain_extrinsics)
    }
}
