//! This module defines a trait for building the domain extrinsics from the original
//! primary block and provides the implementation for both system domain and core domain.

use domain_block_preprocessor::runtime_api_light::RuntimeApiLight;
use domain_block_preprocessor::DomainBlockPreprocessor;
use domain_runtime_primitives::opaque::Block;
use sc_client_api::{BlockBackend, HeaderBackend};
use sp_api::ProvideRuntimeApi;
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domains::{DomainId, ExecutorApi};
use sp_runtime::traits::Block as BlockT;
use sp_settlement::SettlementApi;
use std::marker::PhantomData;
use std::sync::Arc;

/// Trait to build the extrinsics of domain block derived from the original primary block.
pub trait BuildDomainExtrinsics<PBlock: BlockT> {
    /// Returns the final list of encoded domain-specific extrinsics.
    fn build_domain_extrinsics(
        &self,
        domain_id: DomainId,
        primary_hash: PBlock::Hash,
        domain_runtime: Vec<u8>,
    ) -> sp_blockchain::Result<Vec<Vec<u8>>>;
}

/// Utility to build the system domain extrinsics.
pub struct DomainExtrinsicsBuilder<PBlock, PClient, Executor> {
    primary_chain_client: Arc<PClient>,
    executor: Arc<Executor>,
    _phantom: PhantomData<PBlock>,
}

impl<PBlock, PClient, Executor> Clone for DomainExtrinsicsBuilder<PBlock, PClient, Executor> {
    fn clone(&self) -> Self {
        Self {
            primary_chain_client: self.primary_chain_client.clone(),
            executor: self.executor.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<PBlock, PClient, Executor> DomainExtrinsicsBuilder<PBlock, PClient, Executor>
where
    PBlock: BlockT,
    PBlock::Hash: From<H256>,
    PClient: HeaderBackend<PBlock>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, domain_runtime_primitives::Hash>
        + SettlementApi<PBlock, domain_runtime_primitives::Hash>,
    Executor: CodeExecutor,
{
    /// Constructs a new instance of [`DomainExtrinsicsBuilder`].
    pub fn new(primary_chain_client: Arc<PClient>, executor: Arc<Executor>) -> Self {
        Self {
            primary_chain_client,
            executor,
            _phantom: Default::default(),
        }
    }

    fn build_system_domain_extrinsics(
        &self,
        primary_hash: PBlock::Hash,
        runtime_code: Vec<u8>,
    ) -> sp_blockchain::Result<Vec<Vec<u8>>> {
        let system_runtime_api_light =
            RuntimeApiLight::new(self.executor.clone(), runtime_code.into());
        let domain_extrinsics = DomainBlockPreprocessor::<Block, _, _, _>::new(
            self.primary_chain_client.clone(),
            system_runtime_api_light,
        )
        .preprocess_primary_block_for_verifier(primary_hash)?;
        Ok(domain_extrinsics)
    }
}

impl<PBlock, PClient, Executor> BuildDomainExtrinsics<PBlock>
    for DomainExtrinsicsBuilder<PBlock, PClient, Executor>
where
    PBlock: BlockT,
    PBlock::Hash: From<H256>,
    PClient: HeaderBackend<PBlock>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, domain_runtime_primitives::Hash>
        + SettlementApi<PBlock, domain_runtime_primitives::Hash>,
    Executor: CodeExecutor,
{
    fn build_domain_extrinsics(
        &self,
        _domain_id: DomainId,
        primary_hash: <PBlock as BlockT>::Hash,
        domain_runtime: Vec<u8>,
    ) -> sp_blockchain::Result<Vec<Vec<u8>>> {
        self.build_system_domain_extrinsics(primary_hash, domain_runtime)
    }
}
