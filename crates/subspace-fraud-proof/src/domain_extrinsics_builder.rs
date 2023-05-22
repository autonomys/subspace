//! This module defines a trait for building the domain extrinsics from the original
//! primary block and provides the implementation for both system domain and core domain.

use domain_block_preprocessor::runtime_api_light::RuntimeApiLight;
use domain_block_preprocessor::{CoreDomainBlockPreprocessor, SystemDomainBlockPreprocessor};
use domain_runtime_primitives::opaque::Block;
use sc_client_api::{BlockBackend, HeaderBackend};
use sp_api::{CallApiAt, ProvideRuntimeApi};
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domains::{DomainId, ExecutorApi};
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::marker::PhantomData;
use std::sync::Arc;
use system_runtime_primitives::SystemDomainApi;

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
pub struct SystemDomainExtrinsicsBuilder<PBlock, PClient, Executor> {
    primary_chain_client: Arc<PClient>,
    executor: Arc<Executor>,
    _phantom: PhantomData<PBlock>,
}

impl<PBlock, PClient, Executor> SystemDomainExtrinsicsBuilder<PBlock, PClient, Executor>
where
    PBlock: BlockT,
    PBlock::Hash: From<H256>,
    PClient: HeaderBackend<PBlock>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, domain_runtime_primitives::Hash>,
    Executor: CodeExecutor,
{
    /// Constructs a new instance of [`SystemDomainExtrinsicsBuilder`].
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
        let domain_extrinsics = SystemDomainBlockPreprocessor::<Block, _, _, _>::new(
            self.primary_chain_client.clone(),
            system_runtime_api_light,
        )
        .preprocess_primary_block_for_verifier(primary_hash)?;
        Ok(domain_extrinsics)
    }
}

impl<PBlock, PClient, Executor> BuildDomainExtrinsics<PBlock>
    for SystemDomainExtrinsicsBuilder<PBlock, PClient, Executor>
where
    PBlock: BlockT,
    PBlock::Hash: From<H256>,
    PClient: HeaderBackend<PBlock>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, domain_runtime_primitives::Hash>,
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

/// Utility to build the core domain extrinsics.
pub struct CoreDomainExtrinsicsBuilder<PBlock, SBlock, PClient, SClient, Executor> {
    primary_chain_client: Arc<PClient>,
    system_domain_client: Arc<SClient>,
    executor: Arc<Executor>,
    _phantom: PhantomData<(PBlock, SBlock)>,
}

impl<PBlock, SBlock, PClient, SClient, Executor>
    CoreDomainExtrinsicsBuilder<PBlock, SBlock, PClient, SClient, Executor>
where
    PBlock: BlockT,
    PBlock::Hash: From<H256>,
    SBlock: BlockT,
    NumberFor<SBlock>: From<NumberFor<Block>>,
    SBlock::Hash: From<<Block as BlockT>::Hash>,
    PClient: HeaderBackend<PBlock>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + CallApiAt<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, <Block as BlockT>::Hash>,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api: SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>
        + MessengerApi<SBlock, NumberFor<SBlock>>,
    Executor: CodeExecutor,
{
    /// Constructs a new instance of [`CoreDomainExtrinsicsBuilder`].
    pub fn new(
        primary_chain_client: Arc<PClient>,
        system_domain_client: Arc<SClient>,
        executor: Arc<Executor>,
    ) -> Self {
        Self {
            primary_chain_client,
            system_domain_client,
            executor,
            _phantom: Default::default(),
        }
    }

    fn build_core_domain_extrinsics(
        &self,
        domain_id: DomainId,
        primary_hash: PBlock::Hash,
        runtime_code: Vec<u8>,
    ) -> sp_blockchain::Result<Vec<Vec<u8>>> {
        let core_runtime_api_light =
            RuntimeApiLight::new(self.executor.clone(), runtime_code.into());
        let domain_extrinsics = CoreDomainBlockPreprocessor::<Block, _, _, _, _, _>::new(
            domain_id,
            core_runtime_api_light,
            self.primary_chain_client.clone(),
            self.system_domain_client.clone(),
        )
        .preprocess_primary_block_for_verifier(primary_hash)?;
        Ok(domain_extrinsics)
    }
}

impl<PBlock, SBlock, PClient, SClient, Executor> BuildDomainExtrinsics<PBlock>
    for CoreDomainExtrinsicsBuilder<PBlock, SBlock, PClient, SClient, Executor>
where
    PBlock: BlockT,
    PBlock::Hash: From<H256>,
    SBlock: BlockT,
    NumberFor<SBlock>: From<NumberFor<Block>>,
    SBlock::Hash: From<<Block as BlockT>::Hash>,
    PClient: HeaderBackend<PBlock>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + CallApiAt<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, <Block as BlockT>::Hash>,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api: SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>
        + MessengerApi<SBlock, NumberFor<SBlock>>,
    Executor: CodeExecutor,
{
    fn build_domain_extrinsics(
        &self,
        domain_id: DomainId,
        primary_hash: <PBlock as BlockT>::Hash,
        domain_runtime: Vec<u8>,
    ) -> sp_blockchain::Result<Vec<Vec<u8>>> {
        self.build_core_domain_extrinsics(domain_id, primary_hash, domain_runtime)
    }
}
