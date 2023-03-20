use codec::{Decode, Encode};
use sc_executor::RuntimeVersionOf;
use sp_api::{ApiError, BlockT, Core, ProvideRuntimeApi, RuntimeVersion};
use sp_blockchain::HeaderBackend;
use sp_core::traits::{CallContext, CodeExecutor, FetchRuntimeCode, RuntimeCode};
use sp_core::{ExecutionContext, Hasher};
use sp_messenger::messages::ExtractedStateRootsFromProof;
use sp_messenger::MessengerApi;
use sp_runtime::traits::NumberFor;
use sp_state_machine::BasicExternalities;
use std::borrow::Cow;
use std::sync::Arc;

type ExtractedStateRoots<Block> = ExtractedStateRootsFromProof<
    NumberFor<Block>,
    <Block as BlockT>::Hash,
    <Block as BlockT>::Hash,
>;

/// Trait to extract XDM state roots from the Extrinsic.
pub trait StateRootExtractor<Block: BlockT> {
    /// Provides the known correct hash of the chain to decode the extrinsic.
    fn block_hash(&self) -> Block::Hash;

    /// Extracts the state roots from the extrinsic.
    fn extract_state_roots(
        &self,
        at: Block::Hash,
        ext: &Block::Extrinsic,
    ) -> Result<ExtractedStateRoots<Block>, ApiError>;
}

/// Implementation of state root extractor with system domain client.
pub struct StateRootExtractorWithSystemDomainClient<SClient> {
    client: Arc<SClient>,
}

impl<SClient> StateRootExtractorWithSystemDomainClient<SClient> {
    pub fn new(client: Arc<SClient>) -> Self {
        Self { client }
    }
}

impl<SClient> Clone for StateRootExtractorWithSystemDomainClient<SClient> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
        }
    }
}

impl<SClient, SBlock> StateRootExtractor<SBlock>
    for StateRootExtractorWithSystemDomainClient<SClient>
where
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock>,
    SClient::Api: MessengerApi<SBlock, NumberFor<SBlock>>,
    SBlock: BlockT,
{
    /// we always use the best hash when system domain client is used.
    fn block_hash(&self) -> SBlock::Hash {
        self.client.info().best_hash
    }

    fn extract_state_roots(
        &self,
        best_hash: SBlock::Hash,
        ext: &SBlock::Extrinsic,
    ) -> Result<ExtractedStateRoots<SBlock>, ApiError> {
        let api = self.client.runtime_api();
        api.extract_xdm_proof_state_roots(best_hash, ext)
            .and_then(|maybe_state_roots| {
                maybe_state_roots.ok_or(ApiError::Application("Empty state roots".into()))
            })
    }
}

/// This is a compatibility implementation to invoke stateless functions on MessengerApi.
/// This will stateless wrapper and, hence, the dispatch may give invalid output if the invoked function
/// relies on state of the chain.
/// Note: Be sure to use this only when there is no System domain client available as this holds
/// entire system domain runtime on heap.
pub struct StateRootExtractorWithSystemDomainRuntime<SBlock: BlockT, Executor> {
    executor: Arc<Executor>,
    runtime_code: Cow<'static, [u8]>,
    block_hash: SBlock::Hash,
}

impl<SBlock, Executor> Core<SBlock> for StateRootExtractorWithSystemDomainRuntime<SBlock, Executor>
where
    SBlock: BlockT,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn __runtime_api_internal_call_api_at(
        &self,
        _at: <SBlock as BlockT>::Hash,
        _context: ExecutionContext,
        params: Vec<u8>,
        fn_name: &dyn Fn(RuntimeVersion) -> &'static str,
    ) -> Result<Vec<u8>, ApiError> {
        self.dispatch_call(fn_name, params)
    }
}

impl<SBlock, Executor> MessengerApi<SBlock, NumberFor<SBlock>>
    for StateRootExtractorWithSystemDomainRuntime<SBlock, Executor>
where
    SBlock: BlockT,
    NumberFor<SBlock>: Encode + Decode,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn __runtime_api_internal_call_api_at(
        &self,
        _at: <SBlock as BlockT>::Hash,
        _context: ExecutionContext,
        params: Vec<u8>,
        fn_name: &dyn Fn(RuntimeVersion) -> &'static str,
    ) -> Result<Vec<u8>, ApiError> {
        self.dispatch_call(fn_name, params)
    }
}

impl<SBlock: BlockT, Executor> FetchRuntimeCode
    for StateRootExtractorWithSystemDomainRuntime<SBlock, Executor>
{
    fn fetch_runtime_code(&self) -> Option<Cow<[u8]>> {
        Some(self.runtime_code.clone())
    }
}

impl<SBlock, Executor> StateRootExtractorWithSystemDomainRuntime<SBlock, Executor>
where
    SBlock: BlockT,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    pub fn new(
        executor: Arc<Executor>,
        runtime_code: Cow<'static, [u8]>,
        best_hash: SBlock::Hash,
    ) -> Self {
        Self {
            executor,
            runtime_code,
            block_hash: best_hash,
        }
    }

    fn runtime_code(&self) -> RuntimeCode {
        let code_hash = sp_core::Blake2Hasher::hash(&self.runtime_code);
        RuntimeCode {
            code_fetcher: self,
            heap_pages: None,
            hash: code_hash.encode(),
        }
    }

    fn runtime_version(&self) -> Result<RuntimeVersion, ApiError> {
        let mut ext = BasicExternalities::new_empty();
        self.executor
            .runtime_version(&mut ext, &self.runtime_code())
            .map_err(|err| ApiError::Application(Box::new(err)))
    }

    fn dispatch_call(
        &self,
        fn_name: &dyn Fn(RuntimeVersion) -> &'static str,
        input: Vec<u8>,
    ) -> Result<Vec<u8>, ApiError> {
        let runtime_version = self.runtime_version()?;
        let fn_name = fn_name(runtime_version);
        let mut ext = BasicExternalities::new_empty();
        self.executor
            .call(
                &mut ext,
                &self.runtime_code(),
                fn_name,
                &input,
                false,
                CallContext::Offchain,
            )
            .0
            .map_err(|err| {
                ApiError::Application(format!("Failed to invoke call to {fn_name}: {err}").into())
            })
    }
}

impl<SBlock, Executor> StateRootExtractor<SBlock>
    for StateRootExtractorWithSystemDomainRuntime<SBlock, Executor>
where
    SBlock: BlockT,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn block_hash(&self) -> SBlock::Hash {
        self.block_hash
    }

    fn extract_state_roots(
        &self,
        block_hash: SBlock::Hash,
        ext: &SBlock::Extrinsic,
    ) -> Result<ExtractedStateRoots<SBlock>, ApiError> {
        <Self as MessengerApi<SBlock, NumberFor<SBlock>>>::extract_xdm_proof_state_roots(
            self, block_hash, ext,
        )
        .and_then(|maybe_state_roots| {
            maybe_state_roots.ok_or(ApiError::Application("Empty state roots".into()))
        })
    }
}
