use crate::runtime_api::{
    ExtractSignerResult, ExtractedStateRoots, IsInherentExtrinsic, SetCodeConstructor,
    SignerExtractor, StateRootExtractor, TimestampExtrinsicConstructor,
};
use codec::{Codec, Encode};
use domain_runtime_primitives::DomainCoreApi;
use sc_executor::RuntimeVersionOf;
use sp_api::{ApiError, BlockT, Core, Hasher, RuntimeVersion};
use sp_core::traits::{CallContext, CodeExecutor, FetchRuntimeCode, RuntimeCode};
use sp_messenger::MessengerApi;
use sp_runtime::traits::NumberFor;
use sp_runtime::Storage;
use sp_state_machine::BasicExternalities;
use std::borrow::Cow;
use std::sync::Arc;
use subspace_runtime_primitives::Moment;

/// Lightweight runtime api based on the runtime code and partial state.
///
/// NOTE:
/// - This is only supposed to be used when no domain client available, i.e., when the
/// caller does not own the entire domain state.
/// - This perfectly fits the runtime APIs that are purely stateless, but it's also usable
/// for the stateful APIs. If some states are used inside a runtime api, these states must
/// be provided and set before dispatching otherwise [`RuntimeApiLight`] may give invalid output.
pub struct RuntimeApiLight<Executor> {
    executor: Arc<Executor>,
    runtime_code: Cow<'static, [u8]>,
    storage: Storage,
}

impl<Block, Executor> Core<Block> for RuntimeApiLight<Executor>
where
    Block: BlockT,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn __runtime_api_internal_call_api_at(
        &self,
        _at: <Block as BlockT>::Hash,
        params: Vec<u8>,
        fn_name: &dyn Fn(RuntimeVersion) -> &'static str,
    ) -> Result<Vec<u8>, ApiError> {
        self.dispatch_call(fn_name, params)
    }
}

impl<Block, Executor> DomainCoreApi<Block> for RuntimeApiLight<Executor>
where
    Block: BlockT,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn __runtime_api_internal_call_api_at(
        &self,
        _at: <Block as BlockT>::Hash,
        params: Vec<u8>,
        fn_name: &dyn Fn(RuntimeVersion) -> &'static str,
    ) -> Result<Vec<u8>, ApiError> {
        self.dispatch_call(fn_name, params)
    }
}

impl<Block, Executor> MessengerApi<Block, NumberFor<Block>> for RuntimeApiLight<Executor>
where
    Block: BlockT,
    NumberFor<Block>: Codec,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn __runtime_api_internal_call_api_at(
        &self,
        _at: <Block as BlockT>::Hash,
        params: Vec<u8>,
        fn_name: &dyn Fn(RuntimeVersion) -> &'static str,
    ) -> Result<Vec<u8>, ApiError> {
        self.dispatch_call(fn_name, params)
    }
}

impl<Executor> FetchRuntimeCode for RuntimeApiLight<Executor> {
    fn fetch_runtime_code(&self) -> Option<Cow<'static, [u8]>> {
        Some(self.runtime_code.clone())
    }
}

impl<Executor> RuntimeApiLight<Executor>
where
    Executor: CodeExecutor + RuntimeVersionOf,
{
    /// Create a new instance of [`RuntimeApiLight`] with empty storage.
    pub fn new(executor: Arc<Executor>, runtime_code: Cow<'static, [u8]>) -> Self {
        Self {
            executor,
            runtime_code,
            storage: Storage::default(),
        }
    }

    /// Set the storage.
    ///
    /// Inject the state necessary for calling stateful runtime APIs.
    pub fn set_storage(&mut self, storage: Storage) {
        self.storage = storage;
    }

    fn runtime_code(&self) -> RuntimeCode<'_> {
        let code_hash = sp_core::Blake2Hasher::hash(&self.runtime_code);
        RuntimeCode {
            code_fetcher: self,
            heap_pages: None,
            hash: code_hash.encode(),
        }
    }

    fn dispatch_call(
        &self,
        fn_name: &dyn Fn(RuntimeVersion) -> &'static str,
        input: Vec<u8>,
    ) -> Result<Vec<u8>, ApiError> {
        let mut ext = BasicExternalities::new(self.storage.clone());
        let runtime_code = self.runtime_code();
        let runtime_version = self
            .executor
            .runtime_version(&mut ext, &runtime_code)
            .map_err(|err| {
                ApiError::Application(Box::from(format!(
                    "failed to read domain runtime version: {err}"
                )))
            })?;
        let fn_name = fn_name(runtime_version);
        self.executor
            .call(
                &mut ext,
                &runtime_code,
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

impl<Block, Executor> StateRootExtractor<Block> for RuntimeApiLight<Executor>
where
    Block: BlockT,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn extract_state_roots(
        &self,
        block_hash: Block::Hash,
        ext: &Block::Extrinsic,
    ) -> Result<ExtractedStateRoots<Block>, ApiError> {
        let maybe_state_roots = <Self as MessengerApi<Block, _>>::extract_xdm_proof_state_roots(
            self,
            block_hash,
            ext.encode(),
        )?;
        maybe_state_roots.ok_or(ApiError::Application("Empty state roots".into()))
    }
}

impl<Executor, Block> SignerExtractor<Block> for RuntimeApiLight<Executor>
where
    Block: BlockT,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn extract_signer(
        &self,
        at: Block::Hash,
        extrinsics: Vec<<Block as BlockT>::Extrinsic>,
    ) -> Result<ExtractSignerResult<Block>, ApiError> {
        <Self as DomainCoreApi<Block>>::extract_signer(self, at, extrinsics)
    }
}

impl<Executor, Block> SetCodeConstructor<Block> for RuntimeApiLight<Executor>
where
    Block: BlockT,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn construct_set_code_extrinsic(
        &self,
        at: Block::Hash,
        runtime_code: Vec<u8>,
    ) -> Result<Vec<u8>, ApiError> {
        <Self as DomainCoreApi<Block>>::construct_set_code_extrinsic(self, at, runtime_code)
    }
}

impl<Executor, Block> TimestampExtrinsicConstructor<Block> for RuntimeApiLight<Executor>
where
    Block: BlockT,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn construct_timestamp_extrinsic(
        &self,
        at: Block::Hash,
        moment: Moment,
    ) -> Result<Block::Extrinsic, ApiError> {
        <Self as DomainCoreApi<Block>>::construct_timestamp_extrinsic(self, at, moment)
    }
}

impl<Executor, Block> IsInherentExtrinsic<Block> for RuntimeApiLight<Executor>
where
    Block: BlockT,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn is_inherent_extrinsic(
        &self,
        at: Block::Hash,
        extrinsic: &<Block as BlockT>::Extrinsic,
    ) -> Result<bool, ApiError> {
        <Self as DomainCoreApi<Block>>::is_inherent_extrinsic(self, at, extrinsic)
    }
}
