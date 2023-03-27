use crate::runtime_api::{ExtractedStateRoots, StateRootExtractor};
use codec::{Codec, Encode};
use sc_executor::RuntimeVersionOf;
use sp_api::{ApiError, BlockT, Core, Hasher, RuntimeVersion};
use sp_core::traits::{CallContext, CodeExecutor, FetchRuntimeCode, RuntimeCode};
use sp_core::ExecutionContext;
use sp_messenger::MessengerApi;
use sp_runtime::traits::NumberFor;
use sp_state_machine::BasicExternalities;
use std::borrow::Cow;
use std::sync::Arc;

/// This is a stateless wrapper around the runtime api.
/// Note: Dispatch may give invalid output if the invoked function relies on state of the chain.
/// Note: Be sure to use this only when there is no domain client available as this holds
/// since entire domain runtime on heap.
pub struct RuntimeApiLight<Executor> {
    executor: Arc<Executor>,
    runtime_code: Cow<'static, [u8]>,
}

impl<Block, Executor> Core<Block> for RuntimeApiLight<Executor>
where
    Block: BlockT,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn __runtime_api_internal_call_api_at(
        &self,
        _at: <Block as BlockT>::Hash,
        _context: ExecutionContext,
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
        _context: ExecutionContext,
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
    #[allow(unused)]
    pub fn new(executor: Arc<Executor>, runtime_code: Cow<'static, [u8]>) -> Self {
        Self {
            executor,
            runtime_code,
        }
    }

    fn runtime_code(&self) -> RuntimeCode<'_> {
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
        <Self as MessengerApi<Block, NumberFor<Block>>>::extract_xdm_proof_state_roots(
            self, block_hash, ext,
        )
        .and_then(|maybe_state_roots| {
            maybe_state_roots.ok_or(ApiError::Application("Empty state roots".into()))
        })
    }
}
