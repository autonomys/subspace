use crate::runtime_api::{
    CoreBundleConstructor, ExtractSignerResult, ExtractedStateRoots, InherentExtrinsicConstructor,
    SetCodeConstructor, SignerExtractor, StateRootExtractor,
};
use codec::{Codec, Encode};
use domain_runtime_primitives::{DomainCoreApi, InherentExtrinsicApi};
use sc_executor_common::runtime_blob::RuntimeBlob;
use sp_api::{ApiError, BlockT, Core, Hasher, RuntimeVersion};
use sp_core::traits::{CallContext, CodeExecutor, FetchRuntimeCode, RuntimeCode};
use sp_core::ExecutionContext;
use sp_domains::SignedOpaqueBundle;
use sp_messenger::MessengerApi;
use sp_runtime::traits::NumberFor;
use sp_state_machine::BasicExternalities;
use std::borrow::Cow;
use std::sync::Arc;
use subspace_runtime_primitives::Moment;
use system_runtime_primitives::SystemDomainApi;

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
    Executor: CodeExecutor,
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

impl<Block, Executor> DomainCoreApi<Block> for RuntimeApiLight<Executor>
where
    Block: BlockT,
    Executor: CodeExecutor,
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
    Executor: CodeExecutor,
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
    Executor: CodeExecutor,
{
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
        let runtime_blob = RuntimeBlob::new(&self.runtime_code).map_err(|err| {
            ApiError::Application(Box::from(format!("invalid runtime code: {err}")))
        })?;
        sc_executor::read_embedded_version(&runtime_blob)
            .map_err(|err| ApiError::Application(Box::new(err)))?
            .ok_or(ApiError::Application(Box::from(
                "domain runtime version not found".to_string(),
            )))
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
    Executor: CodeExecutor,
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

impl<Executor, Block, PNumber, PHash> SystemDomainApi<Block, PNumber, PHash>
    for RuntimeApiLight<Executor>
where
    Block: BlockT,
    PNumber: Codec,
    PHash: Codec,
    Executor: CodeExecutor,
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

impl<Executor, Block> InherentExtrinsicApi<Block> for RuntimeApiLight<Executor>
where
    Block: BlockT,
    Executor: CodeExecutor,
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

impl<PBlock, Executor, Block> CoreBundleConstructor<PBlock, Block> for RuntimeApiLight<Executor>
where
    PBlock: BlockT,
    Block: BlockT,
    Executor: CodeExecutor,
{
    fn construct_submit_core_bundle_extrinsics(
        &self,
        at: Block::Hash,
        signed_opaque_bundles: Vec<
            SignedOpaqueBundle<NumberFor<PBlock>, PBlock::Hash, Block::Hash>,
        >,
    ) -> Result<Vec<Vec<u8>>, ApiError> {
        <Self as SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>>::construct_submit_core_bundle_extrinsics(
            self, at, signed_opaque_bundles,
        )
    }
}

impl<Executor, Block> SignerExtractor<Block> for RuntimeApiLight<Executor>
where
    Block: BlockT,
    Executor: CodeExecutor,
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
    Executor: CodeExecutor,
{
    fn construct_set_code_extrinsic(
        &self,
        at: Block::Hash,
        runtime_code: Vec<u8>,
    ) -> Result<Vec<u8>, ApiError> {
        <Self as DomainCoreApi<Block>>::construct_set_code_extrinsic(self, at, runtime_code)
    }
}

impl<Executor, Block> InherentExtrinsicConstructor<Block> for RuntimeApiLight<Executor>
where
    Block: BlockT,
    Executor: CodeExecutor,
{
    fn construct_timestamp_inherent_extrinsic(
        &self,
        at: Block::Hash,
        moment: Moment,
    ) -> Result<Option<Block::Extrinsic>, ApiError> {
        <Self as InherentExtrinsicApi<Block>>::construct_inherent_timestamp_extrinsic(
            self, at, moment,
        )
    }
}
