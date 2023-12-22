use codec::{Codec, Encode};
use domain_runtime_primitives::opaque::AccountId;
use domain_runtime_primitives::{CheckExtrinsicsValidityError, DomainCoreApi};
use sc_executor::RuntimeVersionOf;
use sp_api::{ApiError, BlockT, Core, Hasher, RuntimeVersion};
use sp_core::traits::{CallContext, CodeExecutor, FetchRuntimeCode, RuntimeCode};
use sp_messenger::messages::ExtractedStateRootsFromProof;
use sp_messenger::MessengerApi;
use sp_runtime::traits::NumberFor;
use sp_runtime::Storage;
use sp_state_machine::BasicExternalities;
use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::U256;
use subspace_runtime_primitives::Moment;

/// Stateless runtime api based on the runtime code and partial state if provided.
///
/// NOTE:
/// - This is only supposed to be used when no domain client available, i.e., when the
/// caller does not own the entire domain state.
/// - This perfectly fits the runtime APIs that are purely stateless, but it's also usable
/// for the stateful APIs. If some states are used inside a runtime api, these states must
/// be provided and set before dispatching otherwise [`StatelessRuntime`] may give invalid output.
pub struct StatelessRuntime<Block, Executor> {
    executor: Arc<Executor>,
    runtime_code: Cow<'static, [u8]>,
    storage: Storage,
    _marker: PhantomData<Block>,
}

impl<Block, Executor> Core<Block> for StatelessRuntime<Block, Executor>
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

impl<Block, Executor> DomainCoreApi<Block> for StatelessRuntime<Block, Executor>
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

impl<Block, Executor> MessengerApi<Block, NumberFor<Block>> for StatelessRuntime<Block, Executor>
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

impl<Block, Executor> FetchRuntimeCode for StatelessRuntime<Block, Executor> {
    fn fetch_runtime_code(&self) -> Option<Cow<'static, [u8]>> {
        Some(self.runtime_code.clone())
    }
}

pub type ExtractedStateRoots<Block> = ExtractedStateRootsFromProof<
    NumberFor<Block>,
    <Block as BlockT>::Hash,
    <Block as BlockT>::Hash,
>;

pub type ExtractSignerResult<Block> = Vec<(Option<AccountId>, <Block as BlockT>::Extrinsic)>;

impl<Block, Executor> StatelessRuntime<Block, Executor>
where
    Block: BlockT,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    /// Create a new instance of [`StatelessRuntime`] with empty storage.
    pub fn new(executor: Arc<Executor>, runtime_code: Cow<'static, [u8]>) -> Self {
        Self {
            executor,
            runtime_code,
            storage: Storage::default(),
            _marker: Default::default(),
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

    pub fn extract_state_roots(
        &self,
        ext: &Block::Extrinsic,
    ) -> Result<ExtractedStateRoots<Block>, ApiError> {
        let maybe_state_roots = <Self as MessengerApi<Block, _>>::extract_xdm_proof_state_roots(
            self,
            Default::default(),
            ext.encode(),
        )?;
        maybe_state_roots.ok_or(ApiError::Application("Empty state roots".into()))
    }

    pub fn extract_signer(
        &self,
        extrinsics: Vec<<Block as BlockT>::Extrinsic>,
    ) -> Result<ExtractSignerResult<Block>, ApiError> {
        <Self as DomainCoreApi<Block>>::extract_signer(self, Default::default(), extrinsics)
    }

    pub fn construct_set_code_extrinsic(&self, runtime_code: Vec<u8>) -> Result<Vec<u8>, ApiError> {
        <Self as DomainCoreApi<Block>>::construct_set_code_extrinsic(
            self,
            Default::default(),
            runtime_code,
        )
    }

    pub fn construct_timestamp_extrinsic(
        &self,
        moment: Moment,
    ) -> Result<Block::Extrinsic, ApiError> {
        <Self as DomainCoreApi<Block>>::construct_timestamp_extrinsic(
            self,
            Default::default(),
            moment,
        )
    }

    pub fn is_inherent_extrinsic(
        &self,
        extrinsic: &<Block as BlockT>::Extrinsic,
    ) -> Result<bool, ApiError> {
        <Self as DomainCoreApi<Block>>::is_inherent_extrinsic(self, Default::default(), extrinsic)
    }

    pub fn is_within_tx_range(
        &self,
        extrinsic: &<Block as BlockT>::Extrinsic,
        bundle_vrf_hash: &U256,
        tx_range: &U256,
    ) -> Result<bool, ApiError> {
        <Self as DomainCoreApi<Block>>::is_within_tx_range(
            self,
            Default::default(),
            extrinsic,
            bundle_vrf_hash,
            tx_range,
        )
    }

    /// This is stateful runtime api call and require setting of storage keys.
    pub fn check_extrinsics_and_do_pre_dispatch(
        &self,
        uxts: Vec<<Block as BlockT>::Extrinsic>,
        block_number: NumberFor<Block>,
        block_hash: <Block as BlockT>::Hash,
    ) -> Result<Result<(), CheckExtrinsicsValidityError>, ApiError> {
        <Self as DomainCoreApi<Block>>::check_extrinsics_and_do_pre_dispatch(
            self,
            Default::default(),
            uxts,
            block_number,
            block_hash,
        )
    }
}
