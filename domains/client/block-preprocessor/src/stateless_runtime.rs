use codec::{Codec, Encode};
use domain_runtime_primitives::opaque::AccountId;
use domain_runtime_primitives::{Balance, CheckExtrinsicsValidityError, DecodeExtrinsicError};
use sc_client_api::execution_extensions::ExtensionsFactory;
use sc_executor::RuntimeVersionOf;
use sp_api::{ApiError, Core, RuntimeApiInfo};
use sp_core::traits::{CallContext, CodeExecutor, FetchRuntimeCode, RuntimeCode};
use sp_core::Hasher;
use sp_domains::core_api::DomainCoreApi;
use sp_domains::DomainAllowlistUpdates;
use sp_messenger::messages::MessageKey;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use sp_runtime::Storage;
use sp_state_machine::BasicExternalities;
use sp_version::RuntimeVersion;
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
    extension_factory: Box<dyn ExtensionsFactory<Block>>,
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

impl<Block, Executor> MessengerApi<Block> for StatelessRuntime<Block, Executor>
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
            extension_factory: Box::new(()),
            _marker: Default::default(),
        }
    }

    /// Set the storage.
    ///
    /// Inject the state necessary for calling stateful runtime APIs.
    pub fn set_storage(&mut self, storage: Storage) {
        self.storage = storage;
    }

    /// Set the extensions.
    ///
    /// Inject the necessary extensions for Domain.
    pub fn set_extension_factory(&mut self, extension_factory: Box<dyn ExtensionsFactory<Block>>) {
        self.extension_factory = extension_factory;
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
        let ext_extensions = ext.extensions();
        ext_extensions.merge(
            self.extension_factory
                .extensions_for(Default::default(), Default::default()),
        );
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
                CallContext::Offchain,
            )
            .0
            .map_err(|err| {
                ApiError::Application(format!("Failed to invoke call to {fn_name}: {err}").into())
            })
    }

    pub fn outbox_storage_key(&self, message_key: MessageKey) -> Result<Vec<u8>, ApiError> {
        let storage_key = <Self as MessengerApi<Block>>::outbox_storage_key(
            self,
            Default::default(),
            message_key,
        )?;
        Ok(storage_key)
    }

    pub fn inbox_response_storage_key(&self, message_key: MessageKey) -> Result<Vec<u8>, ApiError> {
        let storage_key = <Self as MessengerApi<Block>>::inbox_response_storage_key(
            self,
            Default::default(),
            message_key,
        )?;
        Ok(storage_key)
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

    pub fn construct_consensus_chain_byte_fee_extrinsic(
        &self,
        consensus_chain_byte_fee: Balance,
    ) -> Result<Block::Extrinsic, ApiError> {
        <Self as DomainCoreApi<Block>>::construct_consensus_chain_byte_fee_extrinsic(
            self,
            Default::default(),
            consensus_chain_byte_fee,
        )
    }

    pub fn construct_domain_update_chain_allowlist_extrinsic(
        &self,
        updates: DomainAllowlistUpdates,
    ) -> Result<Block::Extrinsic, ApiError> {
        <Self as DomainCoreApi<Block>>::construct_domain_update_chain_allowlist_extrinsic(
            self,
            Default::default(),
            updates,
        )
    }

    pub fn is_inherent_extrinsic(
        &self,
        extrinsic: &<Block as BlockT>::Extrinsic,
    ) -> Result<bool, ApiError> {
        <Self as DomainCoreApi<Block>>::is_inherent_extrinsic(self, Default::default(), extrinsic)
    }

    pub fn is_valid_xdm(&self, extrinsic: Vec<u8>) -> Result<Option<bool>, ApiError> {
        <Self as MessengerApi<Block>>::is_xdm_valid(self, Default::default(), extrinsic)
    }

    pub fn decode_extrinsic(
        &self,
        opaque_extrinsic: sp_runtime::OpaqueExtrinsic,
    ) -> Result<Result<<Block as BlockT>::Extrinsic, DecodeExtrinsicError>, ApiError> {
        <Self as DomainCoreApi<Block>>::decode_extrinsic(self, Default::default(), opaque_extrinsic)
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

    pub fn transfers_storage_key(&self) -> Result<Vec<u8>, ApiError> {
        <Self as DomainCoreApi<Block>>::transfers_storage_key(self, Default::default())
    }

    pub fn block_fees_storage_key(&self) -> Result<Vec<u8>, ApiError> {
        let runtime_version = {
            let mut ext = BasicExternalities::new(self.storage.clone());
            let ext_extensions = ext.extensions();
            ext_extensions.merge(
                self.extension_factory
                    .extensions_for(Default::default(), Default::default()),
            );
            let runtime_code = self.runtime_code();
            self.executor
                .runtime_version(&mut ext, &runtime_code)
                .map_err(|err| {
                    ApiError::Application(Box::from(format!(
                        "failed to read domain runtime version: {err}"
                    )))
                })?
        };
        let has_runtime_api = runtime_version
            .api_version(&<dyn DomainCoreApi<Block>>::ID)
            .map_or(false, |runtime_api_version| runtime_api_version >= 2);

        if has_runtime_api {
            <Self as DomainCoreApi<Block>>::block_fees_storage_key(self, Default::default())
        } else {
            Ok(sp_domains::operator_block_fees_final_key())
        }
    }
}
