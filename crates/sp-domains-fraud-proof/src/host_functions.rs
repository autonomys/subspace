use crate::InvalidDomainExtrinsicRootInfo;
use codec::Encode;
use domain_block_preprocessor::runtime_api::InherentExtrinsicConstructor;
use domain_block_preprocessor::runtime_api_light::RuntimeApiLight;
use sp_api::{BlockT, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domains::{DomainId, DomainsApi};
use sp_runtime::traits::NumberFor;
use std::marker::PhantomData;
use std::sync::Arc;

/// Trait to query and verify Domains Fraud proof.
pub trait FraudProofHostFunctions: Send + Sync {
    /// Returns the required info to verify invalid domain extrinsic root.
    fn get_invalid_domain_extrinsic_root_info(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
    ) -> Option<InvalidDomainExtrinsicRootInfo>;
}

sp_externalities::decl_extension! {
    /// Domains fraud proof host function
    pub struct FraudProofExtension(std::sync::Arc<dyn FraudProofHostFunctions>);
}

impl FraudProofExtension {
    /// Create a new instance of [`FraudProofExtension`].
    pub fn new(inner: std::sync::Arc<dyn FraudProofHostFunctions>) -> Self {
        Self(inner)
    }
}

/// Trait Impl to query and verify Domains Fraud proof.
pub struct FraudProofHostFunctionsImpl<Block, Client, DomainBlock, Executor> {
    consensus_client: Arc<Client>,
    executor: Arc<Executor>,
    _phantom: PhantomData<(Block, DomainBlock)>,
}

impl<Block, Client, DomainBlock, Executor>
    FraudProofHostFunctionsImpl<Block, Client, DomainBlock, Executor>
{
    pub fn new(consensus_client: Arc<Client>, executor: Arc<Executor>) -> Self {
        FraudProofHostFunctionsImpl {
            consensus_client,
            executor,
            _phantom: Default::default(),
        }
    }
}

impl<Block, Client, DomainBlock, Executor> FraudProofHostFunctions
    for FraudProofHostFunctionsImpl<Block, Client, DomainBlock, Executor>
where
    Block: BlockT,
    Block::Hash: From<H256>,
    DomainBlock: BlockT,
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: DomainsApi<Block, NumberFor<DomainBlock>, DomainBlock::Hash>,
    Executor: CodeExecutor,
{
    fn get_invalid_domain_extrinsic_root_info(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
    ) -> Option<InvalidDomainExtrinsicRootInfo> {
        let runtime_api = self.consensus_client.runtime_api();
        let consensus_block_hash = consensus_block_hash.into();
        let runtime_code = runtime_api
            .domain_runtime_code(consensus_block_hash, domain_id)
            .ok()??;
        let block_randomness = runtime_api
            .extrinsics_shuffling_seed(consensus_block_hash)
            .ok()?;
        let timestamp = runtime_api.timestamp(consensus_block_hash).ok()?;

        let domain_runtime_api_light =
            RuntimeApiLight::new(self.executor.clone(), runtime_code.into());

        let timestamp_extrinsic =
            InherentExtrinsicConstructor::<DomainBlock>::construct_timestamp_inherent_extrinsic(
                &domain_runtime_api_light,
                // We do not care about the domain hash since this is stateless call into
                // domain runtime,
                Default::default(),
                timestamp,
            )
            .ok()?
            .encode();
        Some(InvalidDomainExtrinsicRootInfo {
            block_randomness,
            timestamp_extrinsic,
        })
    }
}
