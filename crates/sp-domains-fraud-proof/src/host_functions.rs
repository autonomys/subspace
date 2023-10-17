use crate::{FraudProofVerificationInfoRequest, FraudProofVerificationInfoResponse};
use codec::{Decode, Encode};
use domain_block_preprocessor::runtime_api::{InherentExtrinsicConstructor, SignerExtractor};
use domain_block_preprocessor::runtime_api_light::RuntimeApiLight;
use sc_client_api::BlockBackend;
use sc_executor::RuntimeVersionOf;
use sp_api::{BlockT, HashT, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domains::{DomainId, DomainsApi};
use sp_runtime::traits::{BlakeTwo256, NumberFor};
use sp_runtime::OpaqueExtrinsic;
use sp_std::vec::Vec;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::Randomness;

/// Trait to query and verify Domains Fraud proof.
pub trait FraudProofHostFunctions: Send + Sync {
    /// Returns the required verification info for the runtime to verify the Fraud proof.
    fn get_fraud_proof_verification_info(
        &self,
        consensus_block_hash: H256,
        fraud_proof_verification_req: FraudProofVerificationInfoRequest,
    ) -> Option<FraudProofVerificationInfoResponse>;

    /// Derive the bundle digest for the given bundle body.
    fn derive_bundle_digest(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
        bundle_body: Vec<OpaqueExtrinsic>,
    ) -> Option<H256>;
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

impl<Block, Client, DomainBlock, Executor>
    FraudProofHostFunctionsImpl<Block, Client, DomainBlock, Executor>
where
    Block: BlockT,
    Block::Hash: From<H256>,
    DomainBlock: BlockT,
    Client: BlockBackend<Block> + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: DomainsApi<Block, NumberFor<DomainBlock>, DomainBlock::Hash>,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn get_block_randomness(&self, consensus_block_hash: H256) -> Option<Randomness> {
        let runtime_api = self.consensus_client.runtime_api();
        let consensus_block_hash = consensus_block_hash.into();
        runtime_api
            .extrinsics_shuffling_seed(consensus_block_hash)
            .ok()
    }

    fn derive_domain_timestamp_extrinsic(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
    ) -> Option<Vec<u8>> {
        let runtime_api = self.consensus_client.runtime_api();
        let consensus_block_hash = consensus_block_hash.into();
        let runtime_code = runtime_api
            .domain_runtime_code(consensus_block_hash, domain_id)
            .ok()??;
        let timestamp = runtime_api.timestamp(consensus_block_hash).ok()?;

        let domain_runtime_api_light =
            RuntimeApiLight::new(self.executor.clone(), runtime_code.into());

        InherentExtrinsicConstructor::<DomainBlock>::construct_timestamp_inherent_extrinsic(
            &domain_runtime_api_light,
            // We do not care about the domain hash since this is stateless call into
            // domain runtime,
            Default::default(),
            timestamp,
        )
        .ok()
        .map(|ext| ext.encode())
    }

    fn get_domain_bundle_body(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
        bundle_index: u32,
    ) -> Option<Vec<OpaqueExtrinsic>> {
        let consensus_block_hash = consensus_block_hash.into();
        let consensus_extrinsics = self
            .consensus_client
            .block_body(consensus_block_hash)
            .ok()??;
        let mut bundles = self
            .consensus_client
            .runtime_api()
            .extract_successful_bundles(consensus_block_hash, domain_id, consensus_extrinsics)
            .ok()?;

        if bundle_index < bundles.len() as u32 {
            Some(bundles.swap_remove(bundle_index as usize).extrinsics)
        } else {
            None
        }
    }
}

impl<Block, Client, DomainBlock, Executor> FraudProofHostFunctions
    for FraudProofHostFunctionsImpl<Block, Client, DomainBlock, Executor>
where
    Block: BlockT,
    Block::Hash: From<H256>,
    DomainBlock: BlockT,
    Client: BlockBackend<Block> + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: DomainsApi<Block, NumberFor<DomainBlock>, DomainBlock::Hash>,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn get_fraud_proof_verification_info(
        &self,
        consensus_block_hash: H256,
        fraud_proof_verification_req: FraudProofVerificationInfoRequest,
    ) -> Option<FraudProofVerificationInfoResponse> {
        match fraud_proof_verification_req {
            FraudProofVerificationInfoRequest::BlockRandomness => self
                .get_block_randomness(consensus_block_hash)
                .map(|block_randomness| {
                    FraudProofVerificationInfoResponse::BlockRandomness(block_randomness)
                }),
            FraudProofVerificationInfoRequest::DomainTimestampExtrinsic(domain_id) => self
                .derive_domain_timestamp_extrinsic(consensus_block_hash, domain_id)
                .map(|domain_timestamp_extrinsic| {
                    FraudProofVerificationInfoResponse::DomainTimestampExtrinsic(
                        domain_timestamp_extrinsic,
                    )
                }),
            FraudProofVerificationInfoRequest::DomainBundleBody {
                domain_id,
                bundle_index,
            } => self
                .get_domain_bundle_body(consensus_block_hash, domain_id, bundle_index)
                .map(|domain_bundle_body| {
                    FraudProofVerificationInfoResponse::DomainBundleBody(domain_bundle_body)
                }),
        }
    }

    fn derive_bundle_digest(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
        bundle_body: Vec<OpaqueExtrinsic>,
    ) -> Option<H256> {
        let domain_runtime_code = {
            let consensus_block_hash = consensus_block_hash.into();
            self.consensus_client
                .runtime_api()
                .domain_runtime_code(consensus_block_hash, domain_id)
                .ok()??
        };

        let mut extrinsics = Vec::with_capacity(bundle_body.len());
        for opaque_extrinsic in bundle_body {
            let ext = <<DomainBlock as BlockT>::Extrinsic>::decode(
                &mut opaque_extrinsic.encode().as_slice(),
            )
            .ok()?;
            extrinsics.push(ext);
        }

        let domain_runtime_api_light =
            RuntimeApiLight::new(self.executor.clone(), domain_runtime_code.into());

        let ext_signers: Vec<_> = SignerExtractor::<DomainBlock>::extract_signer(
            &domain_runtime_api_light,
            // `extract_signer` is a stateless runtime api thus it is okay to use
            // default block hash
            Default::default(),
            extrinsics,
        )
        .ok()?
        .into_iter()
        .map(|(signer, tx)| (signer, BlakeTwo256::hash_of(&tx)))
        .collect();

        Some(BlakeTwo256::hash_of(&ext_signers))
    }
}
