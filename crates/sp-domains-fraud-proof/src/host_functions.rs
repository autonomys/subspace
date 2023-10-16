use crate::{FraudProofVerificationInfoRequest, FraudProofVerificationInfoResponse};
use codec::{Decode, Encode};
use domain_block_preprocessor::runtime_api::InherentExtrinsicConstructor;
use domain_block_preprocessor::runtime_api_light::RuntimeApiLight;
use sp_api::{BlockT, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::traits::{CodeExecutor, FetchRuntimeCode, RuntimeCode};
use sp_core::H256;
use sp_domains::{DomainId, DomainsApi};
use sp_runtime::traits::{BlakeTwo256, Header as HeaderT, NumberFor};
use sp_trie::StorageProof;
use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::Randomness;

struct DomainRuntimeCodeFetcher(Vec<u8>);

impl FetchRuntimeCode for DomainRuntimeCodeFetcher {
    fn fetch_runtime_code(&self) -> Option<Cow<[u8]>> {
        Some(Cow::Borrowed(self.0.as_ref()))
    }
}

/// Trait to query and verify Domains Fraud proof.
pub trait FraudProofHostFunctions: Send + Sync {
    /// Returns the required verification info for the runtime to verify the Fraud proof.
    fn get_fraud_proof_verification_info(
        &self,
        consensus_block_hash: H256,
        fraud_proof_verification_req: FraudProofVerificationInfoRequest,
    ) -> Option<FraudProofVerificationInfoResponse>;

    fn execution_proof_check(
        &self,
        pre_state_root: H256,
        // TODO: implement `PassBy` for `sp_trie::StorageProof` in upstream to pass it directly here
        encoded_proof: Vec<u8>,
        verifying_method: &str,
        call_data: &[u8],
        domain_runtime_code: Vec<u8>,
    ) -> Option<Vec<u8>>;
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
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: DomainsApi<Block, NumberFor<DomainBlock>, DomainBlock::Hash>,
    Executor: CodeExecutor,
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

    fn get_domain_runtime_code(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
    ) -> Option<Vec<u8>> {
        let runtime_api = self.consensus_client.runtime_api();
        // Use the parent hash to get the actual used domain runtime code
        // TODO: update once we can get the actual used domain runtime code by `consensus_block_hash`
        let consensus_block_header = self
            .consensus_client
            .header(consensus_block_hash.into())
            .ok()
            .flatten()?;
        runtime_api
            .domain_runtime_code(*consensus_block_header.parent_hash(), domain_id)
            .ok()
            .flatten()
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
            FraudProofVerificationInfoRequest::DomainTimestampExtrinsic(doman_id) => self
                .derive_domain_timestamp_extrinsic(consensus_block_hash, doman_id)
                .map(|domain_timestamp_extrinsic| {
                    FraudProofVerificationInfoResponse::DomainTimestampExtrinsic(
                        domain_timestamp_extrinsic,
                    )
                }),
            FraudProofVerificationInfoRequest::DomainRuntimeCode(domain_id) => self
                .get_domain_runtime_code(consensus_block_hash, domain_id)
                .map(|domain_runtime_code| {
                    FraudProofVerificationInfoResponse::DomainRuntimeCode(domain_runtime_code)
                }),
        }
    }

    fn execution_proof_check(
        &self,
        pre_state_root: H256,
        encoded_proof: Vec<u8>,
        verifying_method: &str,
        call_data: &[u8],
        domain_runtime_code: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let proof: StorageProof = Decode::decode(&mut encoded_proof.as_ref()).ok()?;

        let domain_runtime_code_fetcher = DomainRuntimeCodeFetcher(domain_runtime_code);
        let runtime_code = RuntimeCode {
            code_fetcher: &domain_runtime_code_fetcher,
            hash: b"Hash of the code does not matter in terms of the execution proof check"
                .to_vec(),
            heap_pages: None,
        };

        sp_state_machine::execution_proof_check::<BlakeTwo256, _>(
            pre_state_root,
            proof,
            &mut Default::default(),
            self.executor.as_ref(),
            verifying_method,
            call_data,
            &runtime_code,
        )
        .ok()
    }
}
