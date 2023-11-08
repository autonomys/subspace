use crate::{
    FraudProofVerificationInfoRequest, FraudProofVerificationInfoResponse, SetCodeExtrinsic,
};
use codec::{Decode, Encode};
use domain_block_preprocessor::inherents::extract_domain_runtime_upgrade_code;
use domain_block_preprocessor::runtime_api::{
    SetCodeConstructor, SignerExtractor, TimestampExtrinsicConstructor,
};
use domain_block_preprocessor::runtime_api_light::RuntimeApiLight;
use sc_client_api::BlockBackend;
use sc_executor::RuntimeVersionOf;
use sp_api::{BlockT, HashT, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::traits::{CodeExecutor, FetchRuntimeCode, RuntimeCode};
use sp_core::H256;
use sp_domains::bundle_producer_election::BundleProducerElectionParams;
use sp_domains::{BundleProducerElectionApi, DomainId, DomainsApi, OperatorId};
use sp_runtime::traits::Header as HeaderT;
use sp_runtime::OpaqueExtrinsic;
use sp_std::vec::Vec;
use sp_trie::StorageProof;
use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::{Randomness, U256};
use subspace_runtime_primitives::Balance;

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

    /// Derive the bundle digest for the given bundle body.
    fn derive_bundle_digest(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
        bundle_body: Vec<OpaqueExtrinsic>,
    ) -> Option<H256>;

    /// Check the execution proof
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

// TODO: Revisit the host function implementation once we decide best strategy to structure them.
impl<Block, Client, DomainBlock, Executor>
    FraudProofHostFunctionsImpl<Block, Client, DomainBlock, Executor>
where
    Block: BlockT,
    Block::Hash: From<H256>,
    DomainBlock: BlockT,
    Client: BlockBackend<Block> + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: DomainsApi<Block, DomainBlock::Header> + BundleProducerElectionApi<Block, Balance>,
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
        let runtime_code = self.get_domain_runtime_code(consensus_block_hash, domain_id)?;
        let timestamp = runtime_api.timestamp(consensus_block_hash.into()).ok()?;

        let domain_runtime_api_light =
            RuntimeApiLight::new(self.executor.clone(), runtime_code.into());

        TimestampExtrinsicConstructor::<DomainBlock>::construct_timestamp_extrinsic(
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

    fn derive_domain_set_code_extrinsic(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
    ) -> Option<SetCodeExtrinsic> {
        let maybe_upgraded_runtime = extract_domain_runtime_upgrade_code::<_, _, DomainBlock>(
            &self.consensus_client,
            consensus_block_hash.into(),
            domain_id,
        )
        .ok()
        .flatten();

        if let Some(upgraded_runtime) = maybe_upgraded_runtime {
            let runtime_code = self.get_domain_runtime_code(consensus_block_hash, domain_id)?;
            let domain_runtime_api_light =
                RuntimeApiLight::new(self.executor.clone(), runtime_code.into());

            SetCodeConstructor::<DomainBlock>::construct_set_code_extrinsic(
                &domain_runtime_api_light,
                // We do not care about the domain hash since this is stateless call into
                // domain runtime,
                Default::default(),
                upgraded_runtime,
            )
            .ok()
            .map(|ext| SetCodeExtrinsic::EncodedExtrinsic(ext.encode()))
        } else {
            Some(SetCodeExtrinsic::None)
        }
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

    fn is_tx_in_range(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
        opaque_extrinsic: OpaqueExtrinsic,
        bundle_index: u32,
    ) -> Option<bool> {
        let runtime_api = self.consensus_client.runtime_api();
        let runtime_code = self.get_domain_runtime_code(consensus_block_hash, domain_id)?;
        let consensus_block_hash = consensus_block_hash.into();
        let domain_tx_range = runtime_api
            .domain_tx_range(consensus_block_hash, domain_id)
            .ok()?;

        let consensus_extrinsics = self
            .consensus_client
            .block_body(consensus_block_hash)
            .ok()??;
        let bundles = self
            .consensus_client
            .runtime_api()
            .extract_successful_bundles(consensus_block_hash, domain_id, consensus_extrinsics)
            .ok()?;

        let bundle = bundles.get(bundle_index as usize)?;
        let bundle_vrf_hash =
            U256::from_be_bytes(bundle.sealed_header.header.proof_of_election.vrf_hash());

        let domain_runtime_api_light =
            RuntimeApiLight::new(self.executor.clone(), runtime_code.into());

        let encoded_extrinsic = opaque_extrinsic.encode();
        let extrinsic =
            <DomainBlock as BlockT>::Extrinsic::decode(&mut encoded_extrinsic.as_slice()).ok()?;

        <RuntimeApiLight<Executor> as domain_runtime_primitives::DomainCoreApi<
            DomainBlock,
        >>::is_within_tx_range(
            &domain_runtime_api_light,
            Default::default(), // Doesn't matter for RuntimeApiLight
            &extrinsic,
            &bundle_vrf_hash,
            &domain_tx_range,
        ).ok()
    }

    fn is_inherent_extrinsic(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
        opaque_extrinsic: OpaqueExtrinsic,
    ) -> Option<bool> {
        let runtime_code = self.get_domain_runtime_code(consensus_block_hash, domain_id)?;

        let domain_runtime_api_light =
            RuntimeApiLight::new(self.executor.clone(), runtime_code.into());

        let encoded_extrinsic = opaque_extrinsic.encode();
        let extrinsic =
            <DomainBlock as BlockT>::Extrinsic::decode(&mut encoded_extrinsic.as_slice()).ok()?;

        <RuntimeApiLight<Executor> as domain_runtime_primitives::DomainCoreApi<
            DomainBlock,
        >>::is_inherent_extrinsic(
            &domain_runtime_api_light,
            Default::default(), // Doesn't matter for RuntimeApiLight
            &extrinsic
        ).ok()
    }

    fn get_domain_election_params(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
    ) -> Option<BundleProducerElectionParams<Balance>> {
        let runtime_api = self.consensus_client.runtime_api();
        let consensus_block_hash = consensus_block_hash.into();
        let election_params = runtime_api
            .bundle_producer_election_params(consensus_block_hash, domain_id)
            .ok()??;
        Some(election_params)
    }

    fn get_operator_stake(
        &self,
        consensus_block_hash: H256,
        operator_id: OperatorId,
    ) -> Option<Balance> {
        let runtime_api = self.consensus_client.runtime_api();
        let consensus_block_hash = consensus_block_hash.into();
        let (_, operator_stake) = runtime_api
            .operator(consensus_block_hash, operator_id)
            .ok()??;
        Some(operator_stake)
    }
}

impl<Block, Client, DomainBlock, Executor> FraudProofHostFunctions
    for FraudProofHostFunctionsImpl<Block, Client, DomainBlock, Executor>
where
    Block: BlockT,
    Block::Hash: From<H256>,
    DomainBlock: BlockT,
    DomainBlock::Hash: From<H256> + Into<H256>,
    Client: BlockBackend<Block> + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: DomainsApi<Block, DomainBlock::Header> + BundleProducerElectionApi<Block, Balance>,
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
            FraudProofVerificationInfoRequest::DomainRuntimeCode(domain_id) => self
                .get_domain_runtime_code(consensus_block_hash, domain_id)
                .map(|domain_runtime_code| {
                    FraudProofVerificationInfoResponse::DomainRuntimeCode(domain_runtime_code)
                }),
            FraudProofVerificationInfoRequest::DomainSetCodeExtrinsic(domain_id) => self
                .derive_domain_set_code_extrinsic(consensus_block_hash, domain_id)
                .map(|maybe_domain_set_code_extrinsic| {
                    FraudProofVerificationInfoResponse::DomainSetCodeExtrinsic(
                        maybe_domain_set_code_extrinsic,
                    )
                }),
            FraudProofVerificationInfoRequest::TxRangeCheck {
                domain_id,
                opaque_extrinsic,
                bundle_index,
            } => self
                .is_tx_in_range(
                    consensus_block_hash,
                    domain_id,
                    opaque_extrinsic,
                    bundle_index,
                )
                .map(|is_tx_in_range| {
                    FraudProofVerificationInfoResponse::TxRangeCheck(is_tx_in_range)
                }),
            FraudProofVerificationInfoRequest::InherentExtrinsicCheck {
                domain_id,
                opaque_extrinsic,
            } => self
                .is_inherent_extrinsic(consensus_block_hash, domain_id, opaque_extrinsic)
                .map(|is_inherent| {
                    FraudProofVerificationInfoResponse::InherentExtrinsicCheck(is_inherent)
                }),
            FraudProofVerificationInfoRequest::DomainElectionParams { domain_id } => self
                .get_domain_election_params(consensus_block_hash, domain_id)
                .map(|domain_election_params| {
                    FraudProofVerificationInfoResponse::DomainElectionParams {
                        domain_total_stake: domain_election_params.total_domain_stake,
                        bundle_slot_probability: domain_election_params.bundle_slot_probability,
                    }
                }),
            FraudProofVerificationInfoRequest::OperatorStake { operator_id } => self
                .get_operator_stake(consensus_block_hash, operator_id)
                .map(|operator_stake| {
                    FraudProofVerificationInfoResponse::OperatorStake(operator_stake)
                }),
        }
    }

    fn derive_bundle_digest(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
        bundle_body: Vec<OpaqueExtrinsic>,
    ) -> Option<H256> {
        let mut extrinsics = Vec::with_capacity(bundle_body.len());
        for opaque_extrinsic in bundle_body {
            let ext = <<DomainBlock as BlockT>::Extrinsic>::decode(
                &mut opaque_extrinsic.encode().as_slice(),
            )
            .ok()?;
            extrinsics.push(ext);
        }

        let domain_runtime_code = self.get_domain_runtime_code(consensus_block_hash, domain_id)?;
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
        .map(|(signer, tx)| {
            (
                signer,
                <DomainBlock::Header as HeaderT>::Hashing::hash_of(&tx),
            )
        })
        .collect();

        Some(<DomainBlock::Header as HeaderT>::Hashing::hash_of(&ext_signers).into())
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

        sp_state_machine::execution_proof_check::<<DomainBlock::Header as HeaderT>::Hashing, _>(
            pre_state_root.into(),
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
