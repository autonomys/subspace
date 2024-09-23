#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::{
    DomainChainAllowlistUpdateExtrinsic, DomainInherentExtrinsic, DomainInherentExtrinsicData,
    DomainStorageKeyRequest, FraudProofVerificationInfoRequest, FraudProofVerificationInfoResponse,
    SetCodeExtrinsic, StatelessDomainRuntimeCall, StorageKeyRequest,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use codec::{Codec, Decode, Encode};
use domain_block_preprocessor::inherents::extract_domain_runtime_upgrade_code;
use domain_block_preprocessor::stateless_runtime::StatelessRuntime;
use domain_runtime_primitives::{
    BlockNumber, CheckExtrinsicsValidityError, CHECK_EXTRINSICS_AND_DO_PRE_DISPATCH_METHOD_NAME,
};
use hash_db::{HashDB, Hasher};
use sc_client_api::execution_extensions::ExtensionsFactory;
use sc_client_api::BlockBackend;
use sc_executor::RuntimeVersionOf;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::{CallContext, CodeExecutor, FetchRuntimeCode, RuntimeCode};
use sp_core::H256;
use sp_domains::bundle_producer_election::BundleProducerElectionParams;
use sp_domains::{BundleProducerElectionApi, DomainId, DomainsApi, OperatorId};
use sp_externalities::Extensions;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT, NumberFor};
use sp_runtime::OpaqueExtrinsic;
use sp_state_machine::{OverlayedChanges, StateMachine, TrieBackend, TrieBackendBuilder};
use sp_trie::{MemoryDB, StorageProof};
use sp_weights::Weight;
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
    // TODO: remove before the new network
    fn derive_bundle_digest(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
        bundle_body: Vec<OpaqueExtrinsic>,
    ) -> Option<H256>;

    /// Derive the bundle digest for the given bundle body.
    fn derive_bundle_digest_v2(
        &self,
        domain_runtime_code: Vec<u8>,
        bundle_body: Vec<OpaqueExtrinsic>,
    ) -> Option<H256>;

    /// Check the execution proof
    fn execution_proof_check(
        &self,
        domain_block_id: (BlockNumber, H256),
        pre_state_root: H256,
        // TODO: implement `PassBy` for `sp_trie::StorageProof` in upstream to pass it directly here
        encoded_proof: Vec<u8>,
        execution_method: &str,
        call_data: &[u8],
        domain_runtime_code: Vec<u8>,
    ) -> Option<Vec<u8>>;

    fn check_extrinsics_in_single_context(
        &self,
        domain_runtime_code: Vec<u8>,
        domain_block_id: (BlockNumber, H256),
        domain_block_state_root: H256,
        bundle_extrinsics: Vec<OpaqueExtrinsic>,
        // TODO: implement `PassBy` for `sp_trie::StorageProof` in upstream to pass it directly here
        encoded_proof: Vec<u8>,
    ) -> Option<Option<u32>>;

    fn construct_domain_inherent_extrinsic(
        &self,
        domain_runtime_code: Vec<u8>,
        domain_inherent_extrinsic_data: DomainInherentExtrinsicData,
    ) -> Option<DomainInherentExtrinsic>;

    fn domain_storage_key(
        &self,
        domain_runtime_code: Vec<u8>,
        req: DomainStorageKeyRequest,
    ) -> Option<Vec<u8>>;

    fn domain_runtime_call(
        &self,
        domain_runtime_code: Vec<u8>,
        call: StatelessDomainRuntimeCall,
    ) -> Option<bool>;

    fn bundle_weight(
        &self,
        domain_runtime_code: Vec<u8>,
        bundle_body: Vec<OpaqueExtrinsic>,
    ) -> Option<Weight>;

    fn extract_xdm_mmr_proof(
        &self,
        domain_runtime_code: Vec<u8>,
        opaque_extrinsic: Vec<u8>,
    ) -> Option<Option<Vec<u8>>>;
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
pub struct FraudProofHostFunctionsImpl<Block, Client, DomainBlock, Executor, EFC> {
    consensus_client: Arc<Client>,
    domain_executor: Arc<Executor>,
    domain_extensions_factory_creator: EFC,
    _phantom: PhantomData<(Block, DomainBlock)>,
}

impl<Block, Client, DomainBlock, Executor, EFC>
    FraudProofHostFunctionsImpl<Block, Client, DomainBlock, Executor, EFC>
{
    pub fn new(
        consensus_client: Arc<Client>,
        domain_executor: Arc<Executor>,
        domain_extensions_factory_creator: EFC,
    ) -> Self {
        FraudProofHostFunctionsImpl {
            consensus_client,
            domain_executor,
            domain_extensions_factory_creator,
            _phantom: Default::default(),
        }
    }
}

// TODO: Revisit the host function implementation once we decide best strategy to structure them.
impl<Block, Client, DomainBlock, Executor, EFC>
    FraudProofHostFunctionsImpl<Block, Client, DomainBlock, Executor, EFC>
where
    Block: BlockT,
    Block::Hash: From<H256>,
    DomainBlock: BlockT,
    DomainBlock::Hash: From<H256> + Into<H256>,
    Client: BlockBackend<Block> + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: DomainsApi<Block, DomainBlock::Header>
        + BundleProducerElectionApi<Block, Balance>
        + MessengerApi<Block, NumberFor<Block>, Block::Hash>,
    Executor: CodeExecutor + RuntimeVersionOf,
    EFC: Fn(Arc<Client>, Arc<Executor>) -> Box<dyn ExtensionsFactory<DomainBlock>> + Send + Sync,
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

        let domain_stateless_runtime = StatelessRuntime::<Block, DomainBlock, _>::new(
            self.domain_executor.clone(),
            runtime_code.into(),
        );

        domain_stateless_runtime
            .construct_timestamp_extrinsic(timestamp)
            .ok()
            .map(|ext| ext.encode())
    }

    fn derive_domain_chain_allowlist_update_extrinsic(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
    ) -> Option<Vec<u8>> {
        let runtime_api = self.consensus_client.runtime_api();
        let runtime_code = self.get_domain_runtime_code(consensus_block_hash, domain_id)?;
        let updates = runtime_api
            .domain_chains_allowlist_update(consensus_block_hash.into(), domain_id)
            .ok()??;

        let domain_stateless_runtime = StatelessRuntime::<Block, DomainBlock, _>::new(
            self.domain_executor.clone(),
            runtime_code.into(),
        );

        domain_stateless_runtime
            .construct_domain_update_chain_allowlist_extrinsic(updates)
            .ok()
            .map(|ext| ext.encode())
    }

    fn derive_consensus_chain_byte_fee_extrinsic(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
    ) -> Option<Vec<u8>> {
        let runtime_api = self.consensus_client.runtime_api();
        let consensus_chain_byte_fee = runtime_api
            .consensus_chain_byte_fee(consensus_block_hash.into())
            .ok()?;

        let runtime_code = self.get_domain_runtime_code(consensus_block_hash, domain_id)?;
        let domain_stateless_runtime = StatelessRuntime::<Block, DomainBlock, _>::new(
            self.domain_executor.clone(),
            runtime_code.into(),
        );

        domain_stateless_runtime
            .construct_consensus_chain_byte_fee_extrinsic(consensus_chain_byte_fee)
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
            let domain_stateless_runtime = StatelessRuntime::<Block, DomainBlock, _>::new(
                self.domain_executor.clone(),
                runtime_code.into(),
            );

            domain_stateless_runtime
                .construct_set_code_extrinsic(upgraded_runtime)
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
            U256::from_be_bytes(*bundle.sealed_header.header.proof_of_election.vrf_hash());

        self.domain_runtime_call(
            runtime_code,
            StatelessDomainRuntimeCall::IsTxInRange {
                opaque_extrinsic,
                bundle_vrf_hash,
                domain_tx_range,
            },
        )
    }

    fn is_inherent_extrinsic(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
        opaque_extrinsic: OpaqueExtrinsic,
    ) -> Option<bool> {
        let runtime_code = self.get_domain_runtime_code(consensus_block_hash, domain_id)?;
        self.domain_runtime_call(
            runtime_code,
            StatelessDomainRuntimeCall::IsInherentExtrinsic(opaque_extrinsic),
        )
    }

    fn is_valid_xdm(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
        opaque_extrinsic: OpaqueExtrinsic,
    ) -> Option<bool> {
        let runtime_code = self.get_domain_runtime_code(consensus_block_hash, domain_id)?;
        let mut domain_stateless_runtime = StatelessRuntime::<Block, DomainBlock, _>::new(
            self.domain_executor.clone(),
            runtime_code.into(),
        );
        let extension_factory = (self.domain_extensions_factory_creator)(
            self.consensus_client.clone(),
            self.domain_executor.clone(),
        );
        domain_stateless_runtime.set_extension_factory(extension_factory);

        let consensus_api = self.consensus_client.runtime_api();
        let domain_initial_state = consensus_api
            .domain_instance_data(consensus_block_hash.into(), domain_id)
            .expect("Runtime Api must not fail. This is unrecoverable error")?
            .0
            .raw_genesis
            .into_storage();
        domain_stateless_runtime.set_storage(domain_initial_state);

        let encoded_extrinsic = opaque_extrinsic.encode();
        let extrinsic = DomainBlock::Extrinsic::decode(&mut encoded_extrinsic.as_slice()).ok()?;
        domain_stateless_runtime
            .is_xdm_mmr_proof_valid(&extrinsic)
            .expect("Runtime api must not fail. This is an unrecoverable error")
    }

    fn is_decodable_extrinsic(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
        opaque_extrinsic: OpaqueExtrinsic,
    ) -> Option<bool> {
        let runtime_code = self.get_domain_runtime_code(consensus_block_hash, domain_id)?;
        self.domain_runtime_call(
            runtime_code,
            StatelessDomainRuntimeCall::IsDecodableExtrinsic(opaque_extrinsic),
        )
    }

    fn storage_key(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
        req: StorageKeyRequest,
    ) -> Option<Vec<u8>> {
        let runtime_code = self.get_domain_runtime_code(consensus_block_hash, domain_id)?;
        let domain_stateless_runtime = StatelessRuntime::<Block, DomainBlock, _>::new(
            self.domain_executor.clone(),
            runtime_code.into(),
        );
        Some(
            match req {
                StorageKeyRequest::Transfers => domain_stateless_runtime.transfers_storage_key(),
            }
            .expect("Domain Runtime Api should not fail. There is no recovery from this; qed."),
        )
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

    fn check_extrinsics_in_single_context_v1(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
        domain_block_id: (BlockNumber, H256),
        domain_block_state_root: H256,
        bundle_extrinsics: Vec<OpaqueExtrinsic>,
        storage_proof: StorageProof,
    ) -> Option<Option<u32>> {
        let runtime_code = self.get_domain_runtime_code(consensus_block_hash, domain_id)?;
        self.check_extrinsics_in_single_context(
            runtime_code,
            domain_block_id,
            domain_block_state_root,
            bundle_extrinsics,
            storage_proof.encode(),
        )
    }
}

impl<Block, Client, DomainBlock, Executor, EFC> FraudProofHostFunctions
    for FraudProofHostFunctionsImpl<Block, Client, DomainBlock, Executor, EFC>
where
    Block: BlockT,
    Block::Hash: From<H256>,
    DomainBlock: BlockT,
    DomainBlock::Hash: From<H256> + Into<H256>,
    NumberFor<DomainBlock>: From<BlockNumber>,
    Client: BlockBackend<Block> + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: DomainsApi<Block, DomainBlock::Header>
        + BundleProducerElectionApi<Block, Balance>
        + MessengerApi<Block, NumberFor<Block>, Block::Hash>,
    Executor: CodeExecutor + RuntimeVersionOf,
    EFC: Fn(Arc<Client>, Arc<Executor>) -> Box<dyn ExtensionsFactory<DomainBlock>> + Send + Sync,
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
            FraudProofVerificationInfoRequest::ConsensusChainByteFeeExtrinsic(domain_id) => self
                .derive_consensus_chain_byte_fee_extrinsic(consensus_block_hash, domain_id)
                .map(|consensus_chain_byte_fee_extrinsic| {
                    FraudProofVerificationInfoResponse::ConsensusChainByteFeeExtrinsic(
                        consensus_chain_byte_fee_extrinsic,
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
            FraudProofVerificationInfoRequest::ExtrinsicDecodableCheck {
                domain_id,
                opaque_extrinsic,
            } => self
                .is_decodable_extrinsic(consensus_block_hash, domain_id, opaque_extrinsic)
                .map(|is_decodable| {
                    FraudProofVerificationInfoResponse::ExtrinsicDecodableCheck(is_decodable)
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
            FraudProofVerificationInfoRequest::CheckExtrinsicsInSingleContext {
                domain_id,
                domain_block_number,
                domain_block_hash,
                domain_block_state_root,
                extrinsics,
                storage_proof,
            } => self
                .check_extrinsics_in_single_context_v1(
                    consensus_block_hash,
                    domain_id,
                    (domain_block_number, domain_block_hash),
                    domain_block_state_root,
                    extrinsics,
                    storage_proof,
                )
                .map(FraudProofVerificationInfoResponse::CheckExtrinsicsInSingleContext),
            FraudProofVerificationInfoRequest::StorageKey { domain_id, req } => {
                Some(FraudProofVerificationInfoResponse::StorageKey(
                    self.storage_key(consensus_block_hash, domain_id, req),
                ))
            }
            FraudProofVerificationInfoRequest::XDMValidationCheck {
                domain_id,
                opaque_extrinsic,
            } => Some(FraudProofVerificationInfoResponse::XDMValidationCheck(
                self.is_valid_xdm(consensus_block_hash, domain_id, opaque_extrinsic),
            )),
            FraudProofVerificationInfoRequest::DomainChainsAllowlistUpdateExtrinsic(domain_id) => {
                Some(
                    FraudProofVerificationInfoResponse::DomainChainAllowlistUpdateExtrinsic(
                        self.derive_domain_chain_allowlist_update_extrinsic(
                            consensus_block_hash,
                            domain_id,
                        )
                        .map(DomainChainAllowlistUpdateExtrinsic::EncodedExtrinsic)
                        .unwrap_or(DomainChainAllowlistUpdateExtrinsic::None),
                    ),
                )
            }
        }
    }

    fn derive_bundle_digest(
        &self,
        consensus_block_hash: H256,
        domain_id: DomainId,
        bundle_body: Vec<OpaqueExtrinsic>,
    ) -> Option<H256> {
        let domain_runtime_code = self.get_domain_runtime_code(consensus_block_hash, domain_id)?;
        self.derive_bundle_digest_v2(domain_runtime_code, bundle_body)
    }

    fn derive_bundle_digest_v2(
        &self,
        domain_runtime_code: Vec<u8>,
        bundle_body: Vec<OpaqueExtrinsic>,
    ) -> Option<H256> {
        let mut extrinsics = Vec::with_capacity(bundle_body.len());
        for opaque_extrinsic in bundle_body {
            let ext =
                DomainBlock::Extrinsic::decode(&mut opaque_extrinsic.encode().as_slice()).ok()?;
            extrinsics.push(ext);
        }

        let domain_stateless_runtime = StatelessRuntime::<Block, DomainBlock, _>::new(
            self.domain_executor.clone(),
            domain_runtime_code.into(),
        );

        let ext_signers: Vec<_> = domain_stateless_runtime
            .extract_signer(extrinsics)
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
        domain_block_id: (BlockNumber, H256),
        pre_state_root: H256,
        encoded_proof: Vec<u8>,
        execution_method: &str,
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

        let (domain_block_number, domain_block_hash) = domain_block_id;
        let mut domain_extensions = (self.domain_extensions_factory_creator)(
            self.consensus_client.clone(),
            self.domain_executor.clone(),
        )
        .extensions_for(domain_block_hash.into(), domain_block_number.into());

        execution_proof_check::<<DomainBlock::Header as HeaderT>::Hashing, _>(
            pre_state_root.into(),
            proof,
            &mut Default::default(),
            self.domain_executor.as_ref(),
            execution_method,
            call_data,
            &runtime_code,
            &mut domain_extensions,
        )
        .ok()
    }

    fn check_extrinsics_in_single_context(
        &self,
        domain_runtime_code: Vec<u8>,
        domain_block_id: (BlockNumber, H256),
        domain_block_state_root: H256,
        bundle_extrinsics: Vec<OpaqueExtrinsic>,
        encoded_proof: Vec<u8>,
    ) -> Option<Option<u32>> {
        let storage_proof: StorageProof = Decode::decode(&mut encoded_proof.as_ref()).ok()?;
        let (domain_block_number, domain_block_hash) = domain_block_id;

        let raw_response = self.execution_proof_check(
            domain_block_id,
            domain_block_state_root,
            storage_proof.encode(),
            CHECK_EXTRINSICS_AND_DO_PRE_DISPATCH_METHOD_NAME,
            // The call data must be encoded form of arguments to `DomainCoreApi::check_extrinsic_and_do_pre_dispatch`
            &(&bundle_extrinsics, &domain_block_number, &domain_block_hash).encode(),
            domain_runtime_code,
        )?;

        let bundle_extrinsics_validity_response: Result<(), CheckExtrinsicsValidityError> =
            Decode::decode(&mut raw_response.as_slice()).ok()?;
        if let Err(bundle_extrinsic_validity_error) = bundle_extrinsics_validity_response {
            Some(Some(bundle_extrinsic_validity_error.extrinsic_index))
        } else {
            Some(None)
        }
    }

    fn construct_domain_inherent_extrinsic(
        &self,
        domain_runtime_code: Vec<u8>,
        domain_inherent_extrinsic_data: DomainInherentExtrinsicData,
    ) -> Option<DomainInherentExtrinsic> {
        let DomainInherentExtrinsicData {
            timestamp,
            maybe_domain_runtime_upgrade,
            consensus_transaction_byte_fee,
            domain_chain_allowlist,
            maybe_sudo_runtime_call,
        } = domain_inherent_extrinsic_data;

        let domain_stateless_runtime = StatelessRuntime::<Block, DomainBlock, _>::new(
            self.domain_executor.clone(),
            domain_runtime_code.into(),
        );

        let domain_timestamp_extrinsic = domain_stateless_runtime
            .construct_timestamp_extrinsic(timestamp)
            .ok()
            .map(|ext| ext.encode())?;

        let consensus_chain_byte_fee_extrinsic = domain_stateless_runtime
            .construct_consensus_chain_byte_fee_extrinsic(consensus_transaction_byte_fee)
            .ok()
            .map(|ext| ext.encode())?;

        let maybe_domain_chain_allowlist_extrinsic = if !domain_chain_allowlist.is_empty() {
            Some(
                domain_stateless_runtime
                    .construct_domain_update_chain_allowlist_extrinsic(domain_chain_allowlist)
                    .ok()
                    .map(|ext| ext.encode())?,
            )
        } else {
            None
        };

        let maybe_domain_set_code_extrinsic = match maybe_domain_runtime_upgrade {
            None => None,
            Some(upgraded_runtime_code) => Some(
                domain_stateless_runtime
                    .construct_set_code_extrinsic(upgraded_runtime_code)
                    .ok()
                    .map(|ext| ext.encode())?,
            ),
        };

        let maybe_domain_sudo_call_extrinsic = match maybe_sudo_runtime_call {
            None => None,
            Some(call) => Some(
                domain_stateless_runtime
                    .construct_domain_sudo_extrinsic(call)
                    .ok()
                    .map(|call| call.encode())?,
            ),
        };

        Some(DomainInherentExtrinsic {
            domain_timestamp_extrinsic,
            maybe_domain_chain_allowlist_extrinsic,
            consensus_chain_byte_fee_extrinsic,
            maybe_domain_set_code_extrinsic,
            maybe_domain_sudo_call_extrinsic,
        })
    }

    fn domain_storage_key(
        &self,
        domain_runtime_code: Vec<u8>,
        req: DomainStorageKeyRequest,
    ) -> Option<Vec<u8>> {
        let domain_stateless_runtime = StatelessRuntime::<Block, DomainBlock, _>::new(
            self.domain_executor.clone(),
            domain_runtime_code.into(),
        );
        let key = match req {
            DomainStorageKeyRequest::BlockFees => domain_stateless_runtime.block_fees_storage_key(),
            DomainStorageKeyRequest::Transfers => domain_stateless_runtime.transfers_storage_key(),
        }
        .ok()?;
        Some(key)
    }

    fn domain_runtime_call(
        &self,
        domain_runtime_code: Vec<u8>,
        call: StatelessDomainRuntimeCall,
    ) -> Option<bool> {
        let domain_stateless_runtime = StatelessRuntime::<Block, DomainBlock, _>::new(
            self.domain_executor.clone(),
            domain_runtime_code.into(),
        );

        match call {
            StatelessDomainRuntimeCall::IsTxInRange {
                opaque_extrinsic,
                bundle_vrf_hash,
                domain_tx_range,
            } => {
                let encoded_extrinsic = opaque_extrinsic.encode();
                let extrinsic =
                    DomainBlock::Extrinsic::decode(&mut encoded_extrinsic.as_slice()).ok()?;
                domain_stateless_runtime
                    .is_within_tx_range(&extrinsic, &bundle_vrf_hash, &domain_tx_range)
                    .ok()
            }
            StatelessDomainRuntimeCall::IsInherentExtrinsic(opaque_extrinsic) => {
                let encoded_extrinsic = opaque_extrinsic.encode();
                let extrinsic =
                    DomainBlock::Extrinsic::decode(&mut encoded_extrinsic.as_slice()).ok()?;
                domain_stateless_runtime
                    .is_inherent_extrinsic(&extrinsic)
                    .ok()
            }
            StatelessDomainRuntimeCall::IsDecodableExtrinsic(opaque_extrinsic) => Some(matches!(
                domain_stateless_runtime.decode_extrinsic(opaque_extrinsic),
                Ok(Ok(_))
            )),
            StatelessDomainRuntimeCall::IsValidDomainSudoCall(encoded_extrinsic) => {
                domain_stateless_runtime
                    .is_valid_sudo_call(encoded_extrinsic)
                    .ok()
            }
        }
    }

    fn bundle_weight(
        &self,
        domain_runtime_code: Vec<u8>,
        bundle_body: Vec<OpaqueExtrinsic>,
    ) -> Option<Weight> {
        let domain_stateless_runtime = StatelessRuntime::<Block, DomainBlock, _>::new(
            self.domain_executor.clone(),
            domain_runtime_code.into(),
        );
        let mut estimated_bundle_weight = Weight::default();
        for opaque_extrinsic in bundle_body {
            let encoded_extrinsic = opaque_extrinsic.encode();
            let extrinsic =
                DomainBlock::Extrinsic::decode(&mut encoded_extrinsic.as_slice()).ok()?;
            let tx_weight = domain_stateless_runtime.extrinsic_weight(&extrinsic).ok()?;
            estimated_bundle_weight = estimated_bundle_weight.saturating_add(tx_weight);
        }
        Some(estimated_bundle_weight)
    }

    fn extract_xdm_mmr_proof(
        &self,
        domain_runtime_code: Vec<u8>,
        opaque_extrinsic: Vec<u8>,
    ) -> Option<Option<Vec<u8>>> {
        let domain_stateless_runtime = StatelessRuntime::<Block, DomainBlock, _>::new(
            self.domain_executor.clone(),
            domain_runtime_code.into(),
        );
        let extrinsic = DomainBlock::Extrinsic::decode(&mut opaque_extrinsic.as_slice()).ok()?;
        domain_stateless_runtime
            .extract_xdm_mmr_proof(&extrinsic)
            .ok()
    }
}

type CreateProofCheckBackedResult<H> = Result<
    (TrieBackend<MemoryDB<H>, H>, sp_trie::recorder::Recorder<H>),
    Box<dyn sp_state_machine::Error>,
>;

/// Creates a memory db backed with a recorder.
/// Fork of `sp_state_machine::create_proof_check_backend` with recorder enabled.
fn create_proof_check_backend_with_recorder<H>(
    root: H::Out,
    proof: StorageProof,
) -> CreateProofCheckBackedResult<H>
where
    H: Hasher,
    H::Out: Codec,
{
    let db = proof.into_memory_db();
    let recorder = sp_trie::recorder::Recorder::<H>::default();

    if db.contains(&root, hash_db::EMPTY_PREFIX) {
        let backend = TrieBackendBuilder::new(db, root)
            .with_recorder(recorder.clone())
            .build();
        Ok((backend, recorder))
    } else {
        Err(Box::new(sp_state_machine::ExecutionError::InvalidProof))
    }
}

/// Execution Proof check error.
#[derive(Debug)]
pub(crate) enum ExecutionProofCheckError {
    /// Holds the actual execution proof error
    // While we don't read the error, we'd still like it to be present in case we need it later
    #[allow(dead_code)]
    ExecutionError(Box<dyn sp_state_machine::Error>),
    /// Error when storage proof contains unused node keys.
    UnusedNodes,
}

impl From<Box<dyn sp_state_machine::Error>> for ExecutionProofCheckError {
    fn from(value: Box<dyn sp_state_machine::Error>) -> Self {
        Self::ExecutionError(value)
    }
}

#[allow(clippy::too_many_arguments)]
/// Executes the given proof using the runtime
/// The only difference between sp_state_machine::execution_proof_check is Extensions
pub(crate) fn execution_proof_check<H, Exec>(
    root: H::Out,
    proof: StorageProof,
    overlay: &mut OverlayedChanges<H>,
    exec: &Exec,
    method: &str,
    call_data: &[u8],
    runtime_code: &RuntimeCode,
    extensions: &mut Extensions,
) -> Result<Vec<u8>, ExecutionProofCheckError>
where
    H: Hasher,
    H::Out: Ord + 'static + Codec,
    Exec: CodeExecutor + Clone + 'static,
{
    let expected_nodes_to_be_read = proof.iter_nodes().count();
    let (trie_backend, recorder) = create_proof_check_backend_with_recorder::<H>(root, proof)?;
    let result = StateMachine::<_, H, Exec>::new(
        &trie_backend,
        overlay,
        exec,
        method,
        call_data,
        extensions,
        runtime_code,
        CallContext::Offchain,
    )
    .execute()?;

    let recorded_proof = recorder.drain_storage_proof();
    if recorded_proof.iter_nodes().count() != expected_nodes_to_be_read {
        return Err(ExecutionProofCheckError::UnusedNodes);
    }

    Ok(result)
}
