//! Invalid transaction proof.

use crate::domain_extrinsics_builder::BuildDomainExtrinsics;
use crate::domain_runtime_code::retrieve_domain_runtime_code;
use crate::verifier_api::VerifierApi;
use codec::{Decode, Encode};
use domain_block_preprocessor::runtime_api_light::RuntimeApiLight;
use domain_runtime_primitives::opaque::Block;
use domain_runtime_primitives::{DomainCoreApi, Hash};
use sc_client_api::StorageProof;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domains::fraud_proof::{InvalidTransactionProof, VerificationError};
use sp_domains::{DomainId, DomainsApi};
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Header as HeaderT};
use sp_runtime::{OpaqueExtrinsic, Storage};
use sp_trie::{read_trie_value, LayoutV1};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

/// Invalid transaction proof verifier.
pub struct InvalidTransactionProofVerifier<
    CBlock,
    CClient,
    Hash,
    Exec,
    VerifierClient,
    DomainExtrinsicsBuilder,
> {
    consensus_client: Arc<CClient>,
    executor: Arc<Exec>,
    verifier_client: VerifierClient,
    domain_extrinsics_builder: DomainExtrinsicsBuilder,
    _phantom: PhantomData<(CBlock, Hash)>,
}

impl<CBlock, CClient, Hash, Exec, VerifierClient, DomainExtrinsicsBuilder> Clone
    for InvalidTransactionProofVerifier<
        CBlock,
        CClient,
        Hash,
        Exec,
        VerifierClient,
        DomainExtrinsicsBuilder,
    >
where
    VerifierClient: Clone,
    DomainExtrinsicsBuilder: Clone,
{
    fn clone(&self) -> Self {
        Self {
            consensus_client: self.consensus_client.clone(),
            executor: self.executor.clone(),
            verifier_client: self.verifier_client.clone(),
            domain_extrinsics_builder: self.domain_extrinsics_builder.clone(),
            _phantom: self._phantom,
        }
    }
}

fn create_runtime_api_light<Exec>(
    storage_proof: StorageProof,
    state_root: &Hash,
    executor: Arc<Exec>,
    wasm_bundle: Cow<'static, [u8]>,
    extrinsic: OpaqueExtrinsic,
) -> Result<RuntimeApiLight<Exec>, VerificationError>
where
    Exec: CodeExecutor,
{
    let mut runtime_api_light = RuntimeApiLight::new(executor, wasm_bundle);

    let sender = <RuntimeApiLight<Exec> as DomainCoreApi<Block>>::extract_signer(
        &runtime_api_light,
        Default::default(),
        vec![extrinsic],
    )?
    .into_iter()
    .next()
    .and_then(|(maybe_signer, _)| maybe_signer)
    .ok_or(VerificationError::SignerNotFound)?;

    let storage_keys = <RuntimeApiLight<Exec> as DomainCoreApi<Block>>::storage_keys_for_verifying_transaction_validity(
        &runtime_api_light,
        Default::default(),
        sender
    )?
    .map_err(|e| {
        sp_api::ApiError::Application(Box::from(format!(
            "Failed to fetch storage keys for tx validity: {e:?}"
        )))
    })?;

    let db = storage_proof.into_memory_db::<BlakeTwo256>();

    let mut top_storage_map = BTreeMap::new();
    for storage_key in storage_keys.into_iter() {
        let storage_value =
            read_trie_value::<LayoutV1<BlakeTwo256>, _>(&db, state_root, &storage_key, None, None)
                .map_err(|_| VerificationError::InvalidStorageProof)?
                .ok_or_else(|| VerificationError::StateNotFound(storage_key.clone()))?;
        top_storage_map.insert(storage_key, storage_value);
    }

    let storage = Storage {
        top: top_storage_map,
        children_default: Default::default(),
    };

    runtime_api_light.set_storage(storage);

    Ok(runtime_api_light)
}

impl<CBlock, CClient, Hash, Exec, VerifierClient, DomainExtrinsicsBuilder>
    InvalidTransactionProofVerifier<
        CBlock,
        CClient,
        Hash,
        Exec,
        VerifierClient,
        DomainExtrinsicsBuilder,
    >
where
    CBlock: BlockT,
    Hash: Encode + Decode,
    H256: Into<CBlock::Hash>,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + Send + Sync,
    CClient::Api: DomainsApi<CBlock, domain_runtime_primitives::BlockNumber, Hash>,
    VerifierClient: VerifierApi,
    DomainExtrinsicsBuilder: BuildDomainExtrinsics<CBlock>,
    Exec: CodeExecutor + 'static,
{
    /// Constructs a new instance of [`InvalidTransactionProofVerifier`].
    pub fn new(
        consensus_client: Arc<CClient>,
        executor: Arc<Exec>,
        verifier_client: VerifierClient,
        domain_extrinsics_builder: DomainExtrinsicsBuilder,
    ) -> Self {
        Self {
            consensus_client,
            executor,
            verifier_client,
            domain_extrinsics_builder,
            _phantom: Default::default(),
        }
    }

    fn fetch_consensus_block_header(
        &self,
        domain_id: DomainId,
        block_number: u32,
    ) -> Result<CBlock::Header, VerificationError> {
        let consensus_block_hash: CBlock::Hash = self
            .verifier_client
            .primary_hash(domain_id, block_number)?
            .into();

        let header = self
            .consensus_client
            .header(consensus_block_hash)?
            .ok_or_else(|| {
                sp_blockchain::Error::Backend(format!(
                    "Header for {consensus_block_hash} not found"
                ))
            })?;

        Ok(header)
    }

    /// Verifies the invalid transaction proof.
    pub fn verify(
        &self,
        invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), VerificationError> {
        let InvalidTransactionProof {
            domain_id,
            block_number,
            domain_block_hash,
            invalid_extrinsic,
            storage_proof,
        } = invalid_transaction_proof;

        // TODO: Validate bundle solution.
        // - Bundle is valid and is produced by a legit executor.
        // - Bundle author, who will be slashed, can be extracted in runtime.

        let header = self.fetch_consensus_block_header(*domain_id, *block_number)?;
        let consensus_parent_hash = *header.parent_hash();

        let domain_runtime_code = retrieve_domain_runtime_code(
            *domain_id,
            consensus_parent_hash,
            &self.consensus_client,
        )?;

        // TODO: Verifiable invalid extrinsic.
        // Once the bundle validity is checked, we ought to know about `extrinsics_root`, plus a
        // Merkle proof of invalid extrinsic, we can get the original invalid extrinsic data in a
        // verifiable way.
        let extrinsic = OpaqueExtrinsic::from_bytes(invalid_extrinsic)?;

        let state_root =
            self.verifier_client
                .state_root(*domain_id, *block_number, *domain_block_hash)?;

        let runtime_api_light = create_runtime_api_light(
            storage_proof.clone(),
            &state_root,
            self.executor.clone(),
            domain_runtime_code.wasm_bundle.into(),
            extrinsic.clone(),
        )?;

        let check_result =
            <RuntimeApiLight<Exec> as DomainCoreApi<Block>>::check_transaction_validity(
                &runtime_api_light,
                Default::default(), // Unused for stateless runtime api.
                extrinsic,
                *domain_block_hash,
            )?;

        if check_result.is_ok() {
            Err(VerificationError::ValidTransaction)
        } else {
            Ok(())
        }
    }
}

/// Verifies invalid transaction proof.
pub trait VerifyInvalidTransactionProof {
    /// Returns `Ok(())` if given `invalid_transaction_proof` is legitimate.
    fn verify_invalid_transaction_proof(
        &self,
        invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), VerificationError>;
}

impl<CBlock, Client, Hash, Exec, VerifierClient, DomainExtrinsicsBuilder>
    VerifyInvalidTransactionProof
    for InvalidTransactionProofVerifier<
        CBlock,
        Client,
        Hash,
        Exec,
        VerifierClient,
        DomainExtrinsicsBuilder,
    >
where
    CBlock: BlockT,
    Hash: Encode + Decode,
    H256: Into<CBlock::Hash>,
    Client: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + Send + Sync,
    Client::Api: DomainsApi<CBlock, domain_runtime_primitives::BlockNumber, Hash>,
    VerifierClient: VerifierApi,
    DomainExtrinsicsBuilder: BuildDomainExtrinsics<CBlock>,
    Exec: CodeExecutor + 'static,
{
    fn verify_invalid_transaction_proof(
        &self,
        invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), VerificationError> {
        self.verify(invalid_transaction_proof)
    }
}
