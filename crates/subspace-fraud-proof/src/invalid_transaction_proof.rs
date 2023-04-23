//! Invalid transaction proof.

use crate::domain_extrinsics_builder::BuildDomainExtrinsics;
use crate::verifier_api::VerifierApi;
use codec::{Decode, Encode};
use domain_block_preprocessor::runtime_api_light::RuntimeApiLight;
use domain_runtime_primitives::opaque::Block;
use domain_runtime_primitives::{AccountId, Balance, DomainCoreApi, Hash, Index};
use sc_client_api::StorageProof;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domains::fraud_proof::{InvalidTransactionProof, VerificationError};
use sp_domains::{DomainId, ExecutorApi};
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Header as HeaderT};
use sp_runtime::{OpaqueExtrinsic, Storage};
use sp_trie::{read_trie_value, LayoutV1};
use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::Arc;

/// Invalid transaction proof verifier.
pub struct InvalidTransactionProofVerifier<
    PBlock,
    PClient,
    Hash,
    Exec,
    VerifierClient,
    DomainExtrinsicsBuilder,
> {
    primary_chain_client: Arc<PClient>,
    executor: Arc<Exec>,
    verifier_client: VerifierClient,
    domain_extrinsics_builder: DomainExtrinsicsBuilder,
    _phantom: PhantomData<(PBlock, Hash)>,
}

impl<PBlock, PClient, Hash, Exec, VerifierClient, DomainExtrinsicsBuilder> Clone
    for InvalidTransactionProofVerifier<
        PBlock,
        PClient,
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
            primary_chain_client: self.primary_chain_client.clone(),
            executor: self.executor.clone(),
            verifier_client: self.verifier_client.clone(),
            domain_extrinsics_builder: self.domain_extrinsics_builder.clone(),
            _phantom: self._phantom,
        }
    }
}

struct AccountStorageInstance;

impl frame_support::traits::StorageInstance for AccountStorageInstance {
    fn pallet_prefix() -> &'static str {
        "System"
    }
    const STORAGE_PREFIX: &'static str = "Account";
}

type AccountStorageMap = frame_support::storage::types::StorageMap<
    AccountStorageInstance,
    frame_support::Blake2_128Concat,
    AccountId,
    frame_system::AccountInfo<Index, pallet_balances::AccountData<Balance>>,
>;

fn create_runtime_api_light<Exec>(
    storage_proof: StorageProof,
    state_root: &Hash,
    executor: Arc<Exec>,
    wasm_bundle: Cow<'static, [u8]>,
    extrinsic: OpaqueExtrinsic,
) -> Result<RuntimeApiLight<Exec>, VerificationError>
where
    Exec: CodeExecutor + 'static,
{
    let db = storage_proof.into_memory_db::<BlakeTwo256>();
    let read_value = |storage_key| {
        read_trie_value::<LayoutV1<BlakeTwo256>, _>(&db, state_root, storage_key, None, None)
            .map_err(|_| VerificationError::InvalidStorageProof)
    };

    let next_fee_multiplier_storage_key = [
        63, 20, 103, 160, 150, 188, 215, 26, 91, 106, 12, 129, 85, 226, 8, 16, 63, 46, 223, 59,
        223, 56, 29, 235, 227, 49, 171, 116, 70, 173, 223, 220,
    ];
    let next_fee_multiplier_value =
        read_value(&next_fee_multiplier_storage_key)?.ok_or_else(|| {
            VerificationError::StateNotFound(next_fee_multiplier_storage_key.to_vec())
        })?;

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
    let sender = AccountId::decode(&mut sender.as_slice())?;

    let account_storage_key = AccountStorageMap::hashed_key_for(sender);
    let account_value = read_value(&account_storage_key)?
        .ok_or_else(|| VerificationError::StateNotFound(account_storage_key.clone()))?;

    let storage = Storage {
        top: [
            (
                next_fee_multiplier_storage_key.to_vec(),
                next_fee_multiplier_value,
            ),
            (account_storage_key, account_value),
        ]
        .into_iter()
        .collect(),
        children_default: Default::default(),
    };

    runtime_api_light.set_storage(storage);

    Ok(runtime_api_light)
}

impl<PBlock, PClient, Hash, Exec, VerifierClient, DomainExtrinsicsBuilder>
    InvalidTransactionProofVerifier<
        PBlock,
        PClient,
        Hash,
        Exec,
        VerifierClient,
        DomainExtrinsicsBuilder,
    >
where
    PBlock: BlockT,
    Hash: Encode + Decode,
    H256: Into<PBlock::Hash>,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + Send + Sync,
    PClient::Api: ExecutorApi<PBlock, Hash>,
    VerifierClient: VerifierApi,
    DomainExtrinsicsBuilder: BuildDomainExtrinsics<PBlock>,
    Exec: CodeExecutor + 'static,
{
    /// Constructs a new instance of [`InvalidStateTransitionProofVerifier`].
    pub fn new(
        primary_chain_client: Arc<PClient>,
        executor: Arc<Exec>,
        verifier_client: VerifierClient,
        domain_extrinsics_builder: DomainExtrinsicsBuilder,
    ) -> Self {
        Self {
            primary_chain_client,
            executor,
            verifier_client,
            domain_extrinsics_builder,
            _phantom: Default::default(),
        }
    }

    fn fetch_domain_extrinsic(
        &self,
        domain_id: DomainId,
        extrinsic_index: u32,
        primary_hash: PBlock::Hash,
        wasm_bundle: Vec<u8>,
    ) -> Result<OpaqueExtrinsic, VerificationError> {
        let domain_extrinsics = self
            .domain_extrinsics_builder
            .build_domain_extrinsics(domain_id, primary_hash, wasm_bundle)
            .map_err(|_| VerificationError::FailedToBuildDomainExtrinsics)?;

        let extrinsic = domain_extrinsics
            .into_iter()
            .nth(extrinsic_index as usize)
            .ok_or(VerificationError::DomainExtrinsicNotFound(extrinsic_index))?;

        Ok(OpaqueExtrinsic::from_bytes(&extrinsic)?)
    }

    /// Verifies the invalid state transition proof.
    pub fn verify(
        &self,
        invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), VerificationError> {
        let InvalidTransactionProof {
            domain_id,
            block_number,
            domain_block_hash,
            extrinsic_index,
            storage_proof,
        } = invalid_transaction_proof;

        let primary_hash: PBlock::Hash = self
            .verifier_client
            .primary_hash(*domain_id, *block_number)?
            .into();

        let header = self
            .primary_chain_client
            .header(primary_hash)?
            .ok_or_else(|| {
                sp_blockchain::Error::Backend(format!("Header for {primary_hash} not found"))
            })?;
        let primary_hash = header.hash();
        let primary_parent_hash = *header.parent_hash();

        let domain_runtime_code = crate::domain_runtime_code::retrieve_domain_runtime_code(
            *domain_id,
            primary_parent_hash,
            &self.primary_chain_client,
        )?;

        let extrinsic = self.fetch_domain_extrinsic(
            *domain_id,
            *extrinsic_index,
            primary_hash,
            domain_runtime_code.wasm_bundle.to_vec(),
        )?;

        let state_root =
            self.verifier_client
                .state_root(*domain_id, *block_number, *domain_block_hash)?;

        let runtime_api_light = create_runtime_api_light(
            storage_proof.clone(),
            &state_root,
            self.executor.clone(),
            domain_runtime_code.wasm_bundle,
            extrinsic.clone(),
        )?;

        let check_result = <RuntimeApiLight<Exec> as DomainCoreApi<Block>>::check_transaction_fee(
            &runtime_api_light,
            Default::default(),
            extrinsic,
        )?;

        if check_result.is_ok() {
            Err(VerificationError::SufficientBalance)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    fn verify_with_extrinsic(
        &self,
        extrinsic: Vec<u8>,
        invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), VerificationError> {
        let InvalidTransactionProof {
            domain_id,
            block_number,
            domain_block_hash,
            extrinsic_index: _,
            storage_proof,
        } = invalid_transaction_proof;

        let primary_hash: PBlock::Hash = self
            .verifier_client
            .primary_hash(*domain_id, *block_number)?
            .into();

        let header = self
            .primary_chain_client
            .header(primary_hash)?
            .ok_or_else(|| {
                sp_blockchain::Error::Backend(format!("Header for {primary_hash} not found"))
            })?;
        let primary_parent_hash = *header.parent_hash();

        let domain_runtime_code = crate::domain_runtime_code::retrieve_domain_runtime_code(
            *domain_id,
            primary_parent_hash,
            &self.primary_chain_client,
        )?;

        let extrinsic = OpaqueExtrinsic::from_bytes(&extrinsic)?;

        let state_root =
            self.verifier_client
                .state_root(*domain_id, *block_number, *domain_block_hash)?;

        let runtime_api_light = create_runtime_api_light(
            storage_proof.clone(),
            &state_root,
            self.executor.clone(),
            domain_runtime_code.wasm_bundle,
            extrinsic.clone(),
        )?;

        let check_result = <RuntimeApiLight<Exec> as DomainCoreApi<Block>>::check_transaction_fee(
            &runtime_api_light,
            Default::default(),
            extrinsic,
        )?;

        if check_result.is_ok() {
            Err(VerificationError::SufficientBalance)
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

    #[cfg(test)]
    fn verify_with_extrinsic(
        &self,
        extrinsic: Vec<u8>,
        invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), VerificationError>;
}

impl<PBlock, Client, Hash, Exec, VerifierClient, DomainExtrinsicsBuilder>
    VerifyInvalidTransactionProof
    for InvalidTransactionProofVerifier<
        PBlock,
        Client,
        Hash,
        Exec,
        VerifierClient,
        DomainExtrinsicsBuilder,
    >
where
    PBlock: BlockT,
    Hash: Encode + Decode,
    H256: Into<PBlock::Hash>,
    Client: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + Send + Sync,
    Client::Api: ExecutorApi<PBlock, Hash>,
    VerifierClient: VerifierApi,
    DomainExtrinsicsBuilder: BuildDomainExtrinsics<PBlock>,
    Exec: CodeExecutor + 'static,
{
    fn verify_invalid_transaction_proof(
        &self,
        invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), VerificationError> {
        self.verify(invalid_transaction_proof)
    }

    #[cfg(test)]
    fn verify_with_extrinsic(
        &self,
        extrinsic: Vec<u8>,
        invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), VerificationError> {
        self.verify_with_extrinsic(extrinsic, invalid_transaction_proof)
    }
}
