#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::fraud_proof::{
    InvalidBundlesProof, InvalidBundlesProofData, InvalidExtrinsicsRootProof,
    InvalidStateTransitionProof, MmrRootProof, ValidBundleProof, VerificationError,
};
use crate::storage_proof::{self, *};
use crate::{
    DomainInherentExtrinsic, DomainInherentExtrinsicData, DomainStorageKeyRequest,
    StatelessDomainRuntimeCall, fraud_proof_runtime_interface,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use domain_runtime_primitives::BlockNumber;
use hash_db::Hasher;
use parity_scale_codec::{Decode, Encode};
use sp_core::H256;
use sp_core::storage::StorageKey;
use sp_domains::bundle::{BundleValidity, InboxedBundle, InvalidBundleType};
use sp_domains::execution_receipt::{BlockFees, ExecutionReceipt, Transfers};
use sp_domains::extrinsics::deduplicate_and_shuffle_extrinsics;
use sp_domains::proof_provider_and_verifier::StorageProofVerifier;
use sp_domains::valued_trie::valued_ordered_trie_root;
use sp_domains::{
    DomainId, ExtrinsicDigest, HeaderHashFor, HeaderHashingFor, HeaderNumberFor,
    INITIAL_DOMAIN_TX_RANGE, RuntimeId,
};
use sp_runtime::generic::Digest;
use sp_runtime::traits::{
    Block as BlockT, Hash, Header as HeaderT, NumberFor, UniqueSaturatedInto, Zero,
};
use sp_runtime::{OpaqueExtrinsic, SaturatedConversion};
use sp_subspace_mmr::{ConsensusChainMmrLeafProof, MmrProofVerifier};
use sp_trie::{LayoutV1, StorageProof};
use subspace_core_primitives::U256;
use trie_db::node::Value;

/// Verifies invalid domain extrinsic root fraud proof.
pub fn verify_invalid_domain_extrinsics_root_fraud_proof<
    CBlock,
    Balance,
    DomainHeader,
    Hashing,
    SKP,
>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    >,
    fraud_proof: &InvalidExtrinsicsRootProof,
    domain_id: DomainId,
    runtime_id: RuntimeId,
    state_root: CBlock::Hash,
    domain_runtime_code: Vec<u8>,
) -> Result<(), VerificationError<DomainHeader::Hash>>
where
    CBlock: BlockT,
    DomainHeader: HeaderT,
    DomainHeader::Hash: Into<H256> + PartialEq + Copy,
    Hashing: Hasher<Out = CBlock::Hash>,
    SKP: FraudProofStorageKeyProvider<NumberFor<CBlock>>,
    Balance: Encode + Zero + Default,
{
    let InvalidExtrinsicsRootProof {
        valid_bundle_digests,
        invalid_inherent_extrinsic_proofs,
        maybe_domain_runtime_upgraded_proof,
        domain_chain_allowlist_proof,
        domain_sudo_call_proof,
        evm_domain_contract_creation_allowed_by_call_proof,
    } = fraud_proof;

    let invalid_inherent_extrinsic_data =
        <InvalidInherentExtrinsicDataProof as BasicStorageProof<CBlock>>::verify::<SKP>(
            invalid_inherent_extrinsic_proofs.clone(),
            (),
            &state_root,
        )?;

    let maybe_domain_runtime_upgrade =
        maybe_domain_runtime_upgraded_proof.verify::<CBlock, SKP>(runtime_id, &state_root)?;

    let domain_chain_allowlist = <DomainChainsAllowlistUpdateStorageProof as BasicStorageProof<
        CBlock,
    >>::verify::<SKP>(
        domain_chain_allowlist_proof.clone(), domain_id, &state_root
    )?;

    let domain_sudo_call = <DomainSudoCallStorageProof as BasicStorageProof<CBlock>>::verify::<SKP>(
        domain_sudo_call_proof.clone(),
        domain_id,
        &state_root,
    )?;

    let evm_domain_contract_creation_allowed_by_call =
        <EvmDomainContractCreationAllowedByCallStorageProof as BasicStorageProof<CBlock>>::verify::<
            SKP,
        >(
            evm_domain_contract_creation_allowed_by_call_proof.clone(),
            domain_id,
            &state_root,
        )?;

    let shuffling_seed = invalid_inherent_extrinsic_data.extrinsics_shuffling_seed;

    let domain_inherent_extrinsic_data = DomainInherentExtrinsicData {
        timestamp: invalid_inherent_extrinsic_data.timestamp,
        maybe_domain_runtime_upgrade,
        consensus_transaction_byte_fee: invalid_inherent_extrinsic_data
            .consensus_transaction_byte_fee,
        domain_chain_allowlist,
        maybe_sudo_runtime_call: domain_sudo_call.maybe_call,
        maybe_evm_domain_contract_creation_allowed_by_call:
            evm_domain_contract_creation_allowed_by_call.maybe_call,
    };

    let DomainInherentExtrinsic {
        domain_timestamp_extrinsic,
        maybe_domain_chain_allowlist_extrinsic,
        consensus_chain_byte_fee_extrinsic,
        maybe_domain_set_code_extrinsic,
        maybe_domain_sudo_call_extrinsic,
        maybe_evm_domain_contract_creation_allowed_by_call_extrinsic,
    } = fraud_proof_runtime_interface::construct_domain_inherent_extrinsic(
        domain_runtime_code,
        domain_inherent_extrinsic_data,
    )
    .ok_or(VerificationError::FailedToDeriveDomainInherentExtrinsic)?;

    let bad_receipt_valid_bundle_digests = bad_receipt.valid_bundle_digests();
    if valid_bundle_digests.len() != bad_receipt_valid_bundle_digests.len() {
        return Err(VerificationError::InvalidBundleDigest);
    }

    let mut bundle_extrinsics_digests = Vec::new();
    for (bad_receipt_valid_bundle_digest, bundle_digest) in bad_receipt_valid_bundle_digests
        .into_iter()
        .zip(valid_bundle_digests)
    {
        let bundle_digest_hash =
            HeaderHashingFor::<DomainHeader>::hash_of(&bundle_digest.bundle_digest);
        if bundle_digest_hash != bad_receipt_valid_bundle_digest {
            return Err(VerificationError::InvalidBundleDigest);
        }

        bundle_extrinsics_digests.extend(bundle_digest.bundle_digest.clone());
    }

    let mut ordered_extrinsics =
        deduplicate_and_shuffle_extrinsics(bundle_extrinsics_digests, shuffling_seed);

    // NOTE: the order of the inherent extrinsics MUST be the same as the pallet order defined in
    // the `construct_runtime` macro for domains.
    // Currently this is the following order:
    // - timestamp extrinsic
    // - executive set_code extrinsic
    // - messenger update_domain_allowlist extrinsic
    // - evm_tracker contract_creation_allowed_by extrinsic
    // - block_fees transaction_byte_fee_extrinsic
    // - domain_sudo extrinsic
    // Since we use `push_front`, the extrinsics should be pushed in reverse order.
    // TODO: this will not be valid once we have a different runtime. To achieve consistency across
    // domains, we should define a runtime api for each domain, which orders the extrinsics the
    // same way the inherents are derived while the domain block is being built.

    if let Some(domain_sudo_call_extrinsic) = maybe_domain_sudo_call_extrinsic {
        let domain_sudo_call_extrinsic = ExtrinsicDigest::new::<
            LayoutV1<HeaderHashingFor<DomainHeader>>,
        >(domain_sudo_call_extrinsic);
        ordered_extrinsics.push_front(domain_sudo_call_extrinsic);
    }

    let transaction_byte_fee_extrinsic = ExtrinsicDigest::new::<
        LayoutV1<HeaderHashingFor<DomainHeader>>,
    >(consensus_chain_byte_fee_extrinsic);
    ordered_extrinsics.push_front(transaction_byte_fee_extrinsic);

    if let Some(evm_domain_contract_creation_allowed_by_call_extrinsic) =
        maybe_evm_domain_contract_creation_allowed_by_call_extrinsic
    {
        let evm_domain_contract_creation_allowed_by_call_extrinsic =
            ExtrinsicDigest::new::<LayoutV1<HeaderHashingFor<DomainHeader>>>(
                evm_domain_contract_creation_allowed_by_call_extrinsic,
            );
        ordered_extrinsics.push_front(evm_domain_contract_creation_allowed_by_call_extrinsic);
    }

    if let Some(domain_chain_allowlist_extrinsic) = maybe_domain_chain_allowlist_extrinsic {
        let domain_chain_allowlist_extrinsic = ExtrinsicDigest::new::<
            LayoutV1<HeaderHashingFor<DomainHeader>>,
        >(domain_chain_allowlist_extrinsic);
        ordered_extrinsics.push_front(domain_chain_allowlist_extrinsic);
    }

    if let Some(domain_set_code_extrinsic) = maybe_domain_set_code_extrinsic {
        let domain_set_code_extrinsic = ExtrinsicDigest::new::<
            LayoutV1<HeaderHashingFor<DomainHeader>>,
        >(domain_set_code_extrinsic);
        ordered_extrinsics.push_front(domain_set_code_extrinsic);
    }

    let timestamp_extrinsic = ExtrinsicDigest::new::<LayoutV1<HeaderHashingFor<DomainHeader>>>(
        domain_timestamp_extrinsic,
    );
    ordered_extrinsics.push_front(timestamp_extrinsic);

    let ordered_trie_node_values = ordered_extrinsics
        .iter()
        .map(|ext_digest| match ext_digest {
            ExtrinsicDigest::Data(data) => Value::Inline(data),
            ExtrinsicDigest::Hash(hash) => Value::Node(hash.0.as_slice()),
        })
        .collect();

    let extrinsics_root = valued_ordered_trie_root::<LayoutV1<HeaderHashingFor<DomainHeader>>>(
        ordered_trie_node_values,
    );
    if *bad_receipt.domain_block_extrinsics_root() == extrinsics_root {
        return Err(VerificationError::InvalidProof);
    }

    Ok(())
}

/// Verifies valid bundle fraud proof.
pub fn verify_valid_bundle_fraud_proof<CBlock, DomainHeader, Balance, SKP>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    >,
    fraud_proof: &ValidBundleProof<NumberFor<CBlock>, CBlock::Hash, DomainHeader>,
    domain_id: DomainId,
    state_root: CBlock::Hash,
    domain_runtime_code: Vec<u8>,
) -> Result<(), VerificationError<DomainHeader::Hash>>
where
    CBlock: BlockT,
    CBlock::Hash: Into<H256>,
    DomainHeader: HeaderT,
    DomainHeader::Hash: Into<H256> + PartialEq + Copy,
    SKP: FraudProofStorageKeyProvider<NumberFor<CBlock>>,
    Balance: Encode + Zero + Default,
{
    let ValidBundleProof { bundle_with_proof } = fraud_proof;
    bundle_with_proof.verify::<CBlock, SKP>(domain_id, &state_root)?;
    let (extrinsics, bundle_index) = (
        bundle_with_proof.bundle.extrinsics().to_vec(),
        bundle_with_proof.bundle_index,
    );

    let valid_bundle_digest =
        fraud_proof_runtime_interface::derive_bundle_digest(domain_runtime_code, extrinsics)
            .ok_or(VerificationError::FailedToDeriveBundleDigest)?;

    let bad_valid_bundle_digest = bad_receipt
        .valid_bundle_digest_at(bundle_index as usize)
        .ok_or(VerificationError::TargetValidBundleNotFound)?;

    if bad_valid_bundle_digest.into() == valid_bundle_digest {
        Err(VerificationError::InvalidProof)
    } else {
        Ok(())
    }
}

/// Verifies invalid state transition fraud proof.
pub fn verify_invalid_state_transition_fraud_proof<CBlock, DomainHeader, Balance>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        DomainHeader::Number,
        DomainHeader::Hash,
        Balance,
    >,
    bad_receipt_parent: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        DomainHeader::Number,
        DomainHeader::Hash,
        Balance,
    >,
    fraud_proof: &InvalidStateTransitionProof,
    domain_runtime_code: Vec<u8>,
) -> Result<(), VerificationError<DomainHeader::Hash>>
where
    CBlock: BlockT,
    CBlock::Hash: Into<H256>,
    DomainHeader: HeaderT,
    DomainHeader::Hash: Into<H256> + From<H256>,
    DomainHeader::Number: UniqueSaturatedInto<BlockNumber> + From<BlockNumber>,
    Balance: Encode + Zero + Default,
{
    let InvalidStateTransitionProof {
        execution_proof,
        execution_phase,
        ..
    } = fraud_proof;

    let (pre_state_root, post_state_root) = execution_phase
        .pre_post_state_root::<CBlock, DomainHeader, Balance>(&bad_receipt, &bad_receipt_parent)?;

    let call_data = execution_phase
        .call_data::<CBlock, DomainHeader, Balance>(&bad_receipt, &bad_receipt_parent)?;

    let execution_result = fraud_proof_runtime_interface::execution_proof_check(
        (
            (*bad_receipt_parent.domain_block_number()).saturated_into(),
            (*bad_receipt_parent.domain_block_hash()).into(),
        ),
        pre_state_root,
        execution_proof.encode(),
        execution_phase.execution_method(),
        call_data.as_ref(),
        domain_runtime_code,
    )
    .ok_or(VerificationError::BadExecutionProof)?;

    let valid_post_state_root = execution_phase
        .decode_execution_result::<DomainHeader>(execution_result)?
        .into();

    let is_mismatch = valid_post_state_root != post_state_root;

    // If there is mismatch and execution phase indicate state root mismatch then the fraud proof is valid
    // If there is no mismatch and execution phase indicate non state root mismatch (i.e the trace is either long or short) then
    // the fraud proof is valid.
    let is_valid = is_mismatch == execution_phase.is_state_root_mismatch();

    if is_valid {
        Ok(())
    } else {
        Err(VerificationError::InvalidProof)
    }
}

/// Verifies invalid domain block hash fraud proof.
pub fn verify_invalid_domain_block_hash_fraud_proof<CBlock, Balance, DomainHeader>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        DomainHeader::Number,
        DomainHeader::Hash,
        Balance,
    >,
    digest_storage_proof: StorageProof,
    parent_domain_block_hash: DomainHeader::Hash,
) -> Result<(), VerificationError<DomainHeader::Hash>>
where
    CBlock: BlockT,
    Balance: PartialEq + Decode + Encode + Zero + Default,
    DomainHeader: HeaderT,
{
    let state_root = *bad_receipt.final_state_root();
    let digest_storage_key = StorageKey(sp_domains::system_digest_final_key());

    let digest = StorageProofVerifier::<DomainHeader::Hashing>::get_decoded_value::<Digest>(
        &state_root,
        digest_storage_proof,
        digest_storage_key,
    )
    .map_err(|err| {
        VerificationError::StorageProof(storage_proof::VerificationError::DigestStorageProof(err))
    })?;

    let derived_domain_block_hash = sp_domains::derive_domain_block_hash::<DomainHeader>(
        *bad_receipt.domain_block_number(),
        *bad_receipt.domain_block_extrinsics_root(),
        state_root,
        parent_domain_block_hash,
        digest,
    );

    if *bad_receipt.domain_block_hash() == derived_domain_block_hash {
        return Err(VerificationError::InvalidProof);
    }

    Ok(())
}

/// Verifies invalid block fees fraud proof.
pub fn verify_invalid_block_fees_fraud_proof<
    CBlock,
    DomainNumber,
    DomainHash,
    Balance,
    DomainHashing,
>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        DomainNumber,
        DomainHash,
        Balance,
    >,
    storage_proof: &StorageProof,
    domain_runtime_code: Vec<u8>,
) -> Result<(), VerificationError<DomainHash>>
where
    CBlock: BlockT,
    Balance: PartialEq + Decode + Encode + Zero + Default,
    DomainHashing: Hasher<Out = DomainHash>,
    DomainNumber: Encode + Zero,
    DomainHash: Clone + Encode + Default + Copy,
{
    let storage_key = fraud_proof_runtime_interface::domain_storage_key(
        domain_runtime_code,
        DomainStorageKeyRequest::BlockFees,
    )
    .ok_or(VerificationError::FailedToGetDomainStorageKey)?;

    let block_fees =
        StorageProofVerifier::<DomainHashing>::get_decoded_value::<BlockFees<Balance>>(
            bad_receipt.final_state_root(),
            storage_proof.clone(),
            StorageKey(storage_key),
        )
        .map_err(|err| {
            VerificationError::StorageProof(
                storage_proof::VerificationError::BlockFeesStorageProof(err),
            )
        })?;

    // if the rewards matches, then this is an invalid fraud proof since rewards must be different.
    if bad_receipt.block_fees() == &block_fees {
        return Err(VerificationError::InvalidProof);
    }

    Ok(())
}

/// Verifies invalid transfers fraud proof.
pub fn verify_invalid_transfers_fraud_proof<
    CBlock,
    DomainNumber,
    DomainHash,
    Balance,
    DomainHashing,
>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        DomainNumber,
        DomainHash,
        Balance,
    >,
    storage_proof: &StorageProof,
    domain_runtime_code: Vec<u8>,
) -> Result<(), VerificationError<DomainHash>>
where
    CBlock: BlockT,
    Balance: PartialEq + Decode + Encode + Zero + Default,
    DomainNumber: Encode + Zero,
    DomainHash: Clone + Encode + Default + Copy,
    DomainHashing: Hasher<Out = DomainHash>,
{
    let storage_key = fraud_proof_runtime_interface::domain_storage_key(
        domain_runtime_code,
        DomainStorageKeyRequest::Transfers,
    )
    .ok_or(VerificationError::FailedToGetDomainStorageKey)?;

    let transfers = StorageProofVerifier::<DomainHashing>::get_decoded_value::<Transfers<Balance>>(
        bad_receipt.final_state_root(),
        storage_proof.clone(),
        StorageKey(storage_key),
    )
    .map_err(|err| {
        VerificationError::StorageProof(storage_proof::VerificationError::TransfersStorageProof(
            err,
        ))
    })?;

    // if the rewards matches, then this is an invalid fraud proof since rewards must be different.
    if bad_receipt.transfers() == &transfers {
        return Err(VerificationError::InvalidProof);
    }

    Ok(())
}

/// This function checks if this fraud proof is expected against the inboxed bundle entry it is targeting.
/// If the entry is expected then it will be returned
/// In any other cases VerificationError will be returned
fn check_expected_bundle_entry<CBlock, DomainHeader, Balance>(
    bad_receipt: &ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    >,
    bundle_index: u32,
    invalid_bundle_type: InvalidBundleType,
    is_good_invalid_fraud_proof: bool,
) -> Result<InboxedBundle<HeaderHashFor<DomainHeader>>, VerificationError<DomainHeader::Hash>>
where
    CBlock: BlockT,
    DomainHeader: HeaderT,
    Balance: Encode + Zero + Default,
{
    let targeted_invalid_bundle_entry = bad_receipt
        .inboxed_bundles()
        .get(bundle_index as usize)
        .ok_or(VerificationError::BundleNotFound)?;

    let is_expected = if !is_good_invalid_fraud_proof {
        // `BadInvalid`
        // The proof trying to prove `bad_receipt_bundle`'s `invalid_bundle_type` is wrong,
        // so the proof should contain the same `invalid_bundle_type`
        targeted_invalid_bundle_entry.bundle == BundleValidity::Invalid(invalid_bundle_type.clone())
    } else {
        // `GoodInvalid`
        match &targeted_invalid_bundle_entry.bundle {
            // The proof trying to prove the bundle is invalid due to `invalid_type_of_proof` while `bad_receipt_bundle`
            // thinks it is valid
            BundleValidity::Valid(_) => true,
            BundleValidity::Invalid(invalid_type) => {
                // The proof trying to prove there is a check failed while the `bad_receipt` thinks it passed,
                // so the proof should point to a check that is performed before the `bad_receipt`'s
                invalid_bundle_type.checking_order() < invalid_type.checking_order()
            }
        }
    };

    if !is_expected {
        return Err(VerificationError::UnexpectedTargetedBundleEntry {
            bundle_index,
            fraud_proof_invalid_type_of_proof: invalid_bundle_type,
            targeted_entry_bundle: targeted_invalid_bundle_entry.bundle.clone(),
        });
    }

    Ok(targeted_invalid_bundle_entry.clone())
}

fn get_extrinsic_from_proof<DomainHeader: HeaderT>(
    extrinsic_index: u32,
    extrinsics_root: <HeaderHashingFor<DomainHeader> as Hasher>::Out,
    proof_data: StorageProof,
) -> Result<OpaqueExtrinsic, VerificationError<DomainHeader::Hash>> {
    let storage_key =
        StorageProofVerifier::<HeaderHashingFor<DomainHeader>>::enumerated_storage_key(
            extrinsic_index,
        );
    StorageProofVerifier::<HeaderHashingFor<DomainHeader>>::get_decoded_value(
        &extrinsics_root,
        proof_data,
        storage_key,
    )
    .map_err(|err| {
        VerificationError::StorageProof(storage_proof::VerificationError::ExtrinsicStorageProof(
            err,
        ))
    })
}

pub fn verify_invalid_bundles_fraud_proof<CBlock, DomainHeader, MmrHash, Balance, SKP, MPV>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    >,
    bad_receipt_parent: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    >,
    invalid_bundles_fraud_proof: &InvalidBundlesProof<
        NumberFor<CBlock>,
        CBlock::Hash,
        MmrHash,
        DomainHeader,
    >,
    domain_id: DomainId,
    state_root: CBlock::Hash,
    domain_runtime_code: Vec<u8>,
) -> Result<(), VerificationError<DomainHeader::Hash>>
where
    CBlock: BlockT,
    DomainHeader: HeaderT,
    CBlock::Hash: Into<H256>,
    DomainHeader::Hash: Into<H256>,
    MmrHash: Decode + Clone,
    SKP: FraudProofStorageKeyProvider<NumberFor<CBlock>>,
    MPV: MmrProofVerifier<MmrHash, NumberFor<CBlock>, CBlock::Hash>,
    Balance: Encode + Zero + Default,
{
    let InvalidBundlesProof {
        bundle_index,
        invalid_bundle_type,
        is_good_invalid_fraud_proof,
        proof_data,
    } = invalid_bundles_fraud_proof;

    let (bundle_index, is_good_invalid_fraud_proof) = (*bundle_index, *is_good_invalid_fraud_proof);
    let targeted_invalid_bundle_entry = check_expected_bundle_entry::<CBlock, DomainHeader, Balance>(
        &bad_receipt,
        bundle_index,
        invalid_bundle_type.clone(),
        is_good_invalid_fraud_proof,
    )?;
    let bundle_extrinsic_root = targeted_invalid_bundle_entry.extrinsics_root;

    // Verify the bundle proof so in following we can use the bundle directly
    match proof_data {
        InvalidBundlesProofData::Bundle(bundle_with_proof)
        | InvalidBundlesProofData::BundleAndExecution {
            bundle_with_proof, ..
        } => {
            if bundle_with_proof.bundle_index != bundle_index {
                return Err(VerificationError::UnexpectedInvalidBundleProofData);
            }
            bundle_with_proof.verify::<CBlock, SKP>(domain_id, &state_root)?;
        }
        InvalidBundlesProofData::Extrinsic(_) => {}
        InvalidBundlesProofData::InvalidXDMProofData { .. } => {}
    }

    // Fast path to check if the fraud proof is targeting a bad receipt that claim a non-exist extrinsic
    // is invalid
    if let Some(invalid_extrinsic_index) = targeted_invalid_bundle_entry.invalid_extrinsic_index()
        && let InvalidBundlesProofData::Bundle(bundle_with_proof) = proof_data
        && bundle_with_proof.bundle.body_length() as u32 <= invalid_extrinsic_index
    {
        return Ok(());
    }

    match &invalid_bundle_type {
        InvalidBundleType::OutOfRangeTx(extrinsic_index) => {
            let bundle = match proof_data {
                InvalidBundlesProofData::Bundle(bundle_with_proof) => {
                    bundle_with_proof.bundle.clone()
                }
                _ => return Err(VerificationError::UnexpectedInvalidBundleProofData),
            };

            let opaque_extrinsic = bundle
                .extrinsics()
                .get(*extrinsic_index as usize)
                .cloned()
                .ok_or(VerificationError::ExtrinsicNotFound)?;

            let domain_tx_range = U256::MAX / INITIAL_DOMAIN_TX_RANGE;
            let bundle_vrf_hash = U256::from_be_bytes(*bundle.proof_of_election().vrf_hash());

            let is_tx_in_range = fraud_proof_runtime_interface::domain_runtime_call(
                domain_runtime_code,
                StatelessDomainRuntimeCall::IsTxInRange {
                    opaque_extrinsic,
                    domain_tx_range,
                    bundle_vrf_hash,
                },
            )
            .ok_or(VerificationError::FailedToGetDomainRuntimeCallResponse)?;

            // Proof to be considered valid only if:
            // if we are proving the bundle is actually invalid, then tx must not be in range, but
            // if we are proving the invalid bundle is wrong, then tx must be in range.
            if is_tx_in_range == is_good_invalid_fraud_proof {
                return Err(VerificationError::InvalidProof);
            }
            Ok(())
        }
        InvalidBundleType::InherentExtrinsic(extrinsic_index) => {
            let opaque_extrinsic = {
                let extrinsic_storage_proof = match proof_data {
                    InvalidBundlesProofData::Extrinsic(p) => p.clone(),
                    _ => return Err(VerificationError::UnexpectedInvalidBundleProofData),
                };
                get_extrinsic_from_proof::<DomainHeader>(
                    *extrinsic_index,
                    bundle_extrinsic_root,
                    extrinsic_storage_proof,
                )?
            };
            let is_inherent = fraud_proof_runtime_interface::domain_runtime_call(
                domain_runtime_code,
                StatelessDomainRuntimeCall::IsInherentExtrinsic(opaque_extrinsic),
            )
            .ok_or(VerificationError::FailedToGetDomainRuntimeCallResponse)?;

            // Proof to be considered valid only if:
            // if we are proving the bundle is actually invalid, then extrinsic must be an inherent, but
            // if we are proving the invalid bundle is wrong, then the extrinsic must not be an inherent.
            if is_inherent == is_good_invalid_fraud_proof {
                Ok(())
            } else {
                Err(VerificationError::InvalidProof)
            }
        }
        InvalidBundleType::IllegalTx(extrinsic_index) => {
            let (bundle, execution_proof) = match proof_data {
                InvalidBundlesProofData::BundleAndExecution {
                    bundle_with_proof,
                    execution_proof,
                } => (bundle_with_proof.bundle.clone(), execution_proof.clone()),
                _ => return Err(VerificationError::UnexpectedInvalidBundleProofData),
            };

            let extrinsics = bundle
                .into_extrinsics()
                .drain(..)
                .take((*extrinsic_index + 1) as usize)
                .collect();

            // Make host call for check extrinsic in single context
            let check_extrinsic_result =
                fraud_proof_runtime_interface::check_extrinsics_in_single_context(
                    domain_runtime_code,
                    (
                        (*bad_receipt_parent.domain_block_number()).saturated_into(),
                        (*bad_receipt_parent.domain_block_hash()).into(),
                    ),
                    (*bad_receipt_parent.final_state_root()).into(),
                    extrinsics,
                    execution_proof.encode(),
                )
                .ok_or(VerificationError::FailedToCheckExtrinsicsInSingleContext)?;

            let is_extrinsic_invalid = check_extrinsic_result == Some(*extrinsic_index);

            // Proof to be considered valid only if:
            // if we are proving the bundle is actually invalid, then the extrinsic must be an invalid extrinsic, but
            // if we are proving the invalid bundle is wrong, then the extrinsic must not be an invalid extrinsic.
            if is_extrinsic_invalid == is_good_invalid_fraud_proof {
                Ok(())
            } else {
                Err(VerificationError::InvalidProof)
            }
        }
        InvalidBundleType::UndecodableTx(extrinsic_index) => {
            let opaque_extrinsic = {
                let extrinsic_storage_proof = match proof_data {
                    InvalidBundlesProofData::Extrinsic(p) => p.clone(),
                    _ => return Err(VerificationError::UnexpectedInvalidBundleProofData),
                };
                get_extrinsic_from_proof::<DomainHeader>(
                    *extrinsic_index,
                    bundle_extrinsic_root,
                    extrinsic_storage_proof,
                )?
            };
            let is_decodable = fraud_proof_runtime_interface::domain_runtime_call(
                domain_runtime_code,
                StatelessDomainRuntimeCall::IsDecodableExtrinsic(opaque_extrinsic),
            )
            .ok_or(VerificationError::FailedToGetDomainRuntimeCallResponse)?;

            if is_decodable == is_good_invalid_fraud_proof {
                return Err(VerificationError::InvalidProof);
            }
            Ok(())
        }
        InvalidBundleType::InvalidBundleWeight => {
            let bundle = match proof_data {
                InvalidBundlesProofData::Bundle(bundle_with_proof) => {
                    bundle_with_proof.bundle.clone()
                }
                _ => return Err(VerificationError::UnexpectedInvalidBundleProofData),
            };
            let bundle_header_weight = bundle.estimated_weight();
            let estimated_bundle_weight = fraud_proof_runtime_interface::bundle_weight(
                domain_runtime_code,
                bundle.into_extrinsics(),
            )
            .ok_or(VerificationError::FailedToGetBundleWeight)?;

            let is_bundle_weight_correct = estimated_bundle_weight == bundle_header_weight;

            if is_bundle_weight_correct == is_good_invalid_fraud_proof {
                return Err(VerificationError::InvalidProof);
            }
            Ok(())
        }
        InvalidBundleType::InvalidXDM(extrinsic_index) => {
            let (extrinsic_proof, maybe_mmr_root_proof) = match proof_data {
                InvalidBundlesProofData::InvalidXDMProofData {
                    extrinsic_proof,
                    mmr_root_proof,
                } => (extrinsic_proof.clone(), mmr_root_proof.clone()),
                _ => return Err(VerificationError::UnexpectedInvalidBundleProofData),
            };

            let opaque_extrinsic = get_extrinsic_from_proof::<DomainHeader>(
                *extrinsic_index,
                bundle_extrinsic_root,
                extrinsic_proof,
            )?;

            let maybe_xdm_mmr_proof = fraud_proof_runtime_interface::extract_xdm_mmr_proof(
                domain_runtime_code,
                opaque_extrinsic.encode(),
            )
            .ok_or(VerificationError::FailedToGetExtractXdmMmrProof)?;

            let (mmr_root_proof, consensus_chain_mmr_leaf_proof) = match maybe_xdm_mmr_proof {
                Some(encoded_xdm_mmr_proof) => {
                    let consensus_chain_mmr_leaf_proof: ConsensusChainMmrLeafProof<
                        NumberFor<CBlock>,
                        CBlock::Hash,
                        MmrHash,
                    > = Decode::decode(&mut encoded_xdm_mmr_proof.as_ref())
                        .map_err(|_| VerificationError::FailedToDecodeXdmMmrProof)?;
                    let mmr_root_proof = maybe_mmr_root_proof
                        .ok_or(VerificationError::UnexpectedInvalidBundleProofData)?;
                    (mmr_root_proof, consensus_chain_mmr_leaf_proof)
                }
                None => {
                    // `None` means this is not an XDM, so for this fraud proof to be valid:
                    // it has to prove that the invalid bundle is wrong, and
                    // the `maybe_mmr_root_proof` must be `None`
                    return if is_good_invalid_fraud_proof || maybe_mmr_root_proof.is_some() {
                        Err(VerificationError::InvalidProof)
                    } else {
                        Ok(())
                    };
                }
            };

            let mmr_root = {
                let MmrRootProof {
                    mmr_proof,
                    mmr_root_storage_proof,
                } = mmr_root_proof;

                let leaf_data = MPV::verify_proof_and_extract_leaf(mmr_proof)
                    .ok_or(VerificationError::BadMmrProof)?;

                <MmrRootStorageProof<MmrHash> as BasicStorageProof<CBlock>>::verify::<SKP>(
                    mmr_root_storage_proof,
                    consensus_chain_mmr_leaf_proof.consensus_block_number,
                    &leaf_data.state_root(),
                )?
            };

            // Verify the original XDM mmr proof statelessly to get the original result
            let is_valid_mmr_proof =
                MPV::verify_proof_stateless(mmr_root, consensus_chain_mmr_leaf_proof).is_some();

            if is_valid_mmr_proof == is_good_invalid_fraud_proof {
                return Err(VerificationError::InvalidProof);
            }
            Ok(())
        }
    }
}
