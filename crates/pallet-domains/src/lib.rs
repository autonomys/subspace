// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Pallet Domains

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(array_windows)]

#[cfg(test)]
mod tests;

use codec::{Decode, Encode};
use frame_support::traits::Get;
use frame_system::offchain::SubmitTransaction;
pub use pallet::*;
use sp_core::H256;
use sp_domains::bundle_election::{verify_system_bundle_solution, verify_vrf_proof};
use sp_domains::fraud_proof::{BundleEquivocationProof, FraudProof, InvalidTransactionProof};
use sp_domains::merkle_tree::Witness;
use sp_domains::transaction::InvalidTransactionCode;
use sp_domains::{BundleSolution, DomainId, ExecutionReceipt, ProofOfElection, SignedOpaqueBundle};
use sp_runtime::traits::{BlockNumberProvider, CheckedSub, One, Zero};
use sp_runtime::transaction_validity::TransactionValidityError;
use sp_runtime::RuntimeAppPublic;

#[frame_support::pallet]
mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_support::PalletError;
    use frame_system::pallet_prelude::*;
    use pallet_receipts::{Error as ReceiptError, FraudProofError};
    use sp_core::H256;
    use sp_domains::fraud_proof::{BundleEquivocationProof, FraudProof, InvalidTransactionProof};
    use sp_domains::transaction::InvalidTransactionCode;
    use sp_domains::{DomainId, ExecutorPublicKey, SignedOpaqueBundle};
    use sp_runtime::traits::{One, Zero};
    use sp_std::fmt::Debug;

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_receipts::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Same with `pallet_subspace::Config::ConfirmationDepthK`.
        type ConfirmationDepthK: Get<Self::BlockNumber>;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
    pub enum BundleError {
        /// The signer of bundle is unexpected.
        UnexpectedSigner,
        /// Invalid bundle signature.
        BadSignature,
        /// Invalid vrf proof.
        BadVrfProof,
        /// State of a system domain block is missing.
        StateRootNotFound,
        /// Invalid state root in the proof of election.
        BadStateRoot,
        /// The type of state root is not H256.
        StateRootNotH256,
        /// Invalid system bundle election solution.
        BadElectionSolution,
        /// An invalid execution receipt found in the bundle.
        Receipt(ExecutionReceiptError),
        /// The Bundle is created too long ago.
        StaleBundle,
        /// Bundle was created on an unknown primary block (probably a fork block).
        UnknownBlock,
    }

    impl<T> From<BundleError> for Error<T> {
        fn from(e: BundleError) -> Self {
            Self::Bundle(e)
        }
    }

    #[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
    pub enum ExecutionReceiptError {
        /// The parent execution receipt is unknown.
        MissingParent,
        /// The execution receipt has been pruned.
        Pruned,
        /// The execution receipt points to a block unknown to the history.
        UnknownBlock,
        /// The execution receipt is too far in the future.
        TooFarInFuture,
        /// Receipts are not consecutive.
        Inconsecutive,
        /// Receipts in a bundle can not be empty.
        Empty,
    }

    impl<T> From<ReceiptError> for Error<T> {
        fn from(error: ReceiptError) -> Self {
            match error {
                ReceiptError::MissingParent => {
                    Self::Bundle(BundleError::Receipt(ExecutionReceiptError::MissingParent))
                }
                ReceiptError::FraudProof(err) => Self::FraudProof(err),
                ReceiptError::UnavailablePrimaryBlockHash => Self::UnavailablePrimaryBlockHash,
            }
        }
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Can not find the block hash of given primary block number.
        UnavailablePrimaryBlockHash,
        /// Invalid bundle.
        Bundle(BundleError),
        /// Invalid fraud proof.
        FraudProof(FraudProofError),
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A domain bundle was included.
        BundleStored {
            domain_id: DomainId,
            bundle_hash: H256,
            bundle_author: ExecutorPublicKey,
        },
        /// A bundle equivocation proof was processed.
        BundleEquivocationProofProcessed,
        /// An invalid transaction proof was processed.
        InvalidTransactionProofProcessed,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // TODO: proper weight
        #[pallet::call_index(0)]
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_bundle(
            origin: OriginFor<T>,
            signed_opaque_bundle: SignedOpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domains", "Processing bundle: {signed_opaque_bundle:?}");

            let domain_id = signed_opaque_bundle.domain_id();

            // Only process the system domain receipts.
            if domain_id.is_system() {
                pallet_receipts::Pallet::<T>::track_receipts(
                    domain_id,
                    signed_opaque_bundle.bundle.receipts.as_slice(),
                )
                .map_err(Error::<T>::from)?;
            }

            Self::deposit_event(Event::BundleStored {
                domain_id,
                bundle_hash: signed_opaque_bundle.hash(),
                bundle_author: signed_opaque_bundle.into_executor_public_key(),
            });

            Ok(())
        }

        // TODO: proper weight
        #[pallet::call_index(1)]
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_fraud_proof(
            origin: OriginFor<T>,
            fraud_proof: FraudProof<T::BlockNumber, T::Hash>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domains", "Processing fraud proof: {fraud_proof:?}");

            if fraud_proof.domain_id().is_system() {
                pallet_receipts::Pallet::<T>::process_fraud_proof(fraud_proof)
                    .map_err(Error::<T>::from)?;
            }

            // TODO: slash the executor accordingly.

            Ok(())
        }

        // TODO: proper weight
        #[pallet::call_index(2)]
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_bundle_equivocation_proof(
            origin: OriginFor<T>,
            bundle_equivocation_proof: BundleEquivocationProof<T::BlockNumber, T::Hash>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domains", "Processing bundle equivocation proof: {bundle_equivocation_proof:?}");

            // TODO: slash the executor accordingly.

            Self::deposit_event(Event::BundleEquivocationProofProcessed);

            Ok(())
        }

        // TODO: proper weight
        #[pallet::call_index(3)]
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_invalid_transaction_proof(
            origin: OriginFor<T>,
            invalid_transaction_proof: InvalidTransactionProof,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domains", "Processing invalid transaction proof: {invalid_transaction_proof:?}");

            // TODO: slash the executor accordingly.

            Self::deposit_event(Event::InvalidTransactionProofProcessed);

            Ok(())
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
        fn on_initialize(block_number: T::BlockNumber) -> Weight {
            let parent_number = block_number - One::one();
            let parent_hash = frame_system::Pallet::<T>::block_hash(parent_number);

            pallet_receipts::PrimaryBlockHash::<T>::insert(
                DomainId::SYSTEM,
                parent_number,
                parent_hash,
            );

            // The genesis block hash is not finalized until the genesis block building is done,
            // hence the genesis receipt is initialized after the genesis building.
            if parent_number.is_zero() {
                pallet_receipts::Pallet::<T>::initialize_genesis_receipt(
                    DomainId::SYSTEM,
                    parent_hash,
                );
            }

            T::DbWeight::get().writes(1)
        }
    }

    /// Constructs a `TransactionValidity` with pallet-executor specific defaults.
    fn unsigned_validity(prefix: &'static str, tag: impl Encode) -> TransactionValidity {
        ValidTransaction::with_tag_prefix(prefix)
            .priority(TransactionPriority::MAX)
            .and_provides(tag)
            .longevity(TransactionLongevity::MAX)
            // We need this extrinsic to be propagated to the farmer nodes.
            .propagate(true)
            .build()
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;
        fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
            match call {
                Call::submit_bundle {
                    signed_opaque_bundle,
                } => Self::pre_dispatch_submit_bundle(signed_opaque_bundle),
                Call::submit_fraud_proof { .. } => Ok(()),
                Call::submit_bundle_equivocation_proof { .. } => Ok(()),
                Call::submit_invalid_transaction_proof { .. } => Ok(()),
                _ => Err(InvalidTransaction::Call.into()),
            }
        }

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::submit_bundle {
                    signed_opaque_bundle,
                } => {
                    if let Err(e) = Self::validate_bundle(signed_opaque_bundle) {
                        log::debug!(
                            target: "runtime::domains",
                            "Bad bundle {:?}, error: {e:?}", signed_opaque_bundle.domain_id(),
                        );
                        if let BundleError::Receipt(_) = e {
                            return InvalidTransactionCode::ExecutionReceipt.into();
                        } else {
                            return InvalidTransactionCode::Bundle.into();
                        }
                    }

                    ValidTransaction::with_tag_prefix("SubspaceSubmitBundle")
                        .priority(TransactionPriority::MAX)
                        .longevity(T::ConfirmationDepthK::get().try_into().unwrap_or_else(|_| {
                            panic!("Block number always fits in TransactionLongevity; qed")
                        }))
                        .and_provides(signed_opaque_bundle.hash())
                        .propagate(true)
                        .build()
                }
                Call::submit_fraud_proof { fraud_proof } => {
                    if let Err(e) = pallet_receipts::Pallet::<T>::validate_fraud_proof(fraud_proof)
                    {
                        log::debug!(
                            target: "runtime::domains",
                            "Bad fraud proof: {fraud_proof:?}, error: {e:?}",
                        );
                        return InvalidTransactionCode::FraudProof.into();
                    }

                    // TODO: proper tag value.
                    unsigned_validity("SubspaceSubmitFraudProof", fraud_proof)
                }
                Call::submit_bundle_equivocation_proof {
                    bundle_equivocation_proof,
                } => {
                    if let Err(e) =
                        Self::validate_bundle_equivocation_proof(bundle_equivocation_proof)
                    {
                        log::debug!(
                            target: "runtime::domains",
                            "Bad bundle equivocation proof: {bundle_equivocation_proof:?}, error: {e:?}",
                        );
                        return InvalidTransactionCode::BundleEquivicationProof.into();
                    }

                    unsigned_validity(
                        "SubspaceSubmitBundleEquivocationProof",
                        bundle_equivocation_proof.hash(),
                    )
                }
                Call::submit_invalid_transaction_proof {
                    invalid_transaction_proof,
                } => {
                    if let Err(e) =
                        Self::validate_invalid_transaction_proof(invalid_transaction_proof)
                    {
                        log::debug!(
                            target: "runtime::domains",
                            "Bad invalid transaction proof: {invalid_transaction_proof:?}, error: {e:?}",
                        );
                        return InvalidTransactionCode::TrasactionProof.into();
                    }

                    unsigned_validity(
                        "SubspaceSubmitInvalidTransactionProof",
                        invalid_transaction_proof,
                    )
                }

                _ => InvalidTransaction::Call.into(),
            }
        }
    }
}

impl<T: Config> Pallet<T> {
    /// Returns the block number of the latest receipt.
    pub fn head_receipt_number() -> T::BlockNumber {
        pallet_receipts::Pallet::<T>::head_receipt_number(DomainId::SYSTEM)
    }

    /// Returns the block number of the oldest receipt still being tracked in the state.
    pub fn oldest_receipt_number() -> T::BlockNumber {
        pallet_receipts::Pallet::<T>::oldest_receipt_number(DomainId::SYSTEM)
    }

    fn receipts_are_consecutive(
        receipts: &[ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>],
    ) -> bool {
        receipts
            .array_windows()
            .all(|[ref head, ref tail]| head.primary_number + One::one() == tail.primary_number)
    }

    fn pre_dispatch_submit_bundle(
        signed_opaque_bundle: &SignedOpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
    ) -> Result<(), TransactionValidityError> {
        let execution_receipts = &signed_opaque_bundle.bundle.receipts;

        if !Self::receipts_are_consecutive(execution_receipts) {
            return Err(TransactionValidityError::Invalid(
                InvalidTransactionCode::ExecutionReceipt.into(),
            ));
        }

        if signed_opaque_bundle.domain_id().is_system() {
            let oldest_receipt_number = Self::oldest_receipt_number();
            let mut best_number = Self::head_receipt_number();

            for receipt in execution_receipts {
                let primary_number = receipt.primary_number;

                // Ignore the receipt if it has already been pruned.
                if primary_number < oldest_receipt_number {
                    continue;
                }

                // Non-best receipt
                if primary_number <= best_number {
                    if !pallet_receipts::Pallet::<T>::point_to_valid_primary_block(
                        DomainId::SYSTEM,
                        receipt,
                    ) {
                        log::debug!(
                            target: "runtime::domains",
                            "Invalid primary hash for #{primary_number:?} in receipt, \
                            expected: {:?}, got: {:?}",
                            pallet_receipts::PrimaryBlockHash::<T>::get(DomainId::SYSTEM, primary_number),
                            receipt.primary_hash,
                        );
                        return Err(TransactionValidityError::Invalid(
                            InvalidTransactionCode::ExecutionReceipt.into(),
                        ));
                    }
                    // New best receipt.
                } else if primary_number == best_number + One::one() {
                    if !pallet_receipts::Pallet::<T>::point_to_valid_primary_block(
                        DomainId::SYSTEM,
                        receipt,
                    ) {
                        log::debug!(
                            target: "runtime::domains",
                            "Invalid primary hash for #{primary_number:?} in receipt, \
                            expected: {:?}, got: {:?}",
                            pallet_receipts::PrimaryBlockHash::<T>::get(DomainId::SYSTEM, primary_number),
                            receipt.primary_hash,
                        );
                        return Err(TransactionValidityError::Invalid(
                            InvalidTransactionCode::ExecutionReceipt.into(),
                        ));
                    }
                    best_number += One::one();
                    // Missing receipt.
                } else {
                    return Err(TransactionValidityError::Invalid(
                        InvalidTransactionCode::ExecutionReceipt.into(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn validate_system_bundle_solution(
        receipts: &[ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>],
        authority_stake_weight: sp_domains::StakeWeight,
        authority_witness: &Witness,
        proof_of_election: &ProofOfElection<T::DomainHash>,
    ) -> Result<(), BundleError> {
        let ProofOfElection {
            state_root,
            block_number,
            block_hash,
            ..
        } = proof_of_election;

        let block_number = T::BlockNumber::from(*block_number);

        let new_best_receipt_number = receipts
            .iter()
            .map(|receipt| receipt.primary_number)
            .max()
            .unwrap_or_default()
            .max(Self::head_receipt_number());

        let state_root_verifiable = block_number <= new_best_receipt_number;

        if !block_number.is_zero() && state_root_verifiable {
            let maybe_state_root = receipts.iter().find_map(|receipt| {
                receipt.trace.last().and_then(|state_root| {
                    if (receipt.primary_number, receipt.domain_hash) == (block_number, *block_hash)
                    {
                        Some(*state_root)
                    } else {
                        None
                    }
                })
            });

            let expected_state_root = match maybe_state_root {
                Some(v) => v,
                None => pallet_receipts::Pallet::<T>::state_root((
                    DomainId::SYSTEM,
                    block_number,
                    block_hash,
                ))
                .ok_or(BundleError::StateRootNotFound)
                .map_err(|err| {
                    log::debug!(
                        target: "runtime::domains",
                        "State root for #{block_number:?},{block_hash:?} not found, \
                        current head receipt: {:?}",
                        pallet_receipts::Pallet::<T>::receipt_head(DomainId::SYSTEM),
                    );
                    err
                })?,
            };

            if expected_state_root != *state_root {
                log::debug!(
                    target: "runtime::domains",
                    "Bad state root for #{block_number:?},{block_hash:?}, \
                    expected: {expected_state_root:?}, got: {state_root:?}",
                );
                return Err(BundleError::BadStateRoot);
            }
        }

        let state_root = H256::decode(&mut state_root.encode().as_slice())
            .map_err(|_| BundleError::StateRootNotH256)?;

        verify_system_bundle_solution(
            proof_of_election,
            state_root,
            authority_stake_weight,
            authority_witness,
        )
        .map_err(|_| BundleError::BadElectionSolution)?;

        Ok(())
    }

    /// Common validation of receipts in all kinds of domain bundle.
    fn validate_execution_receipts(
        execution_receipts: &[ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>],
    ) -> Result<(), ExecutionReceiptError> {
        let current_block_number = frame_system::Pallet::<T>::current_block_number();

        // Genesis block receipt is initialized on primary chain, the first block has no receipts,
        // but any block after the first one requires at least one receipt.
        if current_block_number > One::one() && execution_receipts.is_empty() {
            return Err(ExecutionReceiptError::Empty);
        }

        if !Self::receipts_are_consecutive(execution_receipts) {
            return Err(ExecutionReceiptError::Inconsecutive);
        }

        Ok(())
    }

    fn validate_bundle(
        SignedOpaqueBundle {
            bundle,
            bundle_solution,
            signature,
        }: &SignedOpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
    ) -> Result<(), BundleError> {
        let current_block_number = frame_system::Pallet::<T>::current_block_number();

        // Reject the stale bundles so that they can't be used by attacker to occupy the block space without cost.
        let confirmation_depth_k = T::ConfirmationDepthK::get();
        if let Some(finalized) = current_block_number.checked_sub(&confirmation_depth_k) {
            {
                // Ideally, `bundle.header.primary_number` is `current_block_number - 1`, we need
                // to handle the edge case that `T::ConfirmationDepthK` happens to be 1.
                let is_stale_bundle = if confirmation_depth_k.is_zero() {
                    unreachable!(
                        "ConfirmationDepthK is guaranteed to be non-zero at genesis config"
                    )
                } else if confirmation_depth_k == One::one() {
                    bundle.header.primary_number < finalized
                } else {
                    bundle.header.primary_number <= finalized
                };

                if is_stale_bundle {
                    log::debug!(
                        target: "runtime::domains",
                        "Bundle created on an ancient consensus block, current_block_number: {current_block_number:?}, \
                        ConfirmationDepthK: {confirmation_depth_k:?}, `bundle.header.primary_number`: {:?}, `finalized`: {finalized:?}",
                        bundle.header.primary_number,
                    );
                    return Err(BundleError::StaleBundle);
                }
            }
        }

        let proof_of_election = bundle_solution.proof_of_election();

        if !proof_of_election
            .executor_public_key
            .verify(&bundle.hash(), signature)
        {
            return Err(BundleError::BadSignature);
        }

        verify_vrf_proof(
            &proof_of_election.executor_public_key,
            &proof_of_election.vrf_output,
            &proof_of_election.vrf_proof,
            &proof_of_election.global_challenge,
        )
        .map_err(|_| BundleError::BadVrfProof)?;

        Self::validate_execution_receipts(&bundle.receipts).map_err(BundleError::Receipt)?;

        if proof_of_election.domain_id.is_system() {
            let BundleSolution::System {
                authority_stake_weight,
                authority_witness,
                proof_of_election
            } = bundle_solution else {
                unreachable!("Must be system domain bundle solution as we just checked; qed ")
            };

            // TODO: currently, only the system bundles created on the primary fork can be
            // prevented beforehand, the core bundles will be rejected by the system domain but
            // they are still included on the primary chain as it's not feasible to check core bundles
            // within this pallet, which may be solved if the `submit_bundle` extrinsic is no longer
            // free in the future.
            let bundle_created_on_valid_primary_block =
                match pallet_receipts::PrimaryBlockHash::<T>::get(
                    DomainId::SYSTEM,
                    bundle.header.primary_number,
                ) {
                    Some(block_hash) => block_hash == bundle.header.primary_hash,
                    // The `initialize_block` of non-system pallets is skipped in the `validate_transaction`,
                    // thus the hash of best block, which is recorded in the this pallet's `on_initialize` hook,
                    // is unavailable in pallet-receipts at this point.
                    None => frame_system::Pallet::<T>::parent_hash() == bundle.header.primary_hash,
                };

            if !bundle_created_on_valid_primary_block {
                log::debug!(
                    target: "runtime::domains",
                    "Bundle is probably created on a primary fork #{:?}, expected: {:?}, got: {:?}",
                    bundle.header.primary_number,
                    pallet_receipts::PrimaryBlockHash::<T>::get(DomainId::SYSTEM, bundle.header.primary_number),
                    bundle.header.primary_hash,
                );
                return Err(BundleError::UnknownBlock);
            }

            Self::validate_system_bundle_solution(
                &bundle.receipts,
                *authority_stake_weight,
                authority_witness,
                proof_of_election,
            )?;

            let best_number = Self::head_receipt_number();
            let max_allowed = best_number + T::MaximumReceiptDrift::get();

            let oldest_receipt_number = Self::oldest_receipt_number();

            for execution_receipt in &bundle.receipts {
                let primary_number = execution_receipt.primary_number;

                // The corresponding block info has been pruned, such expired receipts
                // will be skipped too while applying the bundle.
                if primary_number < oldest_receipt_number {
                    continue;
                }

                // Due to `initialize_block` is skipped while calling the runtime api, the block
                // hash mapping for last block is unknown to the transaction pool, but this info
                // is already available in System.
                let point_to_parent_block = primary_number == current_block_number - One::one()
                    && execution_receipt.primary_hash == frame_system::Pallet::<T>::parent_hash();

                let point_to_valid_primary_block =
                    pallet_receipts::Pallet::<T>::point_to_valid_primary_block(
                        DomainId::SYSTEM,
                        execution_receipt,
                    );

                if !point_to_parent_block && !point_to_valid_primary_block {
                    log::debug!(
                        target: "runtime::domains",
                        "Receipt of #{primary_number:?},{:?} points to an unknown primary block, \
                        expected: #{primary_number:?},{:?}",
                        execution_receipt.primary_hash,
                        pallet_receipts::PrimaryBlockHash::<T>::get(DomainId::SYSTEM, primary_number),
                    );
                    return Err(BundleError::Receipt(ExecutionReceiptError::UnknownBlock));
                }

                // Ensure the receipt is not too new.
                if primary_number == current_block_number || primary_number > max_allowed {
                    log::debug!(
                        target: "runtime::domains",
                        "Receipt for #{primary_number:?} is too far in future, \
                        current_block_number: {current_block_number:?}, max_allowed: {max_allowed:?}",
                    );
                    return Err(BundleError::Receipt(ExecutionReceiptError::TooFarInFuture));
                }
            }
        }

        Ok(())
    }

    // TODO: Checks if the bundle equivocation proof is valid.
    fn validate_bundle_equivocation_proof(
        _bundle_equivocation_proof: &BundleEquivocationProof<T::BlockNumber, T::Hash>,
    ) -> Result<(), Error<T>> {
        Ok(())
    }

    // TODO: Checks if the invalid transaction proof is valid.
    fn validate_invalid_transaction_proof(
        _invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), Error<T>> {
        Ok(())
    }
}

impl<T> Pallet<T>
where
    T: Config + frame_system::offchain::SendTransactionTypes<Call<T>>,
{
    /// Submits an unsigned extrinsic [`Call::submit_bundle`].
    pub fn submit_bundle_unsigned(
        signed_opaque_bundle: SignedOpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
    ) {
        let call = Call::submit_bundle {
            signed_opaque_bundle,
        };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(target: "runtime::domains", "Submitted bundle");
            }
            Err(()) => {
                log::error!(target: "runtime::domains", "Error submitting bundle");
            }
        }
    }

    /// Submits an unsigned extrinsic [`Call::submit_fraud_proof`].
    pub fn submit_fraud_proof_unsigned(fraud_proof: FraudProof<T::BlockNumber, T::Hash>) {
        let call = Call::submit_fraud_proof { fraud_proof };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(target: "runtime::domains", "Submitted fraud proof");
            }
            Err(()) => {
                log::error!(target: "runtime::domains", "Error submitting fraud proof");
            }
        }
    }
}
