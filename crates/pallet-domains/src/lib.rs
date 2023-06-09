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

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[cfg(test)]
mod tests;

pub mod weights;

use codec::{Decode, Encode};
use frame_support::traits::Get;
use frame_system::offchain::SubmitTransaction;
pub use pallet::*;
use sp_core::H256;
use sp_domains::bundle_election::verify_system_bundle_solution;
use sp_domains::fraud_proof::FraudProof;
use sp_domains::merkle_tree::Witness;
use sp_domains::transaction::InvalidTransactionCode;
use sp_domains::{BundleSolution, DomainId, ExecutionReceipt, OpaqueBundle, ProofOfElection};
use sp_runtime::traits::{BlockNumberProvider, CheckedSub, One, Zero};
use sp_runtime::transaction_validity::TransactionValidityError;
use sp_std::cmp::Ordering;
use sp_std::vec::Vec;

#[frame_support::pallet]
mod pallet {
    use crate::weights::WeightInfo;
    use frame_support::pallet_prelude::*;
    use frame_support::weights::Weight;
    use frame_support::PalletError;
    use frame_system::pallet_prelude::*;
    use pallet_settlement::{Error as SettlementError, FraudProofError};
    use sp_core::H256;
    use sp_domains::fraud_proof::FraudProof;
    use sp_domains::transaction::InvalidTransactionCode;
    use sp_domains::{DomainId, ExecutorPublicKey, OpaqueBundle};
    use sp_runtime::traits::{One, Zero};
    use sp_std::fmt::Debug;
    use sp_std::vec::Vec;

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_settlement::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Same with `pallet_subspace::Config::ConfirmationDepthK`.
        type ConfirmationDepthK: Get<Self::BlockNumber>;

        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Bundles submitted successfully in current block.
    #[pallet::storage]
    pub(super) type SuccessfulBundles<T> = StorageValue<_, Vec<H256>, ValueQuery>;

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
        #[inline]
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

    impl<T> From<SettlementError> for Error<T> {
        #[inline]
        fn from(error: SettlementError) -> Self {
            match error {
                SettlementError::MissingParent => {
                    Self::Bundle(BundleError::Receipt(ExecutionReceiptError::MissingParent))
                }
                SettlementError::FraudProof(err) => Self::FraudProof(err),
                SettlementError::UnavailablePrimaryBlockHash => Self::UnavailablePrimaryBlockHash,
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
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(
            if opaque_bundle.domain_id().is_system() {
                T::WeightInfo::submit_system_bundle()
            } else {
                T::WeightInfo::submit_core_bundle()
            }
        )]
        pub fn submit_bundle(
            origin: OriginFor<T>,
            opaque_bundle: OpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domains", "Processing bundle: {opaque_bundle:?}");

            let domain_id = opaque_bundle.domain_id();

            // Only process the system domain receipts.
            if domain_id.is_system() {
                pallet_settlement::Pallet::<T>::track_receipt(domain_id, &opaque_bundle.receipt)
                    .map_err(Error::<T>::from)?;
            }

            let bundle_hash = opaque_bundle.hash();

            SuccessfulBundles::<T>::append(bundle_hash);

            Self::deposit_event(Event::BundleStored {
                domain_id,
                bundle_hash,
                bundle_author: opaque_bundle.into_executor_public_key(),
            });

            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(
            match fraud_proof {
                FraudProof::InvalidStateTransition(..) => (
                    T::WeightInfo::submit_system_domain_invalid_state_transition_proof(),
                    Pays::No
                ),
                // TODO: proper weight
                _ => (Weight::from_all(10_000), Pays::No),
            }
        )]
        pub fn submit_fraud_proof(
            origin: OriginFor<T>,
            fraud_proof: FraudProof<T::BlockNumber, T::Hash>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domains", "Processing fraud proof: {fraud_proof:?}");

            if fraud_proof.domain_id().is_system() {
                pallet_settlement::Pallet::<T>::process_fraud_proof(fraud_proof)
                    .map_err(Error::<T>::from)?;
            }

            Ok(())
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
        fn on_initialize(block_number: T::BlockNumber) -> Weight {
            let parent_number = block_number - One::one();
            let parent_hash = frame_system::Pallet::<T>::block_hash(parent_number);

            pallet_settlement::PrimaryBlockHash::<T>::insert(
                DomainId::SYSTEM,
                parent_number,
                parent_hash,
            );

            // The genesis block hash is not finalized until the genesis block building is done,
            // hence the genesis receipt is initialized after the genesis building.
            if parent_number.is_zero() {
                pallet_settlement::Pallet::<T>::initialize_genesis_receipt(
                    DomainId::SYSTEM,
                    parent_hash,
                );
            }

            SuccessfulBundles::<T>::kill();

            T::DbWeight::get().writes(2)
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
                Call::submit_bundle { opaque_bundle } => {
                    Self::pre_dispatch_submit_bundle(opaque_bundle)
                }
                Call::submit_fraud_proof { fraud_proof } => {
                    if !fraud_proof.domain_id().is_system() {
                        log::debug!(
                            target: "runtime::domains",
                            "Wrong fraud proof, expected system domain fraud proof but got: {fraud_proof:?}",
                        );
                        Err(TransactionValidityError::Invalid(
                            InvalidTransactionCode::FraudProof.into(),
                        ))
                    } else {
                        Ok(())
                    }
                }
                _ => Err(InvalidTransaction::Call.into()),
            }
        }

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::submit_bundle { opaque_bundle } => {
                    if let Err(e) = Self::validate_bundle(opaque_bundle) {
                        log::debug!(
                            target: "runtime::domains",
                            "Bad bundle {:?}, error: {e:?}", opaque_bundle.domain_id(),
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
                        .and_provides(opaque_bundle.hash())
                        .propagate(true)
                        .build()
                }
                Call::submit_fraud_proof { fraud_proof } => {
                    if !fraud_proof.domain_id().is_system() {
                        log::debug!(
                            target: "runtime::domains",
                            "Wrong fraud proof, expected system domain fraud proof but got: {fraud_proof:?}",
                        );
                        return InvalidTransactionCode::FraudProof.into();
                    }
                    if let Err(e) =
                        pallet_settlement::Pallet::<T>::validate_fraud_proof(fraud_proof)
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

                _ => InvalidTransaction::Call.into(),
            }
        }
    }
}

impl<T: Config> Pallet<T> {
    pub fn successful_bundles() -> Vec<H256> {
        SuccessfulBundles::<T>::get()
    }

    /// Returns the block number of the latest receipt.
    pub fn head_receipt_number() -> T::BlockNumber {
        pallet_settlement::Pallet::<T>::head_receipt_number(DomainId::SYSTEM)
    }

    /// Returns the block number of the oldest receipt still being tracked in the state.
    pub fn oldest_receipt_number() -> T::BlockNumber {
        pallet_settlement::Pallet::<T>::oldest_receipt_number(DomainId::SYSTEM)
    }

    fn pre_dispatch_submit_bundle(
        opaque_bundle: &OpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
    ) -> Result<(), TransactionValidityError> {
        if !opaque_bundle.domain_id().is_system() {
            return Ok(());
        }

        let receipt = &opaque_bundle.receipt;
        let oldest_receipt_number = Self::oldest_receipt_number();
        let next_head_receipt_number = Self::head_receipt_number() + One::one();
        let primary_number = receipt.primary_number;

        // Ignore the receipt if it has already been pruned.
        if primary_number < oldest_receipt_number {
            return Ok(());
        }

        // TODO: check if the receipt extend the receipt chain or add confirmations to the head receipt.
        match primary_number.cmp(&next_head_receipt_number) {
            // Missing receipt.
            Ordering::Greater => {
                return Err(TransactionValidityError::Invalid(
                    InvalidTransactionCode::ExecutionReceipt.into(),
                ));
            }
            // Non-best receipt or new best receipt.
            Ordering::Less | Ordering::Equal => {
                if !pallet_settlement::Pallet::<T>::point_to_valid_primary_block(
                    DomainId::SYSTEM,
                    receipt,
                ) {
                    log::debug!(
                        target: "runtime::domains",
                        "Invalid primary hash for #{primary_number:?} in receipt, \
                        expected: {:?}, got: {:?}",
                        pallet_settlement::PrimaryBlockHash::<T>::get(DomainId::SYSTEM, primary_number),
                        receipt.primary_hash,
                    );
                    return Err(TransactionValidityError::Invalid(
                        InvalidTransactionCode::ExecutionReceipt.into(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn validate_system_bundle_solution(
        receipt: &ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>,
        authority_stake_weight: sp_domains::StakeWeight,
        authority_witness: &Witness,
        proof_of_election: &ProofOfElection<T::DomainHash>,
    ) -> Result<(), BundleError> {
        let ProofOfElection {
            system_state_root,
            system_block_number,
            system_block_hash,
            ..
        } = proof_of_election;

        let state_root = *system_state_root;
        let block_number = T::BlockNumber::from(*system_block_number);
        let block_hash = *system_block_hash;

        let new_best_receipt_number = receipt.primary_number.max(Self::head_receipt_number());

        let state_root_verifiable = block_number <= new_best_receipt_number;

        if !block_number.is_zero() && state_root_verifiable {
            let maybe_state_root = receipt.trace.last().and_then(|state_root| {
                if (receipt.primary_number, receipt.domain_hash) == (block_number, block_hash) {
                    Some(*state_root)
                } else {
                    None
                }
            });

            let expected_state_root = match maybe_state_root {
                Some(v) => v,
                None => pallet_settlement::Pallet::<T>::state_root((
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
                        pallet_settlement::Pallet::<T>::receipt_head(DomainId::SYSTEM),
                    );
                    err
                })?,
            };

            if expected_state_root != state_root {
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

    fn validate_bundle(
        OpaqueBundle {
            header,
            receipt,
            extrinsics: _,
        }: &OpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
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
                    header.primary_number < finalized
                } else {
                    header.primary_number <= finalized
                };

                if is_stale_bundle {
                    log::debug!(
                        target: "runtime::domains",
                        "Bundle created on an ancient consensus block, current_block_number: {current_block_number:?}, \
                        ConfirmationDepthK: {confirmation_depth_k:?}, `bundle.header.primary_number`: {:?}, `finalized`: {finalized:?}",
                        header.primary_number,
                    );
                    return Err(BundleError::StaleBundle);
                }
            }
        }

        if !header.verify_signature() {
            return Err(BundleError::BadSignature);
        }

        let proof_of_election = header.bundle_solution.proof_of_election();
        proof_of_election
            .verify_vrf_proof()
            .map_err(|_| BundleError::BadVrfProof)?;

        if proof_of_election.domain_id.is_system() {
            let BundleSolution::System {
                authority_stake_weight,
                authority_witness,
                proof_of_election
            } = &header.bundle_solution else {
                unreachable!("Must be system domain bundle solution as we just checked; qed ")
            };

            // TODO: currently, only the system bundles created on the primary fork can be
            // prevented beforehand, the core bundles will be rejected by the system domain but
            // they are still included on the primary chain as it's not feasible to check core bundles
            // within this pallet, which may be solved if the `submit_bundle` extrinsic is no longer
            // free in the future.
            let bundle_created_on_valid_primary_block =
                match pallet_settlement::PrimaryBlockHash::<T>::get(
                    DomainId::SYSTEM,
                    header.primary_number,
                ) {
                    Some(block_hash) => block_hash == header.primary_hash,
                    // The `initialize_block` of non-system pallets is skipped in the `validate_transaction`,
                    // thus the hash of best block, which is recorded in the this pallet's `on_initialize` hook,
                    // is unavailable in pallet-receipts at this point.
                    None => frame_system::Pallet::<T>::parent_hash() == header.primary_hash,
                };

            if !bundle_created_on_valid_primary_block {
                log::debug!(
                    target: "runtime::domains",
                    "Bundle is probably created on a primary fork #{:?}, expected: {:?}, got: {:?}",
                    header.primary_number,
                    pallet_settlement::PrimaryBlockHash::<T>::get(DomainId::SYSTEM, header.primary_number),
                    header.primary_hash,
                );
                return Err(BundleError::UnknownBlock);
            }

            Self::validate_system_bundle_solution(
                receipt,
                *authority_stake_weight,
                authority_witness,
                proof_of_election,
            )?;

            let best_number = Self::head_receipt_number();
            let max_allowed = best_number + T::MaximumReceiptDrift::get();
            let oldest_receipt_number = Self::oldest_receipt_number();
            let primary_number = receipt.primary_number;

            // The corresponding block info has been pruned, such expired receipts
            // will be skipped too while applying the bundle.
            if primary_number < oldest_receipt_number {
                return Ok(());
            }

            // Due to `initialize_block` is skipped while calling the runtime api, the block
            // hash mapping for last block is unknown to the transaction pool, but this info
            // is already available in System.
            let point_to_parent_block = primary_number == current_block_number - One::one()
                && receipt.primary_hash == frame_system::Pallet::<T>::parent_hash();

            let point_to_valid_primary_block =
                pallet_settlement::Pallet::<T>::point_to_valid_primary_block(
                    DomainId::SYSTEM,
                    receipt,
                );

            if !point_to_parent_block && !point_to_valid_primary_block {
                log::debug!(
                    target: "runtime::domains",
                    "Receipt of #{primary_number:?},{:?} points to an unknown primary block, \
                    expected: #{primary_number:?},{:?}",
                    receipt.primary_hash,
                    pallet_settlement::PrimaryBlockHash::<T>::get(DomainId::SYSTEM, primary_number),
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

        Ok(())
    }
}

impl<T> Pallet<T>
where
    T: Config + frame_system::offchain::SendTransactionTypes<Call<T>>,
{
    /// Submits an unsigned extrinsic [`Call::submit_bundle`].
    pub fn submit_bundle_unsigned(
        opaque_bundle: OpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
    ) {
        let slot = opaque_bundle.header.slot_number;
        let extrincis_count = opaque_bundle.extrinsics.len();

        let call = Call::submit_bundle { opaque_bundle };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(
                    target: "runtime::domains",
                    "Submitted bundle from slot {slot}, extrinsics: {extrincis_count}",
                );
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
