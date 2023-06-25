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

use frame_support::traits::Get;
use frame_system::offchain::SubmitTransaction;
pub use pallet::*;
use sp_core::H256;
use sp_domains::fraud_proof::FraudProof;
use sp_domains::{DomainId, OpaqueBundle};
use sp_runtime::traits::{BlockNumberProvider, CheckedSub, One, Zero};
use sp_runtime::transaction_validity::TransactionValidityError;
use sp_std::vec::Vec;

pub type RuntimeId = u32;

#[frame_support::pallet]
mod pallet {
    use super::RuntimeId;
    use crate::weights::WeightInfo;
    use frame_support::pallet_prelude::{StorageMap, *};
    use frame_support::weights::Weight;
    use frame_support::{Identity, PalletError};
    use frame_system::pallet_prelude::*;
    use pallet_settlement::{Error as SettlementError, FraudProofError};
    use sp_core::H256;
    use sp_domains::fraud_proof::FraudProof;
    use sp_domains::transaction::InvalidTransactionCode;
    use sp_domains::{DomainId, ExecutorPublicKey, OpaqueBundle};
    use sp_runtime::traits::Zero;
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

    // TODO: Proper RuntimeObject
    #[derive(DebugNoBound, Encode, Decode, TypeInfo, CloneNoBound, PartialEqNoBound, EqNoBound)]
    #[scale_info(skip_type_params(T))]
    pub struct RuntimeObject<T: Config> {
        pub runtime_name: Vec<u8>,
        pub created_at: T::BlockNumber,
        pub updated_at: T::BlockNumber,
        pub runtime_upgrades: u32,
        pub domain_runtime_code: Vec<u8>,
    }

    /// Bundles submitted successfully in current block.
    #[pallet::storage]
    pub(super) type SuccessfulBundles<T> = StorageValue<_, Vec<H256>, ValueQuery>;

    #[pallet::storage]
    pub(super) type RuntimeRegistry<T> =
        StorageMap<_, Identity, RuntimeId, RuntimeObject<T>, OptionQuery>;

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
        // TODO: proper weight
        #[allow(deprecated)]
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_all(10_000))]
        pub fn submit_bundle(
            origin: OriginFor<T>,
            opaque_bundle: OpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domains", "Processing bundle: {opaque_bundle:?}");

            let domain_id = opaque_bundle.domain_id();

            // TODO: Implement the receipts processing v2.
            pallet_settlement::Pallet::<T>::track_receipt(domain_id, &opaque_bundle.receipt)
                .map_err(Error::<T>::from)?;

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

            pallet_settlement::Pallet::<T>::process_fraud_proof(fraud_proof)
                .map_err(Error::<T>::from)?;

            Ok(())
        }
    }

    #[pallet::genesis_config]
    #[derive(Default)]
    pub struct GenesisConfig {
        pub runtime_name_and_runtime_code: Option<(Vec<u8>, Vec<u8>)>,
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig {
        fn build(&self) {
            if let Some((runtime_name, runtime_code)) = &self.runtime_name_and_runtime_code {
                // Register the genesis domain runtime
                RuntimeRegistry::<T>::insert(
                    0u32,
                    RuntimeObject {
                        runtime_name: runtime_name.clone(),
                        created_at: Zero::zero(),
                        updated_at: Zero::zero(),
                        runtime_upgrades: 0u32,
                        domain_runtime_code: runtime_code.clone(),
                    },
                );

                // Instantiate the genesis domain
            }
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
        fn on_initialize(_block_number: T::BlockNumber) -> Weight {
            SuccessfulBundles::<T>::kill();

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
                Call::submit_bundle { opaque_bundle } => {
                    Self::pre_dispatch_submit_bundle(opaque_bundle)
                }
                Call::submit_fraud_proof { fraud_proof: _ } => Ok(()),
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

    pub fn domain_runtime_code(_domain_id: DomainId) -> Option<Vec<u8>> {
        // TODO: Retrive the runtime_id for given domain_id and then get the correct runtime_object
        RuntimeRegistry::<T>::get(0u32).map(|runtime_object| runtime_object.domain_runtime_code)
    }

    fn pre_dispatch_submit_bundle(
        _opaque_bundle: &OpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
    ) -> Result<(), TransactionValidityError> {
        // TODO: Validate domain block tree
        Ok(())
    }

    fn validate_bundle(
        OpaqueBundle {
            sealed_header,
            receipt: _,
            extrinsics: _,
        }: &OpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
    ) -> Result<(), BundleError> {
        if !sealed_header.verify_signature() {
            return Err(BundleError::BadSignature);
        }

        let header = &sealed_header.header;

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

        // TODO: Implement bundle validation.

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
        let slot = opaque_bundle.sealed_header.header.slot_number;
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
