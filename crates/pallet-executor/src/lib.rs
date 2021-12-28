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

//! Pallet Executor

#![cfg_attr(not(feature = "std"), no_std)]

use frame_system::offchain::SubmitTransaction;
pub use pallet::*;
use sp_executor::{ExecutionReceipt, FraudProof, OpaqueBundle};

// TODO: proper error value
const INVALID_FRAUD_PROOF: u8 = 100;

#[frame_support::pallet]
mod pallet {
    use crate::INVALID_FRAUD_PROOF;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_core::H256;
    use sp_executor::{ExecutionReceipt, FraudProof, OpaqueBundle};

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::error]
    pub enum Error<T> {
        /// The head has been already included.
        HeadAlreadyExists,
        /// The head number was wrong against the latest head.
        UnexpectedHeadNumber,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new candidate receipt was backed.
        CandidateReceiptStored {
            head_number: T::BlockNumber,
            head_hash: T::Hash,
        },
        /// A new candidate receipt was backed.
        ExecutionReceiptStored { receipt_hash: H256 },
        /// A transaction bundle was included.
        TransactionBundleStored { bundle_hash: H256 },
        /// A fraud proof was processed.
        FraudProofProcessed,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_candidate_receipt(
            origin: OriginFor<T>,
            head_number: T::BlockNumber,
            head_hash: T::Hash,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::debug!(
                target: "runtime::subspace::executor",
                "Submitting candidate receipt, head_number: {:?}, head_hash: {:?}",
                head_number, head_hash
            );

            ensure!(
                head_number == Self::last_head_number() + 1u32.into(),
                Error::<T>::UnexpectedHeadNumber
            );

            ensure!(
                !Heads::<T>::contains_key(head_number),
                Error::<T>::HeadAlreadyExists
            );

            LastHeadNumber::<T>::put(head_number);
            Heads::<T>::insert(head_number, head_hash);

            Self::deposit_event(Event::CandidateReceiptStored {
                head_number,
                head_hash,
            });

            Ok(())
        }

        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_execution_receipt(
            origin: OriginFor<T>,
            execution_receipt: ExecutionReceipt<T::Hash>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::debug!(
                target: "runtime::subspace::executor",
                "Submitting execution receipt: {:?}",
                execution_receipt
            );

            // TODO: track the execution receipt

            Self::deposit_event(Event::ExecutionReceiptStored {
                receipt_hash: execution_receipt.hash(),
            });

            Ok(())
        }

        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_transaction_bundle(
            origin: OriginFor<T>,
            opaque_bundle: OpaqueBundle,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::debug!(
                target: "runtime::subspace::executor",
                "Submitting transaction bundle: {:?}",
                opaque_bundle
            );

            Self::deposit_event(Event::TransactionBundleStored {
                bundle_hash: opaque_bundle.hash(),
            });

            Ok(())
        }

        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_fraud_proof(origin: OriginFor<T>, fraud_proof: FraudProof) -> DispatchResult {
            ensure_none(origin)?;

            log::debug!(
                target: "runtime::subspace::executor",
                "Submitting fraud proof: {:?}",
                fraud_proof
            );

            // TODO: slash the executor accordingly.

            Self::deposit_event(Event::FraudProofProcessed);

            Ok(())
        }
    }

    /// Latest block number of executor chain.
    ///
    /// This block is either waiting to be imported or already has been imported by the executor chain.
    #[pallet::storage]
    #[pallet::getter(fn last_head_number)]
    pub(super) type LastHeadNumber<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;

    /// Map of executor block number to the hash of that block.
    #[pallet::storage]
    #[pallet::getter(fn heads)]
    pub(super) type Heads<T: Config> = StorageMap<_, Twox64Concat, T::BlockNumber, T::Hash>;

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;
        fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
            match call {
                Call::submit_candidate_receipt { .. } => Ok(()),
                Call::submit_execution_receipt { .. } => Ok(()),
                Call::submit_transaction_bundle { .. } => Ok(()),
                Call::submit_fraud_proof { .. } => Ok(()),
                _ => Err(InvalidTransaction::Call.into()),
            }
        }

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::submit_candidate_receipt {
                    head_number,
                    head_hash,
                } => {
                    ValidTransaction::with_tag_prefix("SubspaceSubmitCandidateReceipt")
                        .priority(TransactionPriority::MAX)
                        .and_provides((head_number, head_hash))
                        .longevity(TransactionLongevity::MAX)
                        // We need this extrinsic to be propagted to the farmer nodes.
                        .propagate(true)
                        .build()
                }
                Call::submit_execution_receipt { execution_receipt } => {
                    // TODO: validate the Proof-of-Election

                    ValidTransaction::with_tag_prefix("SubspaceSubmitExecutionReceipt")
                        .priority(TransactionPriority::MAX)
                        .and_provides(execution_receipt.hash())
                        .longevity(TransactionLongevity::MAX)
                        // We need this extrinsic to be propagted to the farmer nodes.
                        .propagate(true)
                        .build()
                }
                Call::submit_transaction_bundle { opaque_bundle } => {
                    // TODO: validate the Proof-of-Election

                    ValidTransaction::with_tag_prefix("SubspaceSubmitTransactionBundle")
                        .priority(TransactionPriority::MAX)
                        .and_provides(opaque_bundle.hash())
                        .longevity(TransactionLongevity::MAX)
                        // We need this extrinsic to be propagted to the farmer nodes.
                        .propagate(true)
                        .build()
                }
                Call::submit_fraud_proof { fraud_proof } => {
                    // TODO: prevent the spamming of fraud proof transaction.
                    if let Err(e) = Self::check_fraud_proof(fraud_proof) {
                        log::error!(
                            target: "runtime::subspace::executor",
                            "Invalid fraud proof: {:?}",
                            e
                        );
                        return InvalidTransaction::Custom(INVALID_FRAUD_PROOF).into();
                    }

                    ValidTransaction::with_tag_prefix("SubspaceSubmitFraudProof")
                        .priority(TransactionPriority::MAX)
                        .and_provides(fraud_proof.proof.clone()) // TODO: proper value later.
                        .longevity(TransactionLongevity::MAX)
                        // We need this extrinsic to be propagted to the farmer nodes.
                        .propagate(true)
                        .build()
                }
                _ => InvalidTransaction::Call.into(),
            }
        }
    }
}

impl<T: Config> Pallet<T> {
    /// Returns the block hash given the block number.
    pub fn head_hash(number: T::BlockNumber) -> Option<T::Hash> {
        <Heads<T>>::get(number)
    }

    /// Returns the latest block hash of executor chain.
    pub fn pending_head() -> Option<T::Hash> {
        <Heads<T>>::get(Self::last_head_number())
    }

    // TODO: Checks the fraud proof is valid.
    fn check_fraud_proof(_fraud_proof: &FraudProof) -> Result<(), Error<T>> {
        Ok(())
    }
}

impl<T> Pallet<T>
where
    T: Config + frame_system::offchain::SendTransactionTypes<Call<T>>,
{
    /// Submits an unsigned extrinsic [`Call::submit_candidate_receipt`].
    pub fn submit_candidate_receipt_unsigned(
        head_number: T::BlockNumber,
        head_hash: T::Hash,
    ) -> frame_support::pallet_prelude::DispatchResult {
        let call = Call::submit_candidate_receipt {
            head_number,
            head_hash,
        };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => log::info!(
                target: "runtime::subspace::executor",
                "Submitted Subspace candidate receipt.",
            ),
            Err(e) => log::error!(
                target: "runtime::subspace::executor",
                "Error submitting Subspace candidate receipt: {:?}",
                e,
            ),
        }

        Ok(())
    }

    /// Submits an unsigned extrinsic [`Call::submit_execution_receipt`].
    pub fn submit_execution_receipt_unsigned(
        execution_receipt: ExecutionReceipt<T::Hash>,
    ) -> frame_support::pallet_prelude::DispatchResult {
        let call = Call::submit_execution_receipt { execution_receipt };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => log::info!(
                target: "runtime::subspace::executor",
                "Submitted Subspace execution receipt.",
            ),
            Err(e) => log::error!(
                target: "runtime::subspace::executor",
                "Error submitting Subspace execution receipt: {:?}",
                e,
            ),
        }

        Ok(())
    }

    /// Submits an unsigned extrinsic [`Call::submit_transaction_bundle`].
    pub fn submit_transaction_bundle_unsigned(
        opaque_bundle: OpaqueBundle,
    ) -> frame_support::pallet_prelude::DispatchResult {
        let call = Call::submit_transaction_bundle { opaque_bundle };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => log::info!(
                target: "runtime::subspace::executor",
                "Submitted Subspace transaction bundle.",
            ),
            Err(e) => log::error!(
                target: "runtime::subspace::executor",
                "Error submitting Subspace transaction bundle: {:?}",
                e,
            ),
        }

        Ok(())
    }

    /// Submits an unsigned extrinsic [`Call::submit_fraud_proof`].
    pub fn submit_fraud_proof_unsigned(
        fraud_proof: FraudProof,
    ) -> frame_support::pallet_prelude::DispatchResult {
        let call = Call::submit_fraud_proof { fraud_proof };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => log::info!(
                target: "runtime::subspace::executor",
                "Submitted Subspace fraud proof.",
            ),
            Err(e) => log::error!(
                target: "runtime::subspace::executor",
                "Error submitting Subspace fraud proof: {:?}",
                e,
            ),
        }

        Ok(())
    }
}
