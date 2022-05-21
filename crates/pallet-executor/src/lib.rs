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

#[cfg(test)]
mod tests;

use frame_support::ensure;
use frame_support::traits::Get;
use frame_system::offchain::SubmitTransaction;
pub use pallet::*;
use sp_executor::{
    BundleEquivocationProof, FraudProof, InvalidTransactionProof, SignedExecutionReceipt,
    SignedOpaqueBundle,
};
use sp_runtime::traits::{BlockNumberProvider, One};
use sp_runtime::RuntimeAppPublic;

#[frame_support::pallet]
mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_support::PalletError;
    use frame_system::pallet_prelude::*;
    use sp_core::H256;
    use sp_executor::{
        BundleEquivocationProof, ExecutionReceipt, ExecutorId, FraudProof, InvalidTransactionProof,
        SignedExecutionReceipt, SignedOpaqueBundle,
    };
    use sp_runtime::traits::{
        CheckEqual, CheckedSub, MaybeDisplay, MaybeMallocSizeOf, One, SimpleBitOps,
    };
    use sp_std::fmt::Debug;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        /// Secondary chain block hash type.
        type SecondaryHash: Parameter
            + Member
            + MaybeSerializeDeserialize
            + Debug
            + MaybeDisplay
            + SimpleBitOps
            + Ord
            + Default
            + Copy
            + CheckEqual
            + sp_std::hash::Hash
            + AsRef<[u8]>
            + AsMut<[u8]>
            + MaybeMallocSizeOf
            + MaxEncodedLen;

        /// Number of execution receipts kept in the state.
        #[pallet::constant]
        type ReceiptsPruningDepth: Get<Self::BlockNumber>;

        /// Maximum execution receipt drift.
        ///
        /// If the primary number of an execution receipt plus the maximum drift is bigger than the
        /// best execution chain number, this receipt will be rejected as being too far in the
        /// future.
        type MaximumReceiptDrift: Get<Self::BlockNumber>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[derive(TypeInfo, Encode, Decode, PalletError, Debug)]
    pub enum BundleError {
        /// The signer of transaction bundle is unexpected.
        UnexpectedSigner,
        /// Invalid transaction bundle signature.
        BadSignature,
    }

    impl<T> From<BundleError> for Error<T> {
        fn from(e: BundleError) -> Self {
            Self::Bundle(e)
        }
    }

    #[derive(TypeInfo, Encode, Decode, PalletError, Debug)]
    pub enum ExecutionReceiptError {
        /// The signer of execution receipt is unexpected.
        UnexpectedSigner,
        /// The parent execution receipt is unknown.
        MissingParent,
        /// Invalid execution receipt signature.
        BadSignature,
        /// The execution receipt is stale.
        Stale,
        /// The execution receipt points to a block unknown to the history.
        UnknownBlock,
        /// The execution receipt is too far in the future.
        TooFarInFuture,
    }

    impl<T> From<ExecutionReceiptError> for Error<T> {
        fn from(e: ExecutionReceiptError) -> Self {
            Self::ExecutionReceipt(e)
        }
    }

    #[derive(TypeInfo, Encode, Decode, PalletError, Debug)]
    pub enum FraudProofError {
        /// Fraud proof is expired as the execution receipt has been pruned.
        ExecutionReceiptPruned,
        /// Trying to prove an receipt from the future.
        ExecutionReceiptInFuture,
    }

    impl<T> From<FraudProofError> for Error<T> {
        fn from(e: FraudProofError) -> Self {
            Self::FraudProof(e)
        }
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Invalid bundle.
        Bundle(BundleError),
        /// Invalid execution receipt.
        ExecutionReceipt(ExecutionReceiptError),
        /// Invalid fraud proof.
        FraudProof(FraudProofError),
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new execution receipt was backed.
        NewExecutionReceipt {
            primary_number: T::BlockNumber,
            primary_hash: T::Hash,
        },
        /// A transaction bundle was included.
        TransactionBundleStored { bundle_hash: H256 },
        /// A fraud proof was processed.
        FraudProofProcessed,
        /// A bundle equivocation proof was processed.
        BundleEquivocationProofProcessed,
        /// An invalid transaction proof was processed.
        InvalidTransactionProofProcessed,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // TODO: proper weight
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_execution_receipt(
            origin: OriginFor<T>,
            signed_execution_receipt: SignedExecutionReceipt<
                T::BlockNumber,
                T::Hash,
                T::SecondaryHash,
            >,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::debug!(
                target: "runtime::subspace::executor",
                "Submitting execution receipt: {:?}",
                signed_execution_receipt
            );

            // TODO: ensure the receipt is ready to be applied

            let SignedExecutionReceipt {
                execution_receipt, ..
            } = signed_execution_receipt;

            let primary_hash = execution_receipt.primary_hash;
            let primary_number = execution_receipt.primary_number;

            // Execution receipt starts from the primary block #1.
            if primary_number > One::one() {
                ensure!(
                    Receipts::<T>::get(primary_number - One::one()).is_some(),
                    Error::<T>::ExecutionReceipt(ExecutionReceiptError::MissingParent)
                );
            } else {
                // Initialize the oldest receipt with block #1.
                OldestReceiptNumber::<T>::put(primary_number);
            }

            // Apply the execution receipt.
            <Receipts<T>>::insert(primary_number, execution_receipt);
            <ExecutionChainBestNumber<T>>::put(primary_number);

            // Remove the oldest once the receipts cache is full.
            if let Some(to_prune) = primary_number.checked_sub(&T::ReceiptsPruningDepth::get()) {
                Receipts::<T>::remove(to_prune);
                BlockHash::<T>::remove(to_prune);
                OldestReceiptNumber::<T>::put(to_prune + One::one());
            }

            Self::deposit_event(Event::NewExecutionReceipt {
                primary_number,
                primary_hash,
            });

            Ok(())
        }

        // TODO: proper weight
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_transaction_bundle(
            origin: OriginFor<T>,
            signed_opaque_bundle: SignedOpaqueBundle,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::debug!(
                target: "runtime::subspace::executor",
                "Submitting transaction bundle: {:?}",
                signed_opaque_bundle
            );

            Self::deposit_event(Event::TransactionBundleStored {
                bundle_hash: signed_opaque_bundle.hash(),
            });

            Ok(())
        }

        // TODO: proper weight
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_fraud_proof(origin: OriginFor<T>, fraud_proof: FraudProof) -> DispatchResult {
            ensure_none(origin)?;

            log::debug!(
                target: "runtime::subspace::executor",
                "Submitting fraud proof: {:?}",
                fraud_proof
            );

            // Revert the execution chain.
            let new_best: T::BlockNumber = fraud_proof.parent_number.into();
            <ExecutionChainBestNumber<T>>::mutate(|current_best| {
                let mut to_remove = new_best + One::one();
                while to_remove <= *current_best {
                    Receipts::<T>::remove(to_remove);
                    to_remove += One::one();
                }
                *current_best = new_best;
            });

            // TODO: slash the executor accordingly.

            Self::deposit_event(Event::FraudProofProcessed);

            Ok(())
        }

        // TODO: proper weight
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_bundle_equivocation_proof(
            origin: OriginFor<T>,
            bundle_equivocation_proof: BundleEquivocationProof,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::debug!(
                target: "runtime::subspace::executor",
                "Submitting bundle equivocation proof: {:?}",
                bundle_equivocation_proof
            );

            // TODO: slash the executor accordingly.

            Self::deposit_event(Event::BundleEquivocationProofProcessed);

            Ok(())
        }

        // TODO: proper weight
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_invalid_transaction_proof(
            origin: OriginFor<T>,
            invalid_transaction_proof: InvalidTransactionProof,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::debug!(
                target: "runtime::subspace::executor",
                "Submitting invalid transaction proof: {:?}",
                invalid_transaction_proof
            );

            // TODO: slash the executor accordingly.

            Self::deposit_event(Event::InvalidTransactionProofProcessed);

            Ok(())
        }
    }

    /// A tuple of (stable_executor_id, executor_signing_key).
    #[pallet::storage]
    #[pallet::getter(fn executor)]
    pub(super) type Executor<T: Config> = StorageValue<_, (T::AccountId, ExecutorId), OptionQuery>;

    /// Mapping from the primary block number to the corresponding verified execution receipt.
    ///
    /// The capacity of receipts stored in the state is [`Config::ReceiptsPruningDepth`], the older
    /// ones will be pruned once the size of receipts exceeds this number.
    #[pallet::storage]
    pub(super) type Receipts<T: Config> = StorageMap<
        _,
        Twox64Concat,
        T::BlockNumber,
        ExecutionReceipt<T::BlockNumber, T::Hash, T::SecondaryHash>,
        OptionQuery,
    >;

    /// Map of block number to block hash.
    ///
    /// NOTE: The oldest block hash will be pruned once the oldest receipt is pruned. However, if the
    /// execution chain stalls, i.e., no receipts are included in the primary chain for a long time,
    /// this mapping will grow indefinitely.
    #[pallet::storage]
    pub(super) type BlockHash<T: Config> =
        StorageMap<_, Twox64Concat, T::BlockNumber, T::Hash, ValueQuery>;

    /// Latest execution chain block number.
    #[pallet::storage]
    #[pallet::getter(fn best_execution_chain_number)]
    pub(super) type ExecutionChainBestNumber<T: Config> =
        StorageValue<_, T::BlockNumber, ValueQuery>;

    /// Number of the block that the oldest execution receipt points to.
    #[pallet::storage]
    pub(super) type OldestReceiptNumber<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;

    #[pallet::hooks]
    impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
        fn on_initialize(block_number: T::BlockNumber) -> Weight {
            <BlockHash<T>>::insert(
                block_number - One::one(),
                frame_system::Pallet::<T>::parent_hash(),
            );
            T::DbWeight::get().writes(1)
        }
    }

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub executor: Option<(T::AccountId, ExecutorId)>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self { executor: None }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            <Executor<T>>::put(
                self.executor
                    .clone()
                    .expect("Executor authority must be provided at genesis; qed"),
            );
        }
    }

    /// Constructs a `TransactionValidity` with pallet-executor specific defaults.
    fn unsigned_validity(prefix: &'static str, tag: impl Encode) -> TransactionValidity {
        ValidTransaction::with_tag_prefix(prefix)
            .priority(TransactionPriority::MAX)
            .and_provides(tag)
            .longevity(TransactionLongevity::MAX)
            // We need this extrinsic to be propagted to the farmer nodes.
            .propagate(true)
            .build()
    }

    #[repr(u8)]
    pub enum InvalidTransactionCode {
        BundleEquivicationProof = 101,
        TrasactionProof = 102,
        ExecutionReceipt = 103,
        Bundle = 104,
        FraudProof = 105,
    }

    impl From<InvalidTransactionCode> for InvalidTransaction {
        fn from(invalid_code: InvalidTransactionCode) -> Self {
            InvalidTransaction::Custom(invalid_code as u8)
        }
    }

    impl From<InvalidTransactionCode> for TransactionValidity {
        fn from(invalid_code: InvalidTransactionCode) -> Self {
            InvalidTransaction::Custom(invalid_code as u8).into()
        }
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;
        fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
            match call {
                Call::submit_execution_receipt {
                    signed_execution_receipt,
                } => {
                    let SignedExecutionReceipt {
                        execution_receipt, ..
                    } = signed_execution_receipt;

                    let primary_number = execution_receipt.primary_number;
                    let best_number = ExecutionChainBestNumber::<T>::get();

                    // Ensure the block number of next execution receipt is `best_number + 1`.
                    if primary_number != best_number + One::one() {
                        if primary_number <= best_number {
                            return Err(InvalidTransaction::Stale.into());
                        } else {
                            return Err(InvalidTransaction::Future.into());
                        }
                    }

                    Ok(())
                }
                Call::submit_transaction_bundle { .. } => Ok(()),
                Call::submit_fraud_proof { .. } => Ok(()),
                Call::submit_bundle_equivocation_proof { .. } => Ok(()),
                Call::submit_invalid_transaction_proof { .. } => Ok(()),
                _ => Err(InvalidTransaction::Call.into()),
            }
        }

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::submit_execution_receipt {
                    signed_execution_receipt,
                } => {
                    if let Err(e) = Self::validate_execution_receipt(signed_execution_receipt) {
                        log::error!(
                            target: "runtime::subspace::executor",
                            "Invalid execution receipt: {:?}, error: {:?}",
                            signed_execution_receipt, e
                        );
                        return InvalidTransactionCode::ExecutionReceipt.into();
                    }

                    let primary_number = signed_execution_receipt.execution_receipt.primary_number;

                    let builder =
                        ValidTransaction::with_tag_prefix("SubspaceSubmitExecutionReceipt")
                            .priority(TransactionPriority::MAX)
                            .and_provides(primary_number)
                            .longevity(TransactionLongevity::MAX)
                            .propagate(true);

                    // primary_number is ensured to be larger than the best execution chain chain
                    // number above.
                    //
                    // No requires if it's the next expected execution chain number.
                    if primary_number == ExecutionChainBestNumber::<T>::get() + One::one() {
                        builder.build()
                    } else {
                        builder.and_requires(primary_number - One::one()).build()
                    }
                }
                Call::submit_transaction_bundle {
                    signed_opaque_bundle,
                } => {
                    if let Err(e) = Self::validate_bundle(signed_opaque_bundle) {
                        log::error!(
                            target: "runtime::subspace::executor",
                            "Invalid signed opaque bundle: {:?}, error: {:?}",
                            signed_opaque_bundle, e
                        );
                        return InvalidTransactionCode::Bundle.into();
                    }
                    unsigned_validity(
                        "SubspaceSubmitTransactionBundle",
                        signed_opaque_bundle.hash(),
                    )
                }
                Call::submit_fraud_proof { fraud_proof } => {
                    if let Err(e) = Self::validate_fraud_proof(fraud_proof) {
                        log::error!(
                            target: "runtime::subspace::executor",
                            "Invalid fraud proof: {:?}, error: {:?}",
                            fraud_proof, e
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
                        log::error!(
                            target: "runtime::subspace::executor",
                            "Invalid bundle equivocation proof: {:?}, error: {:?}",
                            bundle_equivocation_proof, e
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
                        log::error!(
                            target: "runtime::subspace::executor",
                            "Wrong InvalidTransactionProof: {:?}, error: {:?}",
                            invalid_transaction_proof, e
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
    fn validate_execution_receipt(
        SignedExecutionReceipt {
            execution_receipt,
            signature,
            signer,
        }: &SignedExecutionReceipt<T::BlockNumber, T::Hash, T::SecondaryHash>,
    ) -> Result<(), ExecutionReceiptError> {
        if !signer.verify(&execution_receipt.hash(), signature) {
            return Err(ExecutionReceiptError::BadSignature);
        }

        let current_block_number = frame_system::Pallet::<T>::current_block_number();

        // Due to `initialize_block` is skipped while calling the runtime api, the block
        // hash mapping for last block is unknown to the transaction pool, but this info
        // is already available in System.
        let point_to_parent_block = execution_receipt.primary_number
            == current_block_number - One::one()
            && execution_receipt.primary_hash == frame_system::Pallet::<T>::parent_hash();

        if !point_to_parent_block
            && BlockHash::<T>::get(execution_receipt.primary_number)
                != execution_receipt.primary_hash
        {
            return Err(ExecutionReceiptError::UnknownBlock);
        }

        // TODO: upgrade once the trusted executor system is upgraded.
        let expected_executor = Self::executor()
            .map(|(_, authority_id)| authority_id)
            .expect("Executor must be initialized before launching the executor chain; qed");
        if *signer != expected_executor {
            return Err(ExecutionReceiptError::UnexpectedSigner);
        }

        // Ensure the receipt is neither old nor too new.
        let primary_number = execution_receipt.primary_number;

        let best_number = ExecutionChainBestNumber::<T>::get();
        if primary_number <= best_number {
            return Err(ExecutionReceiptError::Stale);
        }

        if primary_number == current_block_number
            || primary_number > best_number + T::MaximumReceiptDrift::get()
        {
            return Err(ExecutionReceiptError::TooFarInFuture);
        }

        Ok(())
    }

    fn validate_bundle(
        SignedOpaqueBundle {
            opaque_bundle,
            signature,
            signer,
        }: &SignedOpaqueBundle,
    ) -> Result<(), BundleError> {
        if !signer.verify(&opaque_bundle.hash(), signature) {
            return Err(BundleError::BadSignature);
        }

        // TODO: upgrade once the trusted executor system is upgraded.
        let expected_executor = Self::executor()
            .map(|(_, authority_id)| authority_id)
            .expect("Executor must be initialized before launching the executor chain; qed");
        if *signer != expected_executor {
            return Err(BundleError::UnexpectedSigner);
        }

        Ok(())
    }

    fn validate_fraud_proof(fraud_proof: &FraudProof) -> Result<(), FraudProofError> {
        let to_prove: T::BlockNumber = (fraud_proof.parent_number + 1u32).into();
        ensure!(
            to_prove >= OldestReceiptNumber::<T>::get(),
            FraudProofError::ExecutionReceiptPruned
        );
        ensure!(
            to_prove <= ExecutionChainBestNumber::<T>::get(),
            FraudProofError::ExecutionReceiptInFuture
        );

        // TODO: prevent the spamming of fraud proof transaction.
        // TODO: verify the fraud proof on the client side.
        // if !sp_executor::fraud_proof_ext::fraud_proof::verify(fraud_proof) {
        // log::error!(target: "runtime::subspace::executor", "Invalid fraud proof: {:?}", fraud_proof);
        // return InvalidTransaction::Custom(INVALID_FRAUD_PROOF).into();
        // }

        Ok(())
    }

    // TODO: Checks if the bundle equivocation proof is valid.
    fn validate_bundle_equivocation_proof(
        _bundle_equivocation_proof: &BundleEquivocationProof,
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
    /// Submits an unsigned extrinsic [`Call::submit_execution_receipt`].
    pub fn submit_execution_receipt_unsigned(
        signed_execution_receipt: SignedExecutionReceipt<T::BlockNumber, T::Hash, T::SecondaryHash>,
    ) {
        let call = Call::submit_execution_receipt {
            signed_execution_receipt,
        };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(target: "runtime::subspace::executor", "Submitted execution receipt");
            }
            Err(()) => {
                log::error!(
                    target: "runtime::subspace::executor",
                    "Error submitting execution receipt",
                );
            }
        }
    }

    /// Submits an unsigned extrinsic [`Call::submit_transaction_bundle`].
    pub fn submit_transaction_bundle_unsigned(signed_opaque_bundle: SignedOpaqueBundle) {
        let call = Call::submit_transaction_bundle {
            signed_opaque_bundle,
        };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(target: "runtime::subspace::executor", "Submitted transaction bundle");
            }
            Err(()) => {
                log::error!(
                    target: "runtime::subspace::executor",
                    "Error submitting transaction bundle",
                );
            }
        }
    }

    /// Submits an unsigned extrinsic [`Call::submit_fraud_proof`].
    pub fn submit_fraud_proof_unsigned(fraud_proof: FraudProof) {
        let call = Call::submit_fraud_proof { fraud_proof };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(target: "runtime::subspace::executor", "Submitted fraud proof");
            }
            Err(()) => {
                log::error!(target: "runtime::subspace::executor", "Error submitting fraud proof");
            }
        }
    }

    /// Submits an unsigned extrinsic [`Call::submit_bundle_equivocation_proof`].
    pub fn submit_bundle_equivocation_proof_unsigned(
        bundle_equivocation_proof: BundleEquivocationProof,
    ) {
        let call = Call::submit_bundle_equivocation_proof {
            bundle_equivocation_proof,
        };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(
                    target: "runtime::subspace::executor",
                    "Submitted bundle equivocation proof"
                );
            }
            Err(()) => {
                log::error!(
                    target: "runtime::subspace::executor",
                    "Error submitting bundle equivocation proof",
                );
            }
        }
    }

    /// Submits an unsigned extrinsic [`Call::submit_invalid_transaction_proof`].
    pub fn submit_invalid_transaction_proof_unsigned(
        invalid_transaction_proof: InvalidTransactionProof,
    ) {
        let call = Call::submit_invalid_transaction_proof {
            invalid_transaction_proof,
        };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(target: "runtime::subspace::executor", "Submitted invalid transaction proof")
            }
            Err(()) => {
                log::error!(
                    target: "runtime::subspace::executor",
                    "Error submitting invalid transaction proof",
                );
            }
        }
    }
}
