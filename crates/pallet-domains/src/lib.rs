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
#![feature(is_sorted)]

#[cfg(test)]
mod tests;

use codec::{Decode, Encode};
use frame_support::ensure;
use frame_support::traits::Get;
use frame_system::offchain::SubmitTransaction;
pub use pallet::*;
use sp_core::H256;
use sp_domains::bundle_election::{verify_system_bundle_solution, verify_vrf_proof};
use sp_domains::fraud_proof::{BundleEquivocationProof, FraudProof, InvalidTransactionProof};
use sp_domains::{ExecutionReceipt, InvalidTransactionCode, ProofOfElection, SignedOpaqueBundle};
use sp_runtime::traits::{BlockNumberProvider, CheckedSub, One, Saturating, Zero};
use sp_runtime::transaction_validity::TransactionValidityError;
use sp_runtime::RuntimeAppPublic;
use sp_std::vec::Vec;

#[frame_support::pallet]
mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_support::PalletError;
    use frame_system::pallet_prelude::*;
    use sp_core::H256;
    use sp_domains::fraud_proof::{BundleEquivocationProof, FraudProof, InvalidTransactionProof};
    use sp_domains::{
        ExecutionReceipt, ExecutorPublicKey, InvalidTransactionCode, SignedOpaqueBundle,
    };
    use sp_runtime::traits::{
        CheckEqual, MaybeDisplay, MaybeMallocSizeOf, One, SimpleBitOps, Zero,
    };
    use sp_std::fmt::Debug;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Domain block hash type.
        type DomainHash: Parameter
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
        #[pallet::constant]
        type MaximumReceiptDrift: Get<Self::BlockNumber>;

        /// Same with `pallet_subspace::Config::ConfirmationDepthK`.
        type ConfirmationDepthK: Get<Self::BlockNumber>;
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
        /// Invalid vrf proof.
        BadVrfProof,
        /// Can not verify the state root as the receipt is not been on the primary chain.
        StateRootUnverifiable,
        /// Invalid state root in the proof of election.
        BadStateRoot,
        /// The type of state root is not H256.
        StateRootNotH256,
        /// Invalid system bundle election solution.
        BadElectionSolution,
        /// An invalid execution receipt found in the bundle.
        Receipt(ExecutionReceiptError),
    }

    impl<T> From<BundleError> for Error<T> {
        fn from(e: BundleError) -> Self {
            Self::Bundle(e)
        }
    }

    #[derive(TypeInfo, Encode, Decode, PalletError, Debug)]
    pub enum ExecutionReceiptError {
        /// The parent execution receipt is unknown.
        MissingParent,
        /// The execution receipt has been pruned.
        Pruned,
        /// The execution receipt points to a block unknown to the history.
        UnknownBlock,
        /// The execution receipt is too far in the future.
        TooFarInFuture,
        /// Receipts are not in ascending order.
        Unsorted,
        /// Receipts in a bundle can not be empty.
        Empty,
    }

    #[derive(TypeInfo, Encode, Decode, PalletError, Debug)]
    pub enum FraudProofError {
        /// Fraud proof is expired as the execution receipt has been pruned.
        ExecutionReceiptPruned,
        /// Trying to prove an receipt from the future.
        ExecutionReceiptInFuture,
        /// Unexpected hash type.
        WrongHashType,
        /// The execution receipt points to a block unknown to the history.
        UnknownBlock,
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
        /// Invalid fraud proof.
        FraudProof(FraudProofError),
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        // TODO: We do not rely on this event to collect the receipts included in a block, perhaps can be removed later.
        /// A new execution receipt was backed.
        NewExecutionReceipt {
            primary_number: T::BlockNumber,
            primary_hash: T::Hash,
        },
        /// A domain bundle was included.
        BundleStored {
            bundle_hash: H256,
            bundle_author: ExecutorPublicKey,
        },
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
        pub fn submit_bundle(
            origin: OriginFor<T>,
            signed_opaque_bundle: SignedOpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::debug!(
                target: "runtime::subspace::executor",
                "Submitting transaction bundle: {:?}",
                signed_opaque_bundle
            );

            let oldest_receipt_number = OldestReceiptNumber::<T>::get();
            let (_, mut best_number) = <ReceiptHead<T>>::get();

            for receipt in &signed_opaque_bundle.bundle.receipts {
                // Ignore the receipt if it has already been pruned.
                if receipt.primary_number < oldest_receipt_number {
                    continue;
                }

                if receipt.primary_number <= best_number {
                    // Either increase the vote for a known receipt or add a fork receipt at this height.
                    Self::apply_non_new_best_receipt(receipt);
                } else if receipt.primary_number == best_number + One::one() {
                    Self::apply_new_best_receipt(receipt);
                    best_number += One::one();
                } else {
                    // Reject the entire Bundle due to the missing receipt(s) between [best_number, .., receipt.primary_number].
                    //
                    // This should never happen as pre_dispatch_submit_bundle ensures no missing receipt.
                    return Err(Error::<T>::Bundle(BundleError::Receipt(
                        ExecutionReceiptError::MissingParent,
                    ))
                    .into());
                }
            }

            Self::deposit_event(Event::BundleStored {
                bundle_hash: signed_opaque_bundle.hash(),
                bundle_author: signed_opaque_bundle.proof_of_election.executor_public_key,
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
            let (_, mut to_remove) = ReceiptHead::<T>::get();

            let new_best_number: T::BlockNumber = fraud_proof.parent_number.into();
            let new_best_hash = BlockHash::<T>::get(new_best_number);

            ReceiptHead::<T>::put((new_best_hash, new_best_number));

            while to_remove > new_best_number {
                let block_hash = BlockHash::<T>::get(to_remove);
                for (receipt_hash, _) in <ReceiptVotes<T>>::drain_prefix(block_hash) {
                    Receipts::<T>::remove(receipt_hash);
                }
                to_remove -= One::one();
            }

            // TODO: slash the executor accordingly.

            Self::deposit_event(Event::FraudProofProcessed);

            Ok(())
        }

        // TODO: proper weight
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_bundle_equivocation_proof(
            origin: OriginFor<T>,
            bundle_equivocation_proof: BundleEquivocationProof<T::Hash>,
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

    /// Map of block number to block hash.
    ///
    /// NOTE: The oldest block hash will be pruned once the oldest receipt is pruned. However, if the
    /// execution chain stalls, i.e., no receipts are included in the primary chain for a long time,
    /// this mapping will grow indefinitely.
    #[pallet::storage]
    pub(super) type BlockHash<T: Config> =
        StorageMap<_, Twox64Concat, T::BlockNumber, T::Hash, ValueQuery>;

    /// Mapping from the receipt hash to the corresponding verified execution receipt.
    ///
    /// The capacity of receipts stored in the state is [`Config::ReceiptsPruningDepth`], the older
    /// ones will be pruned once the size of receipts exceeds this number.
    #[pallet::storage]
    pub(super) type Receipts<T: Config> = StorageMap<
        _,
        Twox64Concat,
        H256,
        ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>,
        OptionQuery,
    >;

    /// Mapping for tracking the receipt votes.
    ///
    /// (primary_block_hash, receipt_hash, receipt_count)
    #[pallet::storage]
    pub(super) type ReceiptVotes<T: Config> =
        StorageDoubleMap<_, Twox64Concat, T::Hash, Blake2_128Concat, H256, u32, ValueQuery>;

    /// Mapping for tracking the secondary state roots.
    ///
    /// (secondary_block_number, secondary_block_hash, secondary_state_root)
    #[pallet::storage]
    pub(super) type StateRoots<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        T::BlockNumber,
        Blake2_128Concat,
        T::DomainHash,
        T::DomainHash,
        OptionQuery,
    >;

    /// A pair of (block_hash, block_number) of the latest execution receipt.
    #[pallet::storage]
    #[pallet::getter(fn receipt_head)]
    pub(super) type ReceiptHead<T: Config> = StorageValue<_, (T::Hash, T::BlockNumber), ValueQuery>;

    /// Block number of the oldest receipt stored in the state.
    #[pallet::storage]
    pub(super) type OldestReceiptNumber<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;

    #[pallet::hooks]
    impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
        fn on_initialize(block_number: T::BlockNumber) -> Weight {
            let parent_number = block_number - One::one();
            let parent_hash = frame_system::Pallet::<T>::block_hash(parent_number);

            <BlockHash<T>>::insert(parent_number, parent_hash);

            // The genesis block hash is not finalized until the genesis block building is done,
            // hence the genesis receipt is initialized after the genesis building.
            if parent_number.is_zero() {
                Self::initialize_genesis_receipt(parent_hash);
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
                        log::error!(
                            target: "runtime::subspace::executor",
                            "Invalid signed opaque bundle: {:?}, error: {:?}",
                            signed_opaque_bundle, e
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
    /// Returns the block number of the latest receipt.
    pub fn best_execution_chain_number() -> T::BlockNumber {
        let (_, best_number) = <ReceiptHead<T>>::get();
        best_number
    }

    /// Returns the block number of the oldest receipt still being tracked in the state.
    pub fn oldest_receipt_number() -> T::BlockNumber {
        Self::finalized_receipt_number() + One::one()
    }

    /// Returns the block number of latest _finalized_ receipt.
    pub fn finalized_receipt_number() -> T::BlockNumber {
        let (_, best_number) = <ReceiptHead<T>>::get();
        best_number.saturating_sub(T::ReceiptsPruningDepth::get())
    }

    fn initialize_genesis_receipt(genesis_hash: T::Hash) {
        let genesis_receipt = ExecutionReceipt {
            primary_number: Zero::zero(),
            primary_hash: genesis_hash,
            domain_hash: T::DomainHash::default(),
            trace: Vec::new(),
            trace_root: Default::default(),
        };
        Self::apply_new_best_receipt(&genesis_receipt);
        // Explicitly initialize the oldest receipt number even not necessary as ValueQuery is used.
        OldestReceiptNumber::<T>::put::<T::BlockNumber>(Zero::zero());
    }

    fn pre_dispatch_submit_bundle(
        signed_opaque_bundle: &SignedOpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
    ) -> Result<(), TransactionValidityError> {
        let execution_receipts = &signed_opaque_bundle.bundle.receipts;

        if !execution_receipts
            .iter()
            .map(|r| r.primary_number)
            .is_sorted()
        {
            return Err(TransactionValidityError::Invalid(
                InvalidTransactionCode::ExecutionReceipt.into(),
            ));
        }

        let (_, mut best_number) = <ReceiptHead<T>>::get();

        for receipt in execution_receipts {
            // Non-best receipt
            if receipt.primary_number <= best_number {
                if BlockHash::<T>::get(receipt.primary_number) != receipt.primary_hash {
                    return Err(TransactionValidityError::Invalid(
                        InvalidTransactionCode::ExecutionReceipt.into(),
                    ));
                }
                continue;
            // New nest receipt.
            } else if receipt.primary_number == best_number + One::one() {
                if BlockHash::<T>::get(receipt.primary_number) != receipt.primary_hash {
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

        Ok(())
    }

    fn validate_system_bundle_solution(
        receipts: &[ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>],
        proof_of_election: &ProofOfElection<T::DomainHash>,
    ) -> Result<(), BundleError> {
        let ProofOfElection {
            state_root,
            block_number,
            block_hash,
            ..
        } = proof_of_election;

        if !block_number.is_zero() {
            let block_number = T::BlockNumber::from(*block_number);

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
                None => StateRoots::<T>::get(block_number, block_hash)
                    .ok_or(BundleError::StateRootUnverifiable)?,
            };

            if expected_state_root != *state_root {
                return Err(BundleError::BadStateRoot);
            }
        }

        let state_root = H256::decode(&mut state_root.encode().as_slice())
            .map_err(|_| BundleError::StateRootNotH256)?;

        verify_system_bundle_solution(proof_of_election, state_root)
            .map_err(|_| BundleError::BadElectionSolution)?;

        Ok(())
    }

    fn validate_execution_receipts(
        execution_receipts: &[ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>],
    ) -> Result<(), ExecutionReceiptError> {
        let current_block_number = frame_system::Pallet::<T>::current_block_number();

        // Genesis block receipt is initialized on primary chain, the first block has no receipts,
        // but any block after the first one requires at least one receipt.
        if current_block_number > One::one() && execution_receipts.is_empty() {
            return Err(ExecutionReceiptError::Empty);
        }

        if !execution_receipts
            .iter()
            .map(|r| r.primary_number)
            .is_sorted()
        {
            return Err(ExecutionReceiptError::Unsorted);
        }

        let (_, mut best_number) = <ReceiptHead<T>>::get();

        for execution_receipt in execution_receipts {
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

            // Ensure the receipt is not too new.
            let primary_number = execution_receipt.primary_number;

            if primary_number == current_block_number
                || primary_number > best_number + T::MaximumReceiptDrift::get()
            {
                return Err(ExecutionReceiptError::TooFarInFuture);
            }

            best_number += One::one();
        }

        Ok(())
    }

    fn validate_bundle(
        SignedOpaqueBundle {
            bundle,
            proof_of_election,
            signature,
        }: &SignedOpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
    ) -> Result<(), BundleError> {
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

        if proof_of_election.domain_id.is_system() {
            Self::validate_system_bundle_solution(&bundle.receipts, proof_of_election)?;
        }

        Self::validate_execution_receipts(&bundle.receipts).map_err(BundleError::Receipt)?;

        Ok(())
    }

    fn validate_fraud_proof(fraud_proof: &FraudProof) -> Result<(), FraudProofError> {
        let (_, best_number) = <ReceiptHead<T>>::get();

        let to_prove: T::BlockNumber = (fraud_proof.parent_number + 1u32).into();
        ensure!(
            to_prove > best_number.saturating_sub(T::ReceiptsPruningDepth::get()),
            FraudProofError::ExecutionReceiptPruned
        );

        ensure!(
            to_prove <= best_number,
            FraudProofError::ExecutionReceiptInFuture
        );

        let parent_hash = T::Hash::decode(&mut fraud_proof.parent_hash.encode().as_slice())
            .map_err(|_| FraudProofError::WrongHashType)?;
        let parent_number: T::BlockNumber = fraud_proof.parent_number.into();
        ensure!(
            BlockHash::<T>::get(parent_number) == parent_hash,
            FraudProofError::UnknownBlock
        );

        // TODO: prevent the spamming of fraud proof transaction.

        Ok(())
    }

    // TODO: Checks if the bundle equivocation proof is valid.
    fn validate_bundle_equivocation_proof(
        _bundle_equivocation_proof: &BundleEquivocationProof<T::Hash>,
    ) -> Result<(), Error<T>> {
        Ok(())
    }

    // TODO: Checks if the invalid transaction proof is valid.
    fn validate_invalid_transaction_proof(
        _invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), Error<T>> {
        Ok(())
    }

    fn apply_new_best_receipt(
        execution_receipt: &ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>,
    ) {
        let primary_hash = execution_receipt.primary_hash;
        let primary_number = execution_receipt.primary_number;
        let receipt_hash = execution_receipt.hash();

        // Apply the new best receipt.
        <Receipts<T>>::insert(receipt_hash, execution_receipt);
        <ReceiptHead<T>>::put((primary_hash, primary_number));
        <ReceiptVotes<T>>::mutate(primary_hash, receipt_hash, |count| {
            *count += 1;
        });

        if !primary_number.is_zero() {
            let state_root = execution_receipt
                .trace
                .last()
                .expect("There are at least 2 elements in trace after the genesis block; qed");

            <StateRoots<T>>::insert(primary_number, execution_receipt.domain_hash, state_root);
        }

        // Remove the expired receipts once the receipts cache is full.
        if let Some(to_prune) = primary_number.checked_sub(&T::ReceiptsPruningDepth::get()) {
            BlockHash::<T>::mutate_exists(to_prune, |maybe_block_hash| {
                if let Some(block_hash) = maybe_block_hash.take() {
                    for (receipt_hash, _) in <ReceiptVotes<T>>::drain_prefix(block_hash) {
                        Receipts::<T>::remove(receipt_hash);
                    }
                }
            });
            OldestReceiptNumber::<T>::put(to_prune + One::one());
            let _ = <StateRoots<T>>::clear_prefix(to_prune, u32::MAX, None);
        }

        Self::deposit_event(Event::NewExecutionReceipt {
            primary_number,
            primary_hash,
        });
    }

    fn apply_non_new_best_receipt(
        execution_receipt: &ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>,
    ) {
        let primary_hash = execution_receipt.primary_hash;
        let primary_number = execution_receipt.primary_number;
        let receipt_hash = execution_receipt.hash();

        // Track the fork receipt if it's not seen before.
        if !<Receipts<T>>::contains_key(receipt_hash) {
            <Receipts<T>>::insert(receipt_hash, execution_receipt);
            if !primary_number.is_zero() {
                let state_root = execution_receipt
                    .trace
                    .last()
                    .expect("There are at least 2 elements in trace after the genesis block; qed");

                <StateRoots<T>>::insert(primary_number, execution_receipt.domain_hash, state_root);
            }
            Self::deposit_event(Event::NewExecutionReceipt {
                primary_number,
                primary_hash,
            });
        }
        <ReceiptVotes<T>>::mutate(primary_hash, receipt_hash, |count| {
            *count += 1;
        });
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
        bundle_equivocation_proof: BundleEquivocationProof<T::Hash>,
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
