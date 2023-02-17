// Copyright (C) 2022 Subspace Labs, Inc.
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

//! # Receipts Pallet
//!
//! This pallet provides the general common settlement functions needed by the consensus chain
//! and system domain, which mainly includes tracking the receipts and handling the fraud proofs
//! from the chain they secure.

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::ensure;
use frame_support::traits::Get;
pub use pallet::*;
use sp_domains::fraud_proof::FraudProof;
use sp_domains::{DomainId, ExecutionReceipt};
use sp_runtime::traits::{CheckedSub, One, Saturating, Zero};
use sp_std::vec::Vec;

#[frame_support::pallet]
mod pallet {
    use frame_support::pallet_prelude::{StorageMap, StorageNMap, *};
    use frame_support::PalletError;
    use sp_core::H256;
    use sp_domains::{DomainId, ExecutionReceipt};
    use sp_runtime::traits::{CheckEqual, MaybeDisplay, SimpleBitOps};
    use sp_std::fmt::Debug;

    #[pallet::config]
    pub trait Config: frame_system::Config {
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
            + MaxEncodedLen;

        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Maximum execution receipt drift.
        ///
        /// If the primary number of an execution receipt plus the maximum drift is bigger than the
        /// best execution chain number, this receipt will be rejected as being too far in the
        /// future.
        #[pallet::constant]
        type MaximumReceiptDrift: Get<Self::BlockNumber>;

        /// Number of execution receipts kept in the state.
        #[pallet::constant]
        type ReceiptsPruningDepth: Get<Self::BlockNumber>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub (super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Map of primary block number to primary block hash for tracking bounded receipts per domain.
    ///
    /// The oldest block hash will be pruned once the oldest receipt is pruned. However, if a
    /// domain stalls, i.e., no receipts are included in the domain's parent chain for a long time,
    /// the corresponding entry will grow indefinitely.
    ///
    /// TODO: there is a pitfall that any stalled domain can lead to an ubounded runtime storage
    /// growth.
    #[pallet::storage]
    #[pallet::getter(fn primary_hash)]
    pub type PrimaryBlockHash<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        DomainId,
        Twox64Concat,
        T::BlockNumber,
        T::Hash,
        OptionQuery,
    >;

    /// Stores the latest block number for which Execution receipt(s) are available for a given Domain.
    #[pallet::storage]
    #[pallet::getter(fn receipt_head)]
    pub(super) type HeadReceiptNumber<T: Config> =
        StorageMap<_, Twox64Concat, DomainId, T::BlockNumber, ValueQuery>;

    /// Block number of the oldest receipt stored in the state.
    #[pallet::storage]
    pub(super) type OldestReceiptNumber<T: Config> =
        StorageMap<_, Twox64Concat, DomainId, T::BlockNumber, ValueQuery>;

    /// Mapping from the receipt hash to the corresponding verified execution receipt.
    ///
    /// The capacity of receipts stored in the state is [`Config::ReceiptsPruningDepth`], the older
    /// ones will be pruned once the size of receipts exceeds this number.
    #[pallet::storage]
    #[pallet::getter(fn receipts)]
    pub(super) type Receipts<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        DomainId,
        Twox64Concat,
        H256,
        ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>,
        OptionQuery,
    >;

    /// Mapping for tracking the receipt votes.
    ///
    /// (domain_id, domain_block_hash, receipt_hash) -> receipt_count
    #[pallet::storage]
    pub type ReceiptVotes<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Twox64Concat, DomainId>,
            NMapKey<Twox64Concat, T::Hash>,
            NMapKey<Twox64Concat, H256>,
        ),
        u32,
        ValueQuery,
    >;

    /// Mapping for tracking the domain state roots.
    ///
    /// (domain_id, domain_block_number, domain_block_hash) -> domain_state_root
    #[pallet::storage]
    #[pallet::getter(fn state_root)]
    pub(super) type StateRoots<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Twox64Concat, DomainId>,
            NMapKey<Twox64Concat, T::BlockNumber>,
            NMapKey<Twox64Concat, T::DomainHash>,
        ),
        T::DomainHash,
        OptionQuery,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new domain receipt.
        NewDomainReceipt {
            domain_id: DomainId,
            primary_number: T::BlockNumber,
            primary_hash: T::Hash,
        },
        /// A fraud proof was processed.
        FraudProofProcessed {
            domain_id: DomainId,
            new_best_number: T::BlockNumber,
            new_best_hash: T::Hash,
        },
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
}

#[derive(Debug)]
pub enum Error {
    /// The parent execution receipt is missing.
    MissingParent,
    /// Can not find the block hash of given primary block number.
    UnavailablePrimaryBlockHash,
    /// Invalid fraud proof.
    FraudProof(FraudProofError),
}

impl From<FraudProofError> for Error {
    fn from(e: FraudProofError) -> Self {
        Self::FraudProof(e)
    }
}

impl<T: Config> Pallet<T> {
    /// Returns the block number of the latest receipt.
    pub fn head_receipt_number(domain_id: DomainId) -> T::BlockNumber {
        <HeadReceiptNumber<T>>::get(domain_id)
    }

    /// Returns the block number of the oldest receipt still being tracked in the state.
    pub fn oldest_receipt_number(domain_id: DomainId) -> T::BlockNumber {
        Self::finalized_receipt_number(domain_id) + One::one()
    }

    /// Returns the block number of latest _finalized_ receipt.
    pub fn finalized_receipt_number(domain_id: DomainId) -> T::BlockNumber {
        let best_number = <HeadReceiptNumber<T>>::get(domain_id);
        best_number.saturating_sub(T::ReceiptsPruningDepth::get())
    }

    /// Returns `true` if the primary block the receipt points to is part of the history.
    pub fn point_to_valid_primary_block(
        domain_id: DomainId,
        receipt: &ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>,
    ) -> bool {
        Self::primary_hash(domain_id, receipt.primary_number)
            .map(|hash| hash == receipt.primary_hash)
            .unwrap_or(false)
    }

    /// Initialize the genesis execution receipt
    pub fn initialize_genesis_receipt(domain_id: DomainId, genesis_hash: T::Hash) {
        let genesis_receipt = ExecutionReceipt {
            primary_number: Zero::zero(),
            primary_hash: genesis_hash,
            domain_hash: T::DomainHash::default(),
            trace: Vec::new(),
            trace_root: Default::default(),
        };
        Self::import_head_receipt(domain_id, &genesis_receipt);
        // Explicitly initialize the oldest receipt number even not necessary as ValueQuery is used.
        <OldestReceiptNumber<T>>::insert::<_, T::BlockNumber>(domain_id, Zero::zero());
    }

    /// Track the execution receipts for the domain
    pub fn track_receipts(
        domain_id: DomainId,
        receipts: &[ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>],
    ) -> Result<(), Error> {
        let oldest_receipt_number = <OldestReceiptNumber<T>>::get(domain_id);
        let mut best_number = <HeadReceiptNumber<T>>::get(domain_id);

        for receipt in receipts {
            let primary_number = receipt.primary_number;

            // Ignore the receipt if it has already been pruned.
            if primary_number < oldest_receipt_number {
                continue;
            }

            if primary_number <= best_number {
                // Either increase the vote for a known receipt or add a fork receipt at this height.
                Self::import_receipt(domain_id, receipt);
            } else if primary_number == best_number + One::one() {
                Self::import_head_receipt(domain_id, receipt);
                Self::remove_expired_receipts(domain_id, primary_number);
                best_number += One::one();
            } else {
                // Reject the entire Bundle due to the missing receipt(s) between [best_number, .., receipt.primary_number].
                return Err(Error::MissingParent);
            }
        }
        Ok(())
    }

    /// Process a verified fraud proof.
    pub fn process_fraud_proof(fraud_proof: FraudProof) -> Result<(), Error> {
        // Revert the execution chain.
        let domain_id = fraud_proof.domain_id;
        let mut to_remove = <HeadReceiptNumber<T>>::get(domain_id);

        let new_best_number: T::BlockNumber = fraud_proof.parent_number.into();
        let new_best_hash = PrimaryBlockHash::<T>::get(domain_id, new_best_number)
            .ok_or(Error::UnavailablePrimaryBlockHash)?;

        <HeadReceiptNumber<T>>::insert(domain_id, new_best_number);

        while to_remove > new_best_number {
            let block_hash = PrimaryBlockHash::<T>::get(domain_id, to_remove)
                .ok_or(Error::UnavailablePrimaryBlockHash)?;
            for (receipt_hash, _) in <ReceiptVotes<T>>::drain_prefix((domain_id, block_hash)) {
                if let Some(receipt) = <Receipts<T>>::take(domain_id, receipt_hash) {
                    StateRoots::<T>::remove((domain_id, to_remove, receipt.domain_hash))
                }
            }
            to_remove -= One::one();
        }
        // TODO: slash the executor accordingly.
        Self::deposit_event(Event::FraudProofProcessed {
            domain_id,
            new_best_number,
            new_best_hash,
        });
        Ok(())
    }

    pub fn validate_fraud_proof(fraud_proof: &FraudProof) -> Result<(), Error> {
        let best_number = Self::head_receipt_number(fraud_proof.domain_id);
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
            Self::primary_hash(fraud_proof.domain_id, parent_number) == Some(parent_hash),
            FraudProofError::UnknownBlock
        );

        // TODO: prevent the spamming of fraud proof transaction.

        Ok(())
    }
}

impl<T: Config> Pallet<T> {
    /// Remove the expired receipts once the receipts cache is full.
    fn remove_expired_receipts(domain_id: DomainId, primary_number: T::BlockNumber) {
        if let Some(to_prune) = primary_number.checked_sub(&T::ReceiptsPruningDepth::get()) {
            PrimaryBlockHash::<T>::mutate_exists(domain_id, to_prune, |maybe_block_hash| {
                if let Some(block_hash) = maybe_block_hash.take() {
                    for (receipt_hash, _) in
                        <ReceiptVotes<T>>::drain_prefix((domain_id, block_hash))
                    {
                        <Receipts<T>>::remove(domain_id, receipt_hash);
                    }
                }
            });
            <OldestReceiptNumber<T>>::insert(domain_id, to_prune + One::one());
            let _ = <StateRoots<T>>::clear_prefix((domain_id, to_prune), u32::MAX, None);
        }
    }

    /// Imports the receipt of the latest head of the domain.
    /// Updates the receipt head of the domain accordingly.
    fn import_head_receipt(
        domain_id: DomainId,
        receipt: &ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>,
    ) {
        Self::import_receipt(domain_id, receipt);
        HeadReceiptNumber::<T>::insert(domain_id, receipt.primary_number)
    }

    /// Imports a receipt of domain.
    /// Increments the receipt votes.
    /// Assumes the receipt number is not pruned yet and inserts the a new receipt if not present.
    fn import_receipt(
        domain_id: DomainId,
        execution_receipt: &ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>,
    ) {
        let primary_hash = execution_receipt.primary_hash;
        let primary_number = execution_receipt.primary_number;
        let receipt_hash = execution_receipt.hash();

        // Track the fork receipt if it's not seen before.
        if !<Receipts<T>>::contains_key(domain_id, receipt_hash) {
            <Receipts<T>>::insert(domain_id, receipt_hash, execution_receipt);
            if !primary_number.is_zero() {
                let state_root = execution_receipt
                    .trace
                    .last()
                    .expect("There are at least 2 elements in trace after the genesis block; qed");

                <StateRoots<T>>::insert(
                    (domain_id, primary_number, execution_receipt.domain_hash),
                    state_root,
                );
            }
            Self::deposit_event(Event::NewDomainReceipt {
                domain_id,
                primary_number,
                primary_hash,
            });
        }
        <ReceiptVotes<T>>::mutate((domain_id, primary_hash, receipt_hash), |count| {
            *count += 1;
        });
    }
}
