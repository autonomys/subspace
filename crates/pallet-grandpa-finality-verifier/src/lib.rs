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

//! Substrate GRANDPA finality verifier
//!
//! This pallet is an on-chain GRANDPA finality verifier for Substrate based chains.
//!
//! The pallet is responsible for tracking GRANDPA validator set hand-offs. We only accept headers
//! with justifications signed by the current validator set we know of. The header is inspected for
//! a `ScheduledChanges` digest item, which is then used to update to next validator set.
//!
//! Since this pallet only tracks finalized headers it does not deal with forks. Forks can only
//! occur if the GRANDPA validator set on the bridged chain is either colluding or there is a severe
//! bug causing resulting in an equivocation. Such events are outside the scope of this pallet.
//! Shall the fork occur on the bridged chain governance intervention will be required to
//! re-initialize the bridge and track the right fork.

#![cfg_attr(not(feature = "std"), no_std)]

mod grandpa;

pub mod chain;
#[cfg(test)]
mod tests;

use codec::{Decode, Encode};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_consensus_grandpa::SetId;
use sp_std::fmt::Debug;
use sp_std::vec::Vec;

// Re-export in crate namespace for `construct_runtime!`
pub use pallet::*;

/// Data required to initialize a Chain
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct InitializationData {
    /// Scale encoded best finalized header we know.
    pub best_known_finalized_header: Vec<u8>,
    /// The ID of the current authority set
    pub set_id: SetId,
}

// Scale encoded block number, hash, and header of the target chain
type EncodedBlockNumber = Vec<u8>;
type EncodedBlockHash = Vec<u8>;
type EncodedHeader = Vec<u8>;

#[frame_support::pallet]
pub mod pallet {
    use crate::chain::Chain;
    use crate::grandpa::{
        find_forced_change, find_scheduled_change, verify_justification, AuthoritySet,
    };
    use crate::{EncodedBlockHash, EncodedBlockNumber, EncodedHeader, InitializationData};
    use finality_grandpa::voter_set::VoterSet;
    use frame_support::pallet_prelude::*;
    use sp_consensus_grandpa::GRANDPA_ENGINE_ID;
    use sp_runtime::traits::{CheckedAdd, CheckedSub, Hash, Header, One, Zero};
    use sp_runtime::ArithmeticError;
    use sp_std::fmt::Debug;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        // Chain ID uniquely identifies a substrate based chain
        type ChainId: Parameter + Member + Debug + Default + Copy;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(PhantomData<T>);

    /// The point after which the block validation begins
    #[pallet::storage]
    pub(super) type ValidationCheckPoint<T: Config> =
        StorageMap<_, Identity, T::ChainId, (EncodedBlockNumber, EncodedHeader), ValueQuery>;

    /// Oldest known parent
    #[pallet::storage]
    pub(super) type OldestKnownParent<T: Config> =
        StorageMap<_, Identity, T::ChainId, (EncodedBlockNumber, EncodedBlockHash), ValueQuery>;

    /// Known tip of the chain
    #[pallet::storage]
    pub(super) type ChainTip<T: Config> =
        StorageMap<_, Identity, T::ChainId, (EncodedBlockNumber, EncodedBlockHash), ValueQuery>;

    /// The current GRANDPA Authority set for a given Chain
    #[pallet::storage]
    pub(super) type CurrentAuthoritySet<T: Config> =
        StorageMap<_, Identity, T::ChainId, AuthoritySet, ValueQuery>;

    #[pallet::error]
    pub enum Error<T> {
        /// The block and its contents are not valid
        InvalidBlock,
        /// The authority set from the underlying header chain is invalid.
        InvalidAuthoritySet,
        /// Justification is missing..
        MissingJustification,
        /// The given justification is invalid for the given header.
        InvalidJustification,
        /// Failed to decode initialization data
        FailedDecodingInitData,
        /// Failed to Decode header
        FailedDecodingHeader,
        /// Failed to Decode block number
        FailedDecodingBlockNumber,
        /// Failed to Decode block hash
        FailedDecodingBlockHash,
        /// Failed to Decode block
        FailedDecodingBlock,
        /// Failed to decode justifications
        FailedDecodingJustifications,
        /// The header is already finalized
        InvalidHeader,
        /// The scheduled authority set change found in the header is unsupported by the pallet.
        ///
        /// This is the case for non-standard (e.g forced) authority set changes.
        UnsupportedScheduledChange,
    }

    /// Initializes the chain by extracting the Authority set and best known parent of the chain.
    /// After the initialization the import of blocks can happen in forward and reverse direction based on the parent stored
    /// If Genesis is the validation point, then parent is set to Genesis.
    /// Else parent is set to the parent of the best finalized header
    pub(crate) fn initialize_chain<T: Config, C: Chain>(
        chain_id: T::ChainId,
        init_params: InitializationData,
    ) -> DispatchResult {
        let InitializationData {
            best_known_finalized_header: encoded_header,
            set_id,
        } = init_params;
        let header = C::decode_header::<T>(encoded_header.as_slice())?;
        let change =
            find_scheduled_change(&header).ok_or(Error::<T>::UnsupportedScheduledChange)?;

        // Set the validation point
        let encoded_number = header.number().encode();
        ValidationCheckPoint::<T>::insert(chain_id, (encoded_number.clone(), encoded_header));

        // Set authority set
        let authority_set = AuthoritySet {
            authorities: change.next_authorities,
            set_id,
        };
        CurrentAuthoritySet::<T>::insert(chain_id, authority_set);

        // set the oldest known parent
        let (parent_number, parent_hash) = header
            .number()
            .checked_sub(&One::one())
            .map(|number| (number.encode(), header.parent_hash().encode()))
            .unwrap_or((encoded_number, header.hash().encode()));

        OldestKnownParent::<T>::insert(chain_id, (parent_number.clone(), parent_hash.clone()));
        // we also set the chain tip to parent so that we sequentially import blocks from parent + 1
        ChainTip::<T>::insert(chain_id, (parent_number, parent_hash));
        Ok(())
    }

    pub fn validate_finalized_block<T: Config, C: Chain>(
        chain_id: T::ChainId,
        object: &[u8],
    ) -> Result<(C::Hash, C::BlockNumber), DispatchError> {
        // basic block validation
        let block = C::decode_block::<T>(object)?;
        let number = *block.block.header.number();
        let hash = block.block.header.hash();

        let extrinsics_root = C::Hasher::ordered_trie_root(
            block.block.extrinsics.iter().map(Encode::encode).collect(),
            sp_runtime::StateVersion::V0,
        );
        ensure!(
            extrinsics_root == *block.block.header.extrinsics_root(),
            Error::<T>::InvalidBlock
        );

        let (oldest_known_parent_height, oldest_known_parent_hash) =
            C::decode_block_number_and_hash::<T>(OldestKnownParent::<T>::get(chain_id))?;

        // if the target is the known oldest parent, we import the block and progress backward
        if oldest_known_parent_height == number {
            ensure!(oldest_known_parent_hash == hash, Error::<T>::InvalidBlock);

            OldestKnownParent::<T>::insert(
                chain_id,
                (
                    number.checked_sub(&One::one()).unwrap_or(number).encode(),
                    block.block.header.parent_hash().encode(),
                ),
            );

            return Ok((hash, number));
        }

        // get last imported block height and hash
        let (parent_number, parent_hash) =
            C::decode_block_number_and_hash::<T>(ChainTip::<T>::get(chain_id))?;

        // block height must be always increasing
        ensure!(
            number
                == parent_number
                    .checked_add(&One::one())
                    .ok_or(ArithmeticError::Overflow)?,
            Error::<T>::InvalidBlock
        );
        ensure!(
            *block.block.header.parent_hash() == parent_hash,
            Error::<T>::InvalidBlock
        );

        // double check the validation header before importing the block
        let (encoded_number, encoded_validation_header) = ValidationCheckPoint::<T>::get(chain_id);
        let validation_number = C::decode_block_number::<T>(encoded_number.as_slice())?;
        if number == validation_number {
            ensure!(
                encoded_validation_header == block.block.header.encode(),
                Error::<T>::InvalidHeader
            );
        }

        // if the target header is a descendent of validation block, validate the justification
        if number > validation_number {
            let justification = block
                .justifications
                .ok_or(Error::<T>::MissingJustification)?
                .into_justification(GRANDPA_ENGINE_ID)
                .ok_or(Error::<T>::MissingJustification)?;
            let justification = C::decode_grandpa_justifications::<T>(justification.as_slice())?;

            // fetch current authority set
            let authority_set = <CurrentAuthoritySet<T>>::get(chain_id);
            let voter_set =
                VoterSet::new(authority_set.authorities).ok_or(Error::<T>::InvalidAuthoritySet)?;
            let set_id = authority_set.set_id;

            // verify justification
            verify_justification::<C::Header>((hash, number), set_id, &voter_set, &justification)
                .map_err(|e| {
                log::error!(
                    target: "runtime::grandpa-finality-verifier",
                    "Received invalid justification for {:?}: {:?}",
                    hash,
                    e,
                );
                Error::<T>::InvalidJustification
            })?;

            // Update any next authority set if any
            try_enact_authority_change::<T, C>(chain_id, &block.block.header, set_id)?;
        }

        // update the latest descendant
        ChainTip::<T>::insert(chain_id, (number.encode(), hash.encode()));
        Ok((hash, number))
    }

    /// Check the given header for a GRANDPA scheduled authority set change. If a change
    /// is found it will be enacted immediately.
    ///
    /// This function does not support forced changes, or scheduled changes with delays
    /// since these types of changes are indicative of abnormal behavior from GRANDPA.
    pub(crate) fn try_enact_authority_change<T: Config, C: Chain>(
        chain_id: T::ChainId,
        header: &C::Header,
        current_set_id: sp_consensus_grandpa::SetId,
    ) -> DispatchResult {
        // We don't support forced changes - at that point governance intervention is required.
        ensure!(
            find_forced_change(header).is_none(),
            Error::<T>::UnsupportedScheduledChange
        );

        if let Some(change) = find_scheduled_change(header) {
            // GRANDPA only includes a `delay` for forced changes, so this isn't valid.
            ensure!(
                change.delay == Zero::zero(),
                Error::<T>::UnsupportedScheduledChange
            );

            let next_authorities = AuthoritySet {
                authorities: change.next_authorities,
                set_id: current_set_id + 1,
            };

            // Since our header schedules a change and we know the delay is 0, it must also enact
            // the change.
            CurrentAuthoritySet::<T>::insert(chain_id, &next_authorities);

            log::info!(
                target: "runtime::grandpa-finality-verifier",
                "Transitioned from authority set {} to {}! New authorities are: {:?}",
                current_set_id,
                current_set_id + 1,
                next_authorities,
            );
        };

        Ok(())
    }

    /// Bootstrap the chain to start importing valid finalized blocks
    ///
    /// The initial configuration provided does not need to be the genesis header of the bridged
    /// chain, it can be any arbitrary header. You can also provide the next scheduled set
    /// change if it is already know.
    ///
    /// This function is only allowed to be called from a trusted origin and writes to storage
    /// with practically no checks in terms of the validity of the data. It is important that
    /// you ensure that valid data is being passed in.
    pub fn initialize<T: Config, C: Chain>(
        chain_id: T::ChainId,
        init_data: &[u8],
    ) -> DispatchResult {
        let data = InitializationData::decode(&mut &*init_data).map_err(|error| {
            log::error!("Cannot decode init data, error: {:?}", error);
            Error::<T>::FailedDecodingInitData
        })?;

        initialize_chain::<T, C>(chain_id, data)?;
        Ok(())
    }

    /// purges the on chain state of a given chain
    pub fn purge<T: Config>(chain_id: T::ChainId) -> DispatchResult {
        ValidationCheckPoint::<T>::remove(chain_id);
        CurrentAuthoritySet::<T>::remove(chain_id);
        ChainTip::<T>::remove(chain_id);
        OldestKnownParent::<T>::remove(chain_id);
        Ok(())
    }
}
