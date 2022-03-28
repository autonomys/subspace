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

mod chain;
#[cfg(test)]
mod tests;

use chain::ChainType;
use codec::{Decode, Encode};
use frame_support::dispatch::DispatchResult;
use grandpa::{find_forced_change, find_scheduled_change, AuthoritySet};
use pallet_feeds::FeedValidator;
use scale_info::TypeInfo;
use sp_runtime::traits::{BadOrigin, Zero};
use sp_std::fmt::Debug;

// Re-export in crate namespace for `construct_runtime!`
use crate::chain::{Chain, PolkadotLike};
pub use pallet::*;

// ChainData holds the type of the Chain and if its operational
#[derive(Encode, Decode, TypeInfo)]
struct ChainData {
    chain_type: ChainType,
    halted: bool,
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use crate::grandpa::verify_justification;
    use finality_grandpa::voter_set::VoterSet;
    use frame_support::dispatch::RawOrigin;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::Header;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        // Chain ID uniquely identifies a substrate based chain
        type ChainId: Parameter + Member + MaybeSerializeDeserialize + Debug + Default + Copy;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(PhantomData<T>);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Change `PalletOwner`.
        ///
        /// May only be called either by root, or by `PalletOwner`.
        #[pallet::weight((T::DbWeight::get().reads_writes(1, 1), DispatchClass::Operational))]
        pub fn set_owner(
            origin: OriginFor<T>,
            new_owner: Option<T::AccountId>,
        ) -> DispatchResultWithPostInfo {
            ensure_owner_or_root::<T>(origin)?;
            match new_owner {
                Some(new_owner) => {
                    PalletOwner::<T>::put(&new_owner);
                    log::info!(target: "runtime::grandpa-finality-verifier", "Setting pallet Owner to: {:?}", new_owner);
                }
                None => {
                    PalletOwner::<T>::kill();
                    log::info!(target: "runtime::grandpa-finality-verifier", "Removed Owner of pallet.");
                }
            }

            Ok(().into())
        }

        /// Halt or resume all pallet operations.
        ///
        /// May only be called either by root, or by `PalletOwner`.
        #[pallet::weight((T::DbWeight::get().reads_writes(1, 1), DispatchClass::Operational))]
        pub fn set_operational(
            origin: OriginFor<T>,
            chain_id: T::ChainId,
            operational: bool,
        ) -> DispatchResult {
            ensure_owner_or_root::<T>(origin)?;
            Chains::<T>::try_mutate(chain_id, |maybe_data| -> DispatchResult {
                let data = maybe_data.as_mut().ok_or(Error::<T>::ChainUnknown)?;
                data.halted = !operational;
                Ok(())
            })
        }
    }

    /// Optional pallet owner.
    ///
    /// Pallet owner has a right to halt all pallet operations and then resume it. If it is
    /// `None`, then there are no direct ways to halt/resume pallet operations, but other
    /// runtime methods may still be used to do that (i.e. democracy::referendum to update halt
    /// flag directly or call the `halt_operations`).
    #[pallet::storage]
    pub type PalletOwner<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

    /// Best finalized header of a Chain
    #[pallet::storage]
    pub(super) type BestFinalized<T: Config> =
        StorageMap<_, Blake2_128Concat, T::ChainId, Vec<u8>, OptionQuery>;

    /// The current GRANDPA Authority set for a given Chain
    #[pallet::storage]
    pub(super) type CurrentAuthoritySet<T: Config> =
        StorageMap<_, Blake2_128Concat, T::ChainId, AuthoritySet, ValueQuery>;

    /// Map from Chain Id to ChainData
    #[pallet::storage]
    pub(super) type Chains<T: Config> =
        StorageMap<_, Blake2_128Concat, T::ChainId, ChainData, OptionQuery>;

    #[pallet::error]
    pub enum Error<T> {
        /// Unknown chain
        ChainUnknown,
        /// All feed operations are halted.
        Halted,
        /// The authority set from the underlying header chain is invalid.
        InvalidAuthoritySet,
        /// The given justification is invalid for the given header.
        InvalidJustification,
        /// Failed to Decode header
        FailedDecodingHeader,
        /// Failed to Decode block
        FailedDecodingBlock,
        /// Failed to decode finality proof
        FailedDecodingFinalityProof,
        /// Failed to decode justifications
        FailedDecodingJustifications,
        /// Best finalized header not found for chain
        FinalizedHeaderNotFound,
        /// The header is already finalized
        OldHeader,
        /// The scheduled authority set change found in the header is unsupported by the pallet.
        ///
        /// This is the case for non-standard (e.g forced) authority set changes.
        UnsupportedScheduledChange,
    }

    /// Ensure that the origin is either root, or `PalletOwner`.
    fn ensure_owner_or_root<T: Config>(origin: T::Origin) -> Result<(), BadOrigin> {
        match origin.into() {
            Ok(RawOrigin::Root) => Ok(()),
            Ok(RawOrigin::Signed(ref signer))
                if Some(signer) == <PalletOwner<T>>::get().as_ref() =>
            {
                Ok(())
            }
            _ => Err(BadOrigin),
        }
    }

    /// Ensure that the pallet is in operational mode (not halted).
    pub(crate) fn ensure_operational<T: Config>(
        chain_id: T::ChainId,
    ) -> Result<ChainType, Error<T>> {
        let data = Chains::<T>::get(chain_id);
        match data {
            None => Err(Error::<T>::ChainUnknown),
            Some(data) => {
                if data.halted {
                    Err(Error::<T>::Halted)
                } else {
                    Ok(data.chain_type)
                }
            }
        }
    }

    pub(crate) fn validate_finalized_block<T: Config, C: Chain>(
        chain_id: T::ChainId,
        object: &[u8],
        proof: &[u8],
    ) -> DispatchResult {
        let block = C::decode_block::<T>(object)?;
        let finality_proof = C::decode_finality_proof::<T>(proof)?;
        let justifications =
            C::decode_grandpa_justifications::<T>(finality_proof.justification.as_slice())?;
        let best_finalized = {
            let data =
                BestFinalized::<T>::get(chain_id).ok_or(Error::<T>::FinalizedHeaderNotFound)?;
            C::decode_header::<T>(data.as_slice())
        }?;

        // ensure block is always increasing
        let (number, hash) = (block.block.header.number(), block.block.header.hash());
        ensure!(best_finalized.number() < number, Error::<T>::OldHeader);

        // ensure block and finality points to same block hash
        ensure!(
            hash == finality_proof.block,
            Error::<T>::InvalidJustification
        );

        // fetch current authority set
        let authority_set = <CurrentAuthoritySet<T>>::get(chain_id);
        let voter_set =
            VoterSet::new(authority_set.authorities).ok_or(Error::<T>::InvalidAuthoritySet)?;
        let set_id = authority_set.set_id;

        // verify justification
        verify_justification::<C::Header>((hash, *number), set_id, &voter_set, &justifications)
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
        let next_header = block.block.header;
        try_enact_authority_change::<T, C>(chain_id, &next_header, set_id)?;

        // Update best finalized header
        BestFinalized::<T>::insert(chain_id, next_header.encode());
        Ok(())
    }

    /// Check the given header for a GRANDPA scheduled authority set change. If a change
    /// is found it will be enacted immediately.
    ///
    /// This function does not support forced changes, or scheduled changes with delays
    /// since these types of changes are indicative of abnormal behavior from GRANDPA.
    pub(crate) fn try_enact_authority_change<T: Config, C: Chain>(
        chain_id: T::ChainId,
        header: &C::Header,
        current_set_id: sp_finality_grandpa::SetId,
    ) -> DispatchResult {
        // We don't support forced changes - at that point governance intervention is required.
        ensure!(
            find_forced_change(header).is_none(),
            Error::<T>::UnsupportedScheduledChange
        );

        if let Some(change) = super::find_scheduled_change(header) {
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
}

impl<T: Config> FeedValidator<T::ChainId> for Pallet<T> {
    fn validate(chain_id: T::ChainId, object: &[u8], proof: &[u8]) -> DispatchResult {
        let chain_type = ensure_operational::<T>(chain_id)?;
        match chain_type {
            ChainType::PolkadotLike => {
                validate_finalized_block::<T, PolkadotLike>(chain_id, object, proof)
            }
        }
    }
}
