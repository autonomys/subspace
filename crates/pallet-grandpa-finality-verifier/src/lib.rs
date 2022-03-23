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

//! GRANDPA Finality Verifier
//!
//! This pallet is an on-chain GRANDPA light client for Substrate based chains.
//!
//! This pallet achieves this by trustlessly verifying GRANDPA finality proofs on-chain.
//!
//! The pallet is responsible for tracking GRANDPA validator set hand-offs. We only import headers
//! with justifications signed by the current validator set we know of. The header is inspected for
//! a `ScheduledChanges` digest item, which is then used to update to next validator set.
//!
//! Since this pallet only tracks finalized headers it does not deal with forks. Forks can only
//! occur if the GRANDPA validator set on the bridged chain is either colluding or there is a severe
//! bug causing resulting in an equivocation. Such events are outside the scope of this pallet.
//! Shall the fork occur on the bridged chain governance intervention will be required to
//! re-initialize the bridge and track the right fork.

#![cfg_attr(not(feature = "std"), no_std)]
// Runtime-generated enums
#![allow(clippy::large_enum_variant)]

use finality_grandpa::voter_set::VoterSet;
use frame_support::{ensure, fail};
use frame_system::{ensure_signed, RawOrigin};
use grandpa::{
    AuthoritySet, BlockNumberOf, Chain, GrandpaJustification, HashOf, HasherOf, HeaderOf,
    InitializationData,
};
use sp_finality_grandpa::{ConsensusLog, GRANDPA_ENGINE_ID};
use sp_runtime::traits::{BadOrigin, Header as HeaderT, Zero};
use sp_std::{boxed::Box, convert::TryInto};

mod grandpa;

// Re-export in crate namespace for `construct_runtime!`
pub use pallet::*;

/// Block number of the bridged chain.
pub type BridgedBlockNumber<T> = BlockNumberOf<<T as Config>::BridgedChain>;
/// Block hash of the bridged chain.
pub type BridgedBlockHash<T> = HashOf<<T as Config>::BridgedChain>;
/// Hasher of the bridged chain.
pub type BridgedBlockHasher<T> = HasherOf<<T as Config>::BridgedChain>;
/// Header of the bridged chain.
pub type BridgedHeader<T> = HeaderOf<<T as Config>::BridgedChain>;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The chain we are bridging to here.
        type BridgedChain: Chain;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(PhantomData<T>);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Bootstrap the bridge pallet with an initial header and authority set from which to sync.
        ///
        /// The initial configuration provided does not need to be the genesis header of the bridged
        /// chain, it can be any arbitrary header. You can also provide the next scheduled set
        /// change if it is already know.
        ///
        /// This function is only allowed to be called from a trusted origin and writes to storage
        /// with practically no checks in terms of the validity of the data. It is important that
        /// you ensure that valid data is being passed in.
        #[pallet::weight((10_000, DispatchClass::Operational))]
        pub fn initialize(
            origin: OriginFor<T>,
            init_data: super::InitializationData<BridgedHeader<T>>,
        ) -> DispatchResultWithPostInfo {
            ensure_owner_or_root::<T>(origin)?;

            let init_allowed = !<BestFinalized<T>>::exists();
            ensure!(init_allowed, <Error<T>>::AlreadyInitialized);
            initialize_bridge::<T>(init_data.clone());

            log::info!(
                target: "runtime::bridge-grandpa",
                "Pallet has been initialized with the following parameters: {:?}",
                init_data
            );

            Ok(().into())
        }

        /// Change `PalletOwner`.
        ///
        /// May only be called either by root, or by `PalletOwner`.
        #[pallet::weight((10_000, DispatchClass::Operational))]
        pub fn set_owner(
            origin: OriginFor<T>,
            new_owner: Option<T::AccountId>,
        ) -> DispatchResultWithPostInfo {
            ensure_owner_or_root::<T>(origin)?;
            match new_owner {
                Some(new_owner) => {
                    PalletOwner::<T>::put(&new_owner);
                    log::info!(target: "runtime::bridge-grandpa", "Setting pallet Owner to: {:?}", new_owner);
                }
                None => {
                    PalletOwner::<T>::kill();
                    log::info!(target: "runtime::bridge-grandpa", "Removed Owner of pallet.");
                }
            }

            Ok(().into())
        }

        /// Halt or resume all pallet operations.
        ///
        /// May only be called either by root, or by `PalletOwner`.
        #[pallet::weight((10_000, DispatchClass::Operational))]
        pub fn set_operational(
            origin: OriginFor<T>,
            operational: bool,
        ) -> DispatchResultWithPostInfo {
            ensure_owner_or_root::<T>(origin)?;
            <IsHalted<T>>::put(!operational);

            if operational {
                log::info!(target: "runtime::bridge-grandpa", "Resuming pallet operations.");
            } else {
                log::warn!(target: "runtime::bridge-grandpa", "Stopping pallet operations.");
            }

            Ok(().into())
        }
    }

    /// Hash of the header used to bootstrap the pallet.
    #[pallet::storage]
    pub(super) type InitialHash<T: Config> = StorageValue<_, BridgedBlockHash<T>, ValueQuery>;

    /// Best finalized header.
    #[pallet::storage]
    pub(super) type BestFinalized<T: Config> = StorageValue<_, BridgedHeader<T>, OptionQuery>;

    /// The current GRANDPA Authority set.
    #[pallet::storage]
    pub(super) type CurrentAuthoritySet<T: Config> = StorageValue<_, AuthoritySet, ValueQuery>;

    /// Optional pallet owner.
    ///
    /// Pallet owner has a right to halt all pallet operations and then resume it. If it is
    /// `None`, then there are no direct ways to halt/resume pallet operations, but other
    /// runtime methods may still be used to do that (i.e. democracy::referendum to update halt
    /// flag directly or call the `halt_operations`).
    #[pallet::storage]
    pub type PalletOwner<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

    /// If true, all pallet transactions are failed immediately.
    #[pallet::storage]
    pub(super) type IsHalted<T: Config> = StorageValue<_, bool, ValueQuery>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        /// Optional module owner account.
        pub owner: Option<T::AccountId>,
        /// Optional module initialization data.
        pub init_data: Option<super::InitializationData<BridgedHeader<T>>>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self {
                owner: None,
                init_data: None,
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            if let Some(ref owner) = self.owner {
                <PalletOwner<T>>::put(owner);
            }

            if let Some(init_data) = self.init_data.clone() {
                initialize_bridge::<T>(init_data);
            } else {
                // Since the bridge hasn't been initialized we shouldn't allow anyone to perform
                // transactions.
                <IsHalted<T>>::put(true);
            }
        }
    }

    #[pallet::error]
    pub enum Error<T> {
        /// The given justification is invalid for the given header.
        InvalidJustification,
        /// The authority set from the underlying header chain is invalid.
        InvalidAuthoritySet,
        /// There are too many requests for the current window to handle.
        TooManyRequests,
        /// The header being imported is older than the best finalized header known to the pallet.
        OldHeader,
        /// The header is unknown to the pallet.
        UnknownHeader,
        /// The scheduled authority set change found in the header is unsupported by the pallet.
        ///
        /// This is the case for non-standard (e.g forced) authority set changes.
        UnsupportedScheduledChange,
        /// The pallet is not yet initialized.
        NotInitialized,
        /// The pallet has already been initialized.
        AlreadyInitialized,
        /// All pallet operations are halted.
        Halted,
        /// The storage proof doesn't contains storage root. So it is invalid for given header.
        StorageRootMismatch,
    }

    /// Check the given header for a GRANDPA scheduled authority set change. If a change
    /// is found it will be enacted immediately.
    ///
    /// This function does not support forced changes, or scheduled changes with delays
    /// since these types of changes are indicative of abnormal behavior from GRANDPA.
    ///
    /// Returned value will indicate if a change was enacted or not.
    pub(crate) fn try_enact_authority_change<T: Config>(
        header: &BridgedHeader<T>,
        current_set_id: sp_finality_grandpa::SetId,
    ) -> Result<bool, sp_runtime::DispatchError> {
        let mut change_enacted = false;

        // We don't support forced changes - at that point governance intervention is required.
        ensure!(
            super::find_forced_change(header).is_none(),
            <Error<T>>::UnsupportedScheduledChange
        );

        if let Some(change) = super::find_scheduled_change(header) {
            // GRANDPA only includes a `delay` for forced changes, so this isn't valid.
            ensure!(
                change.delay == Zero::zero(),
                <Error<T>>::UnsupportedScheduledChange
            );

            // TODO [#788]: Stop manually increasing the `set_id` here.
            let next_authorities = AuthoritySet {
                authorities: change.next_authorities,
                set_id: current_set_id + 1,
            };

            // Since our header schedules a change and we know the delay is 0, it must also enact
            // the change.
            <CurrentAuthoritySet<T>>::put(&next_authorities);
            change_enacted = true;

            log::info!(
                target: "runtime::bridge-grandpa",
                "Transitioned from authority set {} to {}! New authorities are: {:?}",
                current_set_id,
                current_set_id + 1,
                next_authorities,
            );
        };

        Ok(change_enacted)
    }

    /// Verify a GRANDPA justification (finality proof) for a given header.
    ///
    /// Will use the GRANDPA current authorities known to the pallet.
    ///
    /// If successful it returns the decoded GRANDPA justification so we can refund any weight which
    /// was overcharged in the initial call.
    pub(crate) fn verify_justification<T: Config>(
        justification: &GrandpaJustification<BridgedHeader<T>>,
        hash: BridgedBlockHash<T>,
        number: BridgedBlockNumber<T>,
        authority_set: AuthoritySet,
    ) -> Result<(), sp_runtime::DispatchError> {
        use grandpa::verify_justification;

        let voter_set =
            VoterSet::new(authority_set.authorities).ok_or(<Error<T>>::InvalidAuthoritySet)?;
        let set_id = authority_set.set_id;

        Ok(verify_justification::<BridgedHeader<T>>(
            (hash, number),
            set_id,
            &voter_set,
            justification,
        )
        .map_err(|e| {
            log::error!(
                target: "runtime::bridge-grandpa",
                "Received invalid justification for {:?}: {:?}",
                hash,
                e,
            );
            <Error<T>>::InvalidJustification
        })?)
    }

    /// Since this writes to storage with no real checks this should only be used in functions that
    /// were called by a trusted origin.
    pub(crate) fn initialize_bridge<T: Config>(
        init_params: super::InitializationData<BridgedHeader<T>>,
    ) {
        let super::InitializationData {
            header,
            authority_list,
            set_id,
            is_halted,
        } = init_params;

        let initial_hash = header.hash();
        <InitialHash<T>>::put(initial_hash);
        <BestFinalized<T>>::put(*header);

        let authority_set = AuthoritySet {
            authorities: authority_list,
            set_id,
        };
        <CurrentAuthoritySet<T>>::put(authority_set);

        <IsHalted<T>>::put(is_halted);
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
    fn ensure_operational<T: Config>() -> Result<(), Error<T>> {
        if <IsHalted<T>>::get() {
            Err(<Error<T>>::Halted)
        } else {
            Ok(())
        }
    }
}

pub(crate) fn find_scheduled_change<H: HeaderT>(
    header: &H,
) -> Option<sp_finality_grandpa::ScheduledChange<H::Number>> {
    use sp_runtime::generic::OpaqueDigestItemId;

    let id = OpaqueDigestItemId::Consensus(&GRANDPA_ENGINE_ID);

    let filter_log = |log: ConsensusLog<H::Number>| match log {
        ConsensusLog::ScheduledChange(change) => Some(change),
        _ => None,
    };

    // find the first consensus digest with the right ID which converts to
    // the right kind of consensus log.
    header
        .digest()
        .convert_first(|l| l.try_to(id).and_then(filter_log))
}

/// Checks the given header for a consensus digest signaling a **forced** scheduled change and
/// extracts it.
pub(crate) fn find_forced_change<H: HeaderT>(
    header: &H,
) -> Option<(H::Number, sp_finality_grandpa::ScheduledChange<H::Number>)> {
    use sp_runtime::generic::OpaqueDigestItemId;

    let id = OpaqueDigestItemId::Consensus(&GRANDPA_ENGINE_ID);

    let filter_log = |log: ConsensusLog<H::Number>| match log {
        ConsensusLog::ForcedChange(delay, change) => Some((delay, change)),
        _ => None,
    };

    // find the first consensus digest with the right ID which converts to
    // the right kind of consensus log.
    header
        .digest()
        .convert_first(|l| l.try_to(id).and_then(filter_log))
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::mock::{run_test, test_header, Origin, TestHeader, TestNumber, TestRuntime};
//     use bp_test_utils::{
//         authority_list, make_default_justification, make_justification_for_header,
//         JustificationGeneratorParams, ALICE, BOB,
//     };
//     use codec::Encode;
//     use frame_support::{
//         assert_err, assert_noop, assert_ok, storage::generator::StorageValue,
//         weights::PostDispatchInfo,
//     };
//     use sp_runtime::{Digest, DigestItem, DispatchError};
//
//     fn initialize_substrate_bridge() {
//         assert_ok!(init_with_origin(Origin::root()));
//     }
//
//     fn init_with_origin(
//         origin: Origin,
//     ) -> Result<
//         InitializationData<TestHeader>,
//         sp_runtime::DispatchErrorWithPostInfo<PostDispatchInfo>,
//     > {
//         let genesis = test_header(0);
//
//         let init_data = InitializationData {
//             header: Box::new(genesis),
//             authority_list: authority_list(),
//             set_id: 1,
//             is_halted: false,
//         };
//
//         Pallet::<TestRuntime>::initialize(origin, init_data.clone()).map(|_| init_data)
//     }
//
//     fn submit_finality_proof(header: u8) -> frame_support::dispatch::DispatchResultWithPostInfo {
//         let header = test_header(header.into());
//         let justification = make_default_justification(&header);
//
//         Pallet::<TestRuntime>::submit_finality_proof(
//             Origin::signed(1),
//             Box::new(header),
//             justification,
//         )
//     }
//
//     fn next_block() {
//         use frame_support::traits::OnInitialize;
//
//         let current_number = frame_system::Pallet::<TestRuntime>::block_number();
//         frame_system::Pallet::<TestRuntime>::set_block_number(current_number + 1);
//         let _ = Pallet::<TestRuntime>::on_initialize(current_number);
//     }
//
//     fn change_log(delay: u64) -> Digest {
//         let consensus_log =
//             ConsensusLog::<TestNumber>::ScheduledChange(sp_finality_grandpa::ScheduledChange {
//                 next_authorities: vec![(ALICE.into(), 1), (BOB.into(), 1)],
//                 delay,
//             });
//
//         Digest {
//             logs: vec![DigestItem::Consensus(
//                 GRANDPA_ENGINE_ID,
//                 consensus_log.encode(),
//             )],
//         }
//     }
//
//     fn forced_change_log(delay: u64) -> Digest {
//         let consensus_log = ConsensusLog::<TestNumber>::ForcedChange(
//             delay,
//             sp_finality_grandpa::ScheduledChange {
//                 next_authorities: vec![(ALICE.into(), 1), (BOB.into(), 1)],
//                 delay,
//             },
//         );
//
//         Digest {
//             logs: vec![DigestItem::Consensus(
//                 GRANDPA_ENGINE_ID,
//                 consensus_log.encode(),
//             )],
//         }
//     }
//
//     #[test]
//     fn init_root_or_owner_origin_can_initialize_pallet() {
//         run_test(|| {
//             assert_noop!(
//                 init_with_origin(Origin::signed(1)),
//                 DispatchError::BadOrigin
//             );
//             assert_ok!(init_with_origin(Origin::root()));
//
//             // Reset storage so we can initialize the pallet again
//             BestFinalized::<TestRuntime>::kill();
//             PalletOwner::<TestRuntime>::put(2);
//             assert_ok!(init_with_origin(Origin::signed(2)));
//         })
//     }
//
//     #[test]
//     fn init_storage_entries_are_correctly_initialized() {
//         run_test(|| {
//             assert_eq!(
//                 BestFinalized::<TestRuntime>::get(),
//                 BridgedBlockHash::<TestRuntime, ()>::default()
//             );
//             assert_eq!(Pallet::<TestRuntime>::best_finalized(), test_header(0));
//
//             let init_data = init_with_origin(Origin::root()).unwrap();
//
//             assert!(<ImportedHeaders<TestRuntime>>::contains_key(
//                 init_data.header.hash()
//             ));
//             assert_eq!(BestFinalized::<TestRuntime>::get(), init_data.header.hash());
//             assert_eq!(
//                 CurrentAuthoritySet::<TestRuntime>::get().authorities,
//                 init_data.authority_list
//             );
//             assert!(!IsHalted::<TestRuntime>::get());
//         })
//     }
//
//     #[test]
//     fn init_can_only_initialize_pallet_once() {
//         run_test(|| {
//             initialize_substrate_bridge();
//             assert_noop!(
//                 init_with_origin(Origin::root()),
//                 <Error<TestRuntime>>::AlreadyInitialized
//             );
//         })
//     }
//
//     #[test]
//     fn pallet_owner_may_change_owner() {
//         run_test(|| {
//             PalletOwner::<TestRuntime>::put(2);
//
//             assert_ok!(Pallet::<TestRuntime>::set_owner(Origin::root(), Some(1)));
//             assert_noop!(
//                 Pallet::<TestRuntime>::set_operational(Origin::signed(2), false),
//                 DispatchError::BadOrigin,
//             );
//             assert_ok!(Pallet::<TestRuntime>::set_operational(
//                 Origin::root(),
//                 false
//             ));
//
//             assert_ok!(Pallet::<TestRuntime>::set_owner(Origin::signed(1), None));
//             assert_noop!(
//                 Pallet::<TestRuntime>::set_operational(Origin::signed(1), true),
//                 DispatchError::BadOrigin,
//             );
//             assert_noop!(
//                 Pallet::<TestRuntime>::set_operational(Origin::signed(2), true),
//                 DispatchError::BadOrigin,
//             );
//             assert_ok!(Pallet::<TestRuntime>::set_operational(Origin::root(), true));
//         });
//     }
//
//     #[test]
//     fn pallet_may_be_halted_by_root() {
//         run_test(|| {
//             assert_ok!(Pallet::<TestRuntime>::set_operational(
//                 Origin::root(),
//                 false
//             ));
//             assert_ok!(Pallet::<TestRuntime>::set_operational(Origin::root(), true));
//         });
//     }
//
//     #[test]
//     fn pallet_may_be_halted_by_owner() {
//         run_test(|| {
//             PalletOwner::<TestRuntime>::put(2);
//
//             assert_ok!(Pallet::<TestRuntime>::set_operational(
//                 Origin::signed(2),
//                 false
//             ));
//             assert_ok!(Pallet::<TestRuntime>::set_operational(
//                 Origin::signed(2),
//                 true
//             ));
//
//             assert_noop!(
//                 Pallet::<TestRuntime>::set_operational(Origin::signed(1), false),
//                 DispatchError::BadOrigin,
//             );
//             assert_noop!(
//                 Pallet::<TestRuntime>::set_operational(Origin::signed(1), true),
//                 DispatchError::BadOrigin,
//             );
//
//             assert_ok!(Pallet::<TestRuntime>::set_operational(
//                 Origin::signed(2),
//                 false
//             ));
//             assert_noop!(
//                 Pallet::<TestRuntime>::set_operational(Origin::signed(1), true),
//                 DispatchError::BadOrigin,
//             );
//         });
//     }
//
//     #[test]
//     fn pallet_rejects_transactions_if_halted() {
//         run_test(|| {
//             initialize_substrate_bridge();
//
//             assert_ok!(Pallet::<TestRuntime>::set_operational(
//                 Origin::root(),
//                 false
//             ));
//             assert_noop!(submit_finality_proof(1), Error::<TestRuntime>::Halted);
//
//             assert_ok!(Pallet::<TestRuntime>::set_operational(Origin::root(), true));
//             assert_ok!(submit_finality_proof(1));
//         })
//     }
//
//     #[test]
//     fn pallet_rejects_header_if_not_initialized_yet() {
//         run_test(|| {
//             assert_noop!(
//                 submit_finality_proof(1),
//                 Error::<TestRuntime>::NotInitialized
//             );
//         });
//     }
//
//     #[test]
//     fn succesfully_imports_header_with_valid_finality() {
//         run_test(|| {
//             initialize_substrate_bridge();
//             assert_ok!(
//                 submit_finality_proof(1),
//                 PostDispatchInfo {
//                     actual_weight: None,
//                     pays_fee: frame_support::weights::Pays::Yes,
//                 },
//             );
//
//             let header = test_header(1);
//             assert_eq!(<BestFinalized<TestRuntime>>::get(), header.hash());
//             assert!(<ImportedHeaders<TestRuntime>>::contains_key(header.hash()));
//         })
//     }
//
//     #[test]
//     fn rejects_justification_that_skips_authority_set_transition() {
//         run_test(|| {
//             initialize_substrate_bridge();
//
//             let header = test_header(1);
//
//             let params = JustificationGeneratorParams::<TestHeader> {
//                 set_id: 2,
//                 ..Default::default()
//             };
//             let justification = make_justification_for_header(params);
//
//             assert_err!(
//                 Pallet::<TestRuntime>::submit_finality_proof(
//                     Origin::signed(1),
//                     Box::new(header),
//                     justification,
//                 ),
//                 <Error<TestRuntime>>::InvalidJustification
//             );
//         })
//     }
//
//     #[test]
//     fn does_not_import_header_with_invalid_finality_proof() {
//         run_test(|| {
//             initialize_substrate_bridge();
//
//             let header = test_header(1);
//             let mut justification = make_default_justification(&header);
//             justification.round = 42;
//
//             assert_err!(
//                 Pallet::<TestRuntime>::submit_finality_proof(
//                     Origin::signed(1),
//                     Box::new(header),
//                     justification,
//                 ),
//                 <Error<TestRuntime>>::InvalidJustification
//             );
//         })
//     }
//
//     #[test]
//     fn disallows_invalid_authority_set() {
//         run_test(|| {
//             let genesis = test_header(0);
//
//             let invalid_authority_list = vec![(ALICE.into(), u64::MAX), (BOB.into(), u64::MAX)];
//             let init_data = InitializationData {
//                 header: Box::new(genesis),
//                 authority_list: invalid_authority_list,
//                 set_id: 1,
//                 is_halted: false,
//             };
//
//             assert_ok!(Pallet::<TestRuntime>::initialize(Origin::root(), init_data));
//
//             let header = test_header(1);
//             let justification = make_default_justification(&header);
//
//             assert_err!(
//                 Pallet::<TestRuntime>::submit_finality_proof(
//                     Origin::signed(1),
//                     Box::new(header),
//                     justification,
//                 ),
//                 <Error<TestRuntime>>::InvalidAuthoritySet
//             );
//         })
//     }
//
//     #[test]
//     fn importing_header_ensures_that_chain_is_extended() {
//         run_test(|| {
//             initialize_substrate_bridge();
//
//             assert_ok!(submit_finality_proof(4));
//             assert_err!(submit_finality_proof(3), Error::<TestRuntime>::OldHeader);
//             assert_ok!(submit_finality_proof(5));
//         })
//     }
//
//     #[test]
//     fn importing_header_enacts_new_authority_set() {
//         run_test(|| {
//             initialize_substrate_bridge();
//
//             let next_set_id = 2;
//             let next_authorities = vec![(ALICE.into(), 1), (BOB.into(), 1)];
//
//             // Need to update the header digest to indicate that our header signals an authority set
//             // change. The change will be enacted when we import our header.
//             let mut header = test_header(2);
//             header.digest = change_log(0);
//
//             // Create a valid justification for the header
//             let justification = make_default_justification(&header);
//
//             // Let's import our test header
//             assert_ok!(
//                 Pallet::<TestRuntime>::submit_finality_proof(
//                     Origin::signed(1),
//                     Box::new(header.clone()),
//                     justification
//                 ),
//                 PostDispatchInfo {
//                     actual_weight: None,
//                     pays_fee: frame_support::weights::Pays::No,
//                 },
//             );
//
//             // Make sure that our header is the best finalized
//             assert_eq!(<BestFinalized<TestRuntime>>::get(), header.hash());
//             assert!(<ImportedHeaders<TestRuntime>>::contains_key(header.hash()));
//
//             // Make sure that the authority set actually changed upon importing our header
//             assert_eq!(
//                 <CurrentAuthoritySet<TestRuntime>>::get(),
//                 bp_header_chain::AuthoritySet::new(next_authorities, next_set_id),
//             );
//         })
//     }
//
//     #[test]
//     fn importing_header_rejects_header_with_scheduled_change_delay() {
//         run_test(|| {
//             initialize_substrate_bridge();
//
//             // Need to update the header digest to indicate that our header signals an authority set
//             // change. However, the change doesn't happen until the next block.
//             let mut header = test_header(2);
//             header.digest = change_log(1);
//
//             // Create a valid justification for the header
//             let justification = make_default_justification(&header);
//
//             // Should not be allowed to import this header
//             assert_err!(
//                 Pallet::<TestRuntime>::submit_finality_proof(
//                     Origin::signed(1),
//                     Box::new(header),
//                     justification
//                 ),
//                 <Error<TestRuntime>>::UnsupportedScheduledChange
//             );
//         })
//     }
//
//     #[test]
//     fn importing_header_rejects_header_with_forced_changes() {
//         run_test(|| {
//             initialize_substrate_bridge();
//
//             // Need to update the header digest to indicate that it signals a forced authority set
//             // change.
//             let mut header = test_header(2);
//             header.digest = forced_change_log(0);
//
//             // Create a valid justification for the header
//             let justification = make_default_justification(&header);
//
//             // Should not be allowed to import this header
//             assert_err!(
//                 Pallet::<TestRuntime>::submit_finality_proof(
//                     Origin::signed(1),
//                     Box::new(header),
//                     justification
//                 ),
//                 <Error<TestRuntime>>::UnsupportedScheduledChange
//             );
//         })
//     }
//
//     #[test]
//     fn parse_finalized_storage_proof_rejects_proof_on_unknown_header() {
//         run_test(|| {
//             assert_noop!(
//                 Pallet::<TestRuntime>::parse_finalized_storage_proof(
//                     Default::default(),
//                     sp_trie::StorageProof::new(vec![]),
//                     |_| (),
//                 ),
//                 Error::<TestRuntime>::UnknownHeader,
//             );
//         });
//     }
//
//     #[test]
//     fn parse_finalized_storage_accepts_valid_proof() {
//         run_test(|| {
//             let (state_root, storage_proof) = bp_runtime::craft_valid_storage_proof();
//
//             let mut header = test_header(2);
//             header.set_state_root(state_root);
//
//             let hash = header.hash();
//             <BestFinalized<TestRuntime>>::put(hash);
//             <ImportedHeaders<TestRuntime>>::insert(hash, header);
//
//             assert_ok!(
//                 Pallet::<TestRuntime>::parse_finalized_storage_proof(hash, storage_proof, |_| (),),
//                 (),
//             );
//         });
//     }
//
//     #[test]
//     fn rate_limiter_disallows_imports_once_limit_is_hit_in_single_block() {
//         run_test(|| {
//             initialize_substrate_bridge();
//
//             assert_ok!(submit_finality_proof(1));
//             assert_ok!(submit_finality_proof(2));
//             assert_err!(
//                 submit_finality_proof(3),
//                 <Error<TestRuntime>>::TooManyRequests
//             );
//         })
//     }
//
//     #[test]
//     fn rate_limiter_invalid_requests_do_not_count_towards_request_count() {
//         run_test(|| {
//             let submit_invalid_request = || {
//                 let header = test_header(1);
//                 let mut invalid_justification = make_default_justification(&header);
//                 invalid_justification.round = 42;
//
//                 Pallet::<TestRuntime>::submit_finality_proof(
//                     Origin::signed(1),
//                     Box::new(header),
//                     invalid_justification,
//                 )
//             };
//
//             initialize_substrate_bridge();
//
//             for _ in 0..<TestRuntime as Config>::MaxRequests::get() + 1 {
//                 // Notice that the error here *isn't* `TooManyRequests`
//                 assert_err!(
//                     submit_invalid_request(),
//                     <Error<TestRuntime>>::InvalidJustification
//                 );
//             }
//
//             // Can still submit `MaxRequests` requests afterwards
//             assert_ok!(submit_finality_proof(1));
//             assert_ok!(submit_finality_proof(2));
//             assert_err!(
//                 submit_finality_proof(3),
//                 <Error<TestRuntime>>::TooManyRequests
//             );
//         })
//     }
//
//     #[test]
//     fn rate_limiter_allows_request_after_new_block_has_started() {
//         run_test(|| {
//             initialize_substrate_bridge();
//             assert_ok!(submit_finality_proof(1));
//             assert_ok!(submit_finality_proof(2));
//
//             next_block();
//             assert_ok!(submit_finality_proof(3));
//         })
//     }
//
//     #[test]
//     fn rate_limiter_disallows_imports_once_limit_is_hit_across_different_blocks() {
//         run_test(|| {
//             initialize_substrate_bridge();
//             assert_ok!(submit_finality_proof(1));
//             assert_ok!(submit_finality_proof(2));
//
//             next_block();
//             assert_ok!(submit_finality_proof(3));
//             assert_err!(
//                 submit_finality_proof(4),
//                 <Error<TestRuntime>>::TooManyRequests
//             );
//         })
//     }
//
//     #[test]
//     fn rate_limiter_allows_max_requests_after_long_time_with_no_activity() {
//         run_test(|| {
//             initialize_substrate_bridge();
//             assert_ok!(submit_finality_proof(1));
//             assert_ok!(submit_finality_proof(2));
//
//             next_block();
//             next_block();
//
//             next_block();
//             assert_ok!(submit_finality_proof(5));
//             assert_ok!(submit_finality_proof(7));
//         })
//     }
//
//     #[test]
//     fn should_prune_headers_over_headers_to_keep_parameter() {
//         run_test(|| {
//             initialize_substrate_bridge();
//             assert_ok!(submit_finality_proof(1));
//             let first_header = Pallet::<TestRuntime>::best_finalized();
//             next_block();
//
//             assert_ok!(submit_finality_proof(2));
//             next_block();
//             assert_ok!(submit_finality_proof(3));
//             next_block();
//             assert_ok!(submit_finality_proof(4));
//             next_block();
//             assert_ok!(submit_finality_proof(5));
//             next_block();
//
//             assert_ok!(submit_finality_proof(6));
//
//             assert!(
//                 !Pallet::<TestRuntime>::is_known_header(first_header.hash()),
//                 "First header should be pruned."
//             );
//         })
//     }
//
//     #[test]
//     fn storage_keys_computed_properly() {
//         assert_eq!(
//             IsHalted::<TestRuntime>::storage_value_final_key().to_vec(),
//             bp_header_chain::storage_keys::is_halted_key("Grandpa").0,
//         );
//
//         assert_eq!(
//             BestFinalized::<TestRuntime>::storage_value_final_key().to_vec(),
//             bp_header_chain::storage_keys::best_finalized_hash_key("Grandpa").0,
//         );
//     }
// }
