// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
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

//! # Offences Subspace Pallet
//!
//! Tracks reported offences

// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

mod mock;
mod tests;

use codec::{Decode, Encode};
pub use pallet::*;
use sp_consensus_subspace::offence::{
    Offence, OffenceDetails, OffenceError, OnOffenceHandler, ReportOffence,
};
use sp_runtime::traits::Hash;
use sp_std::prelude::*;
use subspace_core_primitives::PublicKey;

/// A binary blob which represents a SCALE codec-encoded `O::TimeSlot`.
type OpaqueTimeSlot = Vec<u8>;

/// A type alias for a report identifier.
type ReportIdOf<T> = <T as frame_system::Config>::Hash;

#[frame_support::pallet]
mod pallet {
    use super::{OpaqueTimeSlot, ReportIdOf};
    use frame_support::pallet_prelude::*;
    use sp_consensus_subspace::offence::{Kind, OffenceDetails, OnOffenceHandler};
    use sp_std::prelude::*;
    use subspace_core_primitives::PublicKey;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// The pallet's config trait.
    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// A handler called for every offence report.
        type OnOffenceHandler: OnOffenceHandler<PublicKey>;
    }

    /// The primary structure that holds all offence records keyed by report identifiers.
    #[pallet::storage]
    #[pallet::getter(fn reports)]
    pub type Reports<T: Config> =
        StorageMap<_, Twox64Concat, ReportIdOf<T>, OffenceDetails<PublicKey>>;

    /// A vector of reports of the same kind that happened at the same time slot.
    #[pallet::storage]
    pub type ConcurrentReportsIndex<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        Kind,
        Twox64Concat,
        OpaqueTimeSlot,
        Vec<ReportIdOf<T>>,
        ValueQuery,
    >;

    /// Enumerates all reports of a kind along with the time they happened.
    ///
    /// All reports are sorted by the time of offence.
    ///
    /// Note that the actual type of this mapping is `Vec<u8>`, this is because values of
    /// different types are not supported at the moment so we are doing the manual serialization.
    #[pallet::storage]
    pub type ReportsByKindIndex<T> = StorageMap<
        _,
        Twox64Concat,
        Kind,
        Vec<u8>, // (O::TimeSlot, ReportIdOf<T>)
        ValueQuery,
    >;

    /// Events type.
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event {
        /// There is an offence reported of the given `kind` happened at the `session_index` and
        /// (kind-specific) time slot. This event is not deposited for duplicate slashes.
        /// \[kind, timeslot\].
        Offence {
            kind: Kind,
            timeslot: OpaqueTimeSlot,
        },
    }
}

impl<T: Config, O: Offence<PublicKey>> ReportOffence<PublicKey, O> for Pallet<T> {
    fn report_offence(offence: O) -> Result<(), OffenceError> {
        let offenders = offence.offenders();
        let time_slot = offence.time_slot();

        // Go through all offenders in the offence report and find all offenders that were spotted
        // in unique reports.
        let TriageOutcome {
            concurrent_offenders,
        } = match Self::triage_offence_report::<O>(&time_slot, offenders) {
            Some(triage) => triage,
            // The report contained only duplicates, so there is no need to slash again.
            None => return Err(OffenceError::DuplicateReport),
        };

        T::OnOffenceHandler::on_offence(&concurrent_offenders);

        // Deposit the event.
        Self::deposit_event(Event::Offence {
            kind: O::ID,
            timeslot: time_slot.encode(),
        });

        Ok(())
    }

    fn is_known_offence(offenders: &[PublicKey], time_slot: &O::TimeSlot) -> bool {
        let any_unknown = offenders.iter().any(|offender| {
            let report_id = Self::report_id::<O>(time_slot, offender);
            !<Reports<T>>::contains_key(report_id)
        });

        !any_unknown
    }
}

impl<T: Config> Pallet<T> {
    /// Compute the ID for the given report properties.
    ///
    /// The report id depends on the offence kind, time slot and the id of offender.
    fn report_id<O: Offence<PublicKey>>(
        time_slot: &O::TimeSlot,
        offender: &PublicKey,
    ) -> ReportIdOf<T> {
        (O::ID, time_slot.encode(), offender).using_encoded(T::Hashing::hash)
    }

    /// Triages the offence report and returns the set of offenders that was involved in unique
    /// reports along with the list of the concurrent offences.
    fn triage_offence_report<O: Offence<PublicKey>>(
        time_slot: &O::TimeSlot,
        offenders: Vec<PublicKey>,
    ) -> Option<TriageOutcome> {
        let mut storage = ReportIndexStorage::<T, O>::load(time_slot);

        let mut any_new = false;
        for offender in offenders {
            let report_id = Self::report_id::<O>(time_slot, &offender);

            if !<Reports<T>>::contains_key(report_id) {
                any_new = true;
                <Reports<T>>::insert(report_id, OffenceDetails { offender });

                storage.insert(time_slot, report_id);
            }
        }

        if any_new {
            // Load report details for the all reports happened at the same time.
            let concurrent_offenders = storage
                .concurrent_reports
                .iter()
                .filter_map(<Reports<T>>::get)
                .collect::<Vec<_>>();

            storage.save();

            Some(TriageOutcome {
                concurrent_offenders,
            })
        } else {
            None
        }
    }
}

struct TriageOutcome {
    /// Other reports for the same report kinds.
    concurrent_offenders: Vec<OffenceDetails<PublicKey>>,
}

/// An auxiliary struct for working with storage of indexes localized for a specific offence
/// kind (specified by the `O` type parameter).
///
/// This struct is responsible for aggregating storage writes and the underlying storage should not
/// accessed directly meanwhile.
#[must_use = "The changes are not saved without called `save`"]
struct ReportIndexStorage<T: Config, O: Offence<PublicKey>> {
    opaque_time_slot: OpaqueTimeSlot,
    concurrent_reports: Vec<ReportIdOf<T>>,
    same_kind_reports: Vec<(O::TimeSlot, ReportIdOf<T>)>,
}

impl<T: Config, O: Offence<PublicKey>> ReportIndexStorage<T, O> {
    /// Preload indexes from the storage for the specific `time_slot` and the kind of the offence.
    fn load(time_slot: &O::TimeSlot) -> Self {
        let opaque_time_slot = time_slot.encode();

        let same_kind_reports = ReportsByKindIndex::<T>::get(O::ID);
        let same_kind_reports =
            Vec::<(O::TimeSlot, ReportIdOf<T>)>::decode(&mut &same_kind_reports[..])
                .unwrap_or_default();

        let concurrent_reports = <ConcurrentReportsIndex<T>>::get(O::ID, &opaque_time_slot);

        Self {
            opaque_time_slot,
            concurrent_reports,
            same_kind_reports,
        }
    }

    /// Insert a new report to the index.
    fn insert(&mut self, time_slot: &O::TimeSlot, report_id: ReportIdOf<T>) {
        // Insert the report id into the list while maintaining the ordering by the time
        // slot.
        let pos = self
            .same_kind_reports
            .partition_point(|(when, _)| when <= time_slot);
        self.same_kind_reports
            .insert(pos, (time_slot.clone(), report_id));

        // Update the list of concurrent reports.
        self.concurrent_reports.push(report_id);
    }

    /// Dump the indexes to the storage.
    fn save(self) {
        ReportsByKindIndex::<T>::insert(O::ID, self.same_kind_reports.encode());
        <ConcurrentReportsIndex<T>>::insert(
            O::ID,
            &self.opaque_time_slot,
            &self.concurrent_reports,
        );
    }
}
