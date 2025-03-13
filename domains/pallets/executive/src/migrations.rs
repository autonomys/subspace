//! Runtime storage migrations for pallet-executive and system pallets.

use event_segments_migration::EventSegments;
use frame_support::traits::{Get, OnRuntimeUpgrade};
use frame_support::weights::Weight;
use frame_system::pallet::Config;
use frame_system::{EventRecord, Pallet as System};
#[cfg(not(feature = "std"))]
use sp_std::vec::Vec;

pub struct StorageCheckedMigrateToEventSegments<T>(sp_std::marker::PhantomData<T>);

impl<T: Config> OnRuntimeUpgrade for StorageCheckedMigrateToEventSegments<T> {
    fn on_runtime_upgrade() -> Weight {
        // The system pallet doesn't have storage versions, so we need to check if we were previously using Events storage instead.
        // The migrations run after the upgraded System::reset_events() runs on the old storage format, which leads to an inconsistency:
        // - the storage claims there are uncleared events, because it was set to the old event count, but
        // - the event segments storage is empty.
        //
        // This migration is safe to run on any upgrade, because:
        // - if event segments are disabled (or there are no uncleared events for any other reason), it will do nothing;
        // - if event segments are enabled and in use, it will also do nothing.
        if System::<T>::uncleared_event_count() > 0 && EventSegments::<T>::get(0).is_none() {
            let weights = frame_system::migrations::migrate_from_events_to_event_segments::<T>();

            weights + T::DbWeight::get().reads(2)
        } else {
            // Checking if we need to migrate costs up to 2 reads
            T::DbWeight::get().reads(2)
        }
    }
}

pub(super) mod event_segments_migration {
    use super::{Config, EventRecord, System};
    use frame_support::pallet_prelude::{OptionQuery, ValueQuery};
    use frame_support::{storage_alias, Identity};
    #[cfg(not(feature = "std"))]
    use sp_std::boxed::Box;
    #[cfg(not(feature = "std"))]
    use sp_std::vec::Vec;
    // frame_system::EventIndex is a private type
    use core::primitive::u32 as EventIndex;

    #[storage_alias]
    pub(super) type Events<T: Config> = StorageValue<
        System<T>,
        Vec<
            Box<
                EventRecord<
                    <T as frame_system::Config>::RuntimeEvent,
                    <T as frame_system::Config>::Hash,
                >,
            >,
        >,
        ValueQuery,
    >;

    #[storage_alias]
    pub(super) type EventSegments<T: Config> = StorageMap<
        System<T>,
        Identity,
        EventIndex,
        Vec<
            Box<
                EventRecord<
                    <T as frame_system::Config>::RuntimeEvent,
                    <T as frame_system::Config>::Hash,
                >,
            >,
        >,
        OptionQuery,
    >;

    #[storage_alias]
    pub(super) type UnclearedEventCount<T: Config> =
        StorageValue<System<T>, EventIndex, ValueQuery>;
}

#[cfg(test)]
mod tests {
    use super::event_segments_migration::{Events, UnclearedEventCount};
    use super::*;
    use crate::mock::{new_test_ext, MockRuntime, RuntimeEvent};
    use frame_support::weights::RuntimeDbWeight;

    #[test]
    fn test_system_event_segments_storage_migration() {
        let event = Box::new(EventRecord {
            phase: Default::default(),
            event: RuntimeEvent::System(frame_system::Event::CodeUpdated),
            topics: Default::default(),
        });

        // Migration needed: "uncleared" events, but no event segments
        let mut ext = new_test_ext();
        ext.execute_with(|| {
            UnclearedEventCount::<MockRuntime>::put(1);
        });
        ext.commit_all().unwrap();
        ext.execute_with(|| {
            let weights = StorageCheckedMigrateToEventSegments::<MockRuntime>::on_runtime_upgrade();

            // 2 reads and 2 writes: check then clear Events and UnclearedEventCount
            let db_weights: RuntimeDbWeight =
                <MockRuntime as frame_system::Config>::DbWeight::get();
            assert_eq!(weights, db_weights.reads_writes(2, 2));

            assert_eq!(Events::<MockRuntime>::get(), Vec::new());
            assert_eq!(EventSegments::<MockRuntime>::get(0), None);
            assert_eq!(UnclearedEventCount::<MockRuntime>::get(), 0);
        });

        // Migration not needed: no "uncleared" events (and no event segments)
        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let weights = StorageCheckedMigrateToEventSegments::<MockRuntime>::on_runtime_upgrade();

            // 2 reads: check Events and UnclearedEventCount
            let db_weights: RuntimeDbWeight =
                <MockRuntime as frame_system::Config>::DbWeight::get();
            assert_eq!(weights, db_weights.reads_writes(2, 0));

            assert_eq!(Events::<MockRuntime>::get(), Vec::new());
            assert_eq!(EventSegments::<MockRuntime>::get(0), None);
            assert_eq!(UnclearedEventCount::<MockRuntime>::get(), 0);
        });

        // Migration not needed: event segments already in use (and uncleared events)
        let mut ext = new_test_ext();
        ext.execute_with(|| {
            EventSegments::<MockRuntime>::set(0, Some(vec![event.clone()]));
            UnclearedEventCount::<MockRuntime>::put(1);
        });
        ext.commit_all().unwrap();
        ext.execute_with(|| {
            let weights = StorageCheckedMigrateToEventSegments::<MockRuntime>::on_runtime_upgrade();

            // 2 reads: check Events and UnclearedEventCount
            let db_weights: RuntimeDbWeight =
                <MockRuntime as frame_system::Config>::DbWeight::get();
            assert_eq!(weights, db_weights.reads_writes(2, 0));

            assert_eq!(Events::<MockRuntime>::get(), Vec::new());
            assert_eq!(
                EventSegments::<MockRuntime>::get(0),
                Some(vec![event.clone()])
            );
            assert_eq!(UnclearedEventCount::<MockRuntime>::get(), 1);
        });

        // Migration not needed: event segments already in use (and no uncleared events)
        let mut ext = new_test_ext();
        ext.execute_with(|| {
            EventSegments::<MockRuntime>::set(0, Some(vec![event.clone()]));
        });
        ext.commit_all().unwrap();
        ext.execute_with(|| {
            let weights = StorageCheckedMigrateToEventSegments::<MockRuntime>::on_runtime_upgrade();

            // 2 reads: check Events and UnclearedEventCount
            let db_weights: RuntimeDbWeight =
                <MockRuntime as frame_system::Config>::DbWeight::get();
            assert_eq!(weights, db_weights.reads_writes(2, 0));

            assert_eq!(Events::<MockRuntime>::get(), Vec::new());
            assert_eq!(EventSegments::<MockRuntime>::get(0), Some(vec![event]));
            assert_eq!(UnclearedEventCount::<MockRuntime>::get(), 0);
        });
    }
}
