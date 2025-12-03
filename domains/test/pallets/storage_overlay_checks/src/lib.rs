//! Test pallet to check the overlay changes during the block execution and post block execution.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

use frame_system::pallet_prelude::BlockNumberFor;
pub use pallet::*;
use sp_core::H256;

#[frame_support::pallet]
mod pallet {
    use crate::StorageParams;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::BlockNumberFor;
    use sp_core::H256;
    use sp_runtime::traits::Zero;

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    #[pallet::storage]
    pub(super) type Svvq<T> = StorageValue<_, H256, ValueQuery>;

    #[pallet::storage]
    pub(super) type Svoq<T> = StorageValue<_, H256, OptionQuery>;

    #[pallet::storage]
    pub(super) type Smvq<T> = StorageMap<_, Identity, H256, H256, ValueQuery>;

    #[pallet::storage]
    pub(super) type Smoq<T> = StorageMap<_, Identity, H256, H256, OptionQuery>;

    #[pallet::storage]
    pub(super) type Sdmvq<T> =
        StorageDoubleMap<_, Identity, H256, Identity, H256, H256, ValueQuery>;

    #[pallet::storage]
    pub(super) type Sdmoq<T> =
        StorageDoubleMap<_, Identity, H256, Identity, H256, H256, OptionQuery>;

    #[pallet::storage]
    pub(super) type Snmvq<T> = StorageNMap<
        _,
        (
            NMapKey<Identity, H256>,
            NMapKey<Identity, H256>,
            NMapKey<Identity, H256>,
        ),
        H256,
        ValueQuery,
    >;

    #[pallet::storage]
    pub(super) type Snmoq<T> = StorageNMap<
        _,
        (
            NMapKey<Identity, H256>,
            NMapKey<Identity, H256>,
            NMapKey<Identity, H256>,
        ),
        H256,
        OptionQuery,
    >;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(n: BlockNumberFor<T>) -> Weight {
            // even blocks, storages must be set already and are emptied
            // odd block, storages must be empty and are set
            let params = StorageParams::default();
            if n % BlockNumberFor::<T>::from(2u32) == Zero::zero() {
                Pallet::<T>::check_storage_exists(n, params);
                Pallet::<T>::clear_storage(n);
            } else {
                Pallet::<T>::check_storage_empty(n, params);
                Pallet::<T>::set_storage(n, params);
            }

            Weight::zero()
        }

        fn on_finalize(n: BlockNumberFor<T>) {
            // even blocks, storages must be emptied during initialize
            // odd block, storages must be set during initialize
            let params = StorageParams::default();
            if n % BlockNumberFor::<T>::from(2u32) == Zero::zero() {
                Pallet::<T>::check_storage_empty(n, params);
            } else {
                Pallet::<T>::check_storage_exists(n, params);
            }
        }
    }
}

#[derive(Clone, Copy)]
struct StorageParams {
    key1: H256,
    key2: H256,
    key3: H256,
    value: H256,
}

impl Default for StorageParams {
    fn default() -> Self {
        Self {
            key1: H256::repeat_byte(1),
            key2: H256::repeat_byte(2),
            key3: H256::repeat_byte(3),
            value: H256::repeat_byte(4),
        }
    }
}

impl<T: Config> Pallet<T> {
    fn set_storage(n: BlockNumberFor<T>, params: StorageParams) {
        log::debug!("Setting storages at: {n:?}");
        let StorageParams {
            key1,
            key2,
            key3,
            value,
        } = params;

        Svvq::<T>::set(value);
        Svoq::<T>::set(Some(value));
        Smvq::<T>::set(key1, value);
        Smoq::<T>::set(key1, Some(value));
        Sdmvq::<T>::set(key1, key2, value);
        Sdmoq::<T>::set(key1, key2, Some(value));
        Snmvq::<T>::set((key1, key2, key3), value);
        Snmoq::<T>::set((key1, key2, key3), Some(value));
    }

    fn clear_storage(n: BlockNumberFor<T>) {
        log::debug!("Clearing storages at: {n:?}");
        Svvq::<T>::kill();
        Svoq::<T>::kill();
        let _ = Smvq::<T>::clear(u32::MAX, None);
        let _ = Smoq::<T>::clear(u32::MAX, None);
        let _ = Sdmvq::<T>::clear(u32::MAX, None);
        let _ = Sdmoq::<T>::clear(u32::MAX, None);
        let _ = Snmvq::<T>::clear(u32::MAX, None);
        let _ = Snmoq::<T>::clear(u32::MAX, None);
    }

    fn check_storage_exists(n: BlockNumberFor<T>, params: StorageParams) {
        log::debug!("Checking storages exists at: {n:?}");
        let StorageParams {
            key1,
            key2,
            key3,
            value,
        } = params;

        assert_eq!(Svvq::<T>::get(), value);
        assert_eq!(Svoq::<T>::get(), Some(value));
        assert_eq!(Smvq::<T>::get(key1), value);
        assert_eq!(Smoq::<T>::get(key1), Some(value));
        assert_eq!(Sdmvq::<T>::get(key1, key2), value);
        assert_eq!(Sdmoq::<T>::get(key1, key2), Some(value));
        assert_eq!(Snmvq::<T>::get((key1, key2, key3)), value);
        assert_eq!(Snmoq::<T>::get((key1, key2, key3)), Some(value));
    }

    fn check_storage_empty(n: BlockNumberFor<T>, params: StorageParams) {
        log::debug!("Checking storages empty at: {n:?}");
        let StorageParams {
            key1,
            key2,
            key3,
            value: _,
        } = params;

        assert!(!Svvq::<T>::exists());

        assert!(!Svoq::<T>::exists());
        assert_eq!(Svoq::<T>::get(), None);

        assert!(!Smvq::<T>::contains_key(key1));

        assert!(!Smoq::<T>::contains_key(key1));
        assert_eq!(Smoq::<T>::get(key1), None);

        assert!(!Sdmvq::<T>::contains_key(key1, key2));

        assert!(!Sdmoq::<T>::contains_key(key1, key2));
        assert_eq!(Sdmoq::<T>::get(key1, key2), None);

        assert!(!Snmvq::<T>::contains_key((key1, key2, key3)));

        assert!(!Snmoq::<T>::contains_key((key1, key2, key3)));
        assert_eq!(Snmoq::<T>::get((key1, key2, key3)), None);
    }
}
