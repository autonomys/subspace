#![cfg_attr(not(feature = "std"), no_std)]
use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
use frame_system::pallet_prelude::*;
pub use pallet::*;
use scale_info::TypeInfo;
use sp_std::vec::Vec;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    #[pallet::config]
    pub trait Config: frame_system::Config {
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    pub type PutDataObject = Vec<u8>;
    pub type FeedId = u64;
    pub type ObjectMetadata = Vec<u8>;

    #[derive(Decode, Encode, TypeInfo, Default)]
    pub struct TotalObjectsAndSize {
        pub size: u64,
        pub objects: u64,
    }

    #[pallet::storage]
    pub type Feeds<T: Config> =
        StorageMap<_, Blake2_128Concat, FeedId, ObjectMetadata, OptionQuery>;

    #[pallet::storage]
    pub type Totals<T: Config> =
        StorageMap<_, Blake2_128Concat, FeedId, TotalObjectsAndSize, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn current_feed_id)]
    pub type CurrentFeedId<T: Config> = StorageValue<_, FeedId, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// New object is added \[object_metadata, account_id, object_size\]
        DataSubmitted(ObjectMetadata, T::AccountId, u64),
        /// New feed is created \[feed_id, account_id\]
        FeedCreated(FeedId, T::AccountId),
    }

    #[pallet::error]
    pub enum Error<T> {
        UknownFeedId,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // TODO: add proper weights
        #[pallet::weight(10_000)]
        pub fn put(
            origin: OriginFor<T>,
            feed_id: FeedId,
            data: PutDataObject,
            metadata: ObjectMetadata,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let object_size = data.len() as u64;

            log::debug!("metadata: {:?}", metadata);
            log::debug!("object_size: {:?}", object_size);

            let current_feed_id = Self::current_feed_id();

            ensure!(current_feed_id >= feed_id, Error::<T>::UknownFeedId);

            Feeds::<T>::insert(feed_id, metadata.clone());

            Totals::<T>::mutate(feed_id, |feed_totals| {
                feed_totals.size += object_size;
                feed_totals.objects += 1;
            });

            Self::deposit_event(Event::DataSubmitted(metadata, who, object_size));

            Ok(())
        }

        // TODO: add proper weights
        #[pallet::weight(10_000)]
        pub fn create(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let feed_id = Self::current_feed_id();

            CurrentFeedId::<T>::mutate(|feed_id| *feed_id = feed_id.saturating_add(1));

            Totals::<T>::insert(feed_id, TotalObjectsAndSize::default());

            Self::deposit_event(Event::FeedCreated(feed_id, who));

            Ok(())
        }
    }
}
