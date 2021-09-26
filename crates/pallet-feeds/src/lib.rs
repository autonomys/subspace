#![cfg_attr(not(feature = "std"), no_std)]
use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
use frame_system::pallet_prelude::*;
pub use pallet::*;
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

    #[pallet::storage]
    pub type Feeds<T: Config> =
        StorageMap<_, Blake2_128Concat, FeedId, ObjectMetadata, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn current_feed_id)]
    pub type CurrentFeedId<T: Config> = StorageValue<_, FeedId, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        DataSubmitted(ObjectMetadata, T::AccountId),
        FeedCreated(FeedId, T::AccountId),
    }

    #[pallet::error]
    pub enum Error<T> {
        UknownFeedId,
    }

    // TODO: consider extracting feed_id from metadata as separate argument
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

            // TODO: add data handling
            log::debug!("metadata: {:?}", metadata);
            log::debug!("data.len: {:?}", data.len());

            let current_feed_id = Self::current_feed_id();

            ensure!(current_feed_id >= feed_id, Error::<T>::UknownFeedId);

            Feeds::<T>::insert(feed_id, metadata.clone());

            Self::deposit_event(Event::DataSubmitted(metadata, who));

            Ok(())
        }

        // TODO: add proper weights
        #[pallet::weight(10_000)]
        pub fn create(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let feed_id = Self::current_feed_id();

            CurrentFeedId::<T>::mutate(|feed_id| *feed_id = feed_id.saturating_add(1));

            Self::deposit_event(Event::FeedCreated(feed_id, who));

            Ok(())
        }
    }
}
