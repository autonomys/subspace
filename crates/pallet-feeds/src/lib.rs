#![cfg_attr(not(feature = "std"), no_std)]
use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
use frame_system::pallet_prelude::*;
pub use pallet::*;
use scale_info::TypeInfo;
use sp_core::H256;
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

    // TODO: make it more generic
    #[derive(Encode, Decode, Debug, Clone, Eq, PartialEq, TypeInfo)]
    pub struct ObjectMetadata {
        pub feed_id: FeedId,
        // last block hash
        pub hash: H256,
        // last block number
        pub number: u32,
    }

    #[pallet::storage]
    pub type Feeds<T: Config> = StorageMap<_, Blake2_128Concat, FeedId, (H256, u32), OptionQuery>;

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

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // TODO: add proper weights
        #[pallet::weight(10_000)]
        pub fn put(
            origin: OriginFor<T>,
            data: PutDataObject,
            metadata: ObjectMetadata,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            log::info!("metadata: {:?}", metadata);

            let ObjectMetadata {
                feed_id,
                hash,
                number,
            } = metadata;

            ensure!(Feeds::<T>::contains_key(feed_id), Error::<T>::UknownFeedId);

            Feeds::<T>::mutate_exists(feed_id, |values| *values = Some((hash, number)));

            // TODO: add data handling
            log::info!("data.len: {:?}", data.len());

            Self::deposit_event(Event::DataSubmitted(metadata, who));

            Ok(())
        }

        // TODO: add proper weights
        #[pallet::weight(10_000)]
        pub fn create(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let feed_id = Self::current_feed_id();

            Feeds::<T>::insert(feed_id, (H256::default(), u32::default()));

            CurrentFeedId::<T>::mutate(|feed_id| *feed_id = feed_id.saturating_add(1));

            Self::deposit_event(Event::FeedCreated(feed_id, who));

            Ok(())
        }
    }
}
