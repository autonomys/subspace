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
    // TODO: clarify if it should be u32
    pub type ChainId = u32;

    #[pallet::event]
    #[pallet::metadata(T::AccountId = "AccountId")]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        DataSubmitted(PutDataObject, T::AccountId),
    }

    #[pallet::error]
    pub enum Error<T> {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // TODO: add proper weights
        #[pallet::weight(10_000)]
        pub fn put(origin: OriginFor<T>, data: PutDataObject, chain_id: ChainId) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // TODO: add data handling
            log::info!("CHAIN ID: {:?}", chain_id);
            log::info!("NEW DATA OBJECT: {:?}", data.len());

            // TODO: Consider removing in the future
            Self::deposit_event(Event::DataSubmitted(data, who));

            Ok(())
        }
    }
}
