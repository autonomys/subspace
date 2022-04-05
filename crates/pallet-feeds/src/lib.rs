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

//! Pallet feeds, used for storing arbitrary user-provided data combined into feeds.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

use crate::feed_processor::FeedObjectMapping;
use core::mem;
pub use pallet::*;

pub mod feed_processor;
#[cfg(all(feature = "std", test))]
mod mock;
#[cfg(all(feature = "std", test))]
mod tests;

#[frame_support::pallet]
mod pallet {
    use crate::feed_processor::{FeedMetadata, FeedProcessor as FeedProcessorT, FeedProcessorId};
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::{CheckedAdd, One};
    use sp_runtime::ArithmeticError;
    use sp_std::prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// `pallet-feeds` events
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        // Feed ID uniquely identifies a Feed
        type FeedId: Parameter
            + Member
            + MaybeSerializeDeserialize
            + Default
            + Copy
            + One
            + CheckedAdd
            + PartialOrd;

        fn feed_processor(
            feed_processor_id: FeedProcessorId,
        ) -> Box<dyn FeedProcessorT<Self::FeedId>>;
    }

    /// Pallet feeds, used for storing arbitrary user-provided data combined into feeds.
    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// User-provided object to store
    pub(super) type Object = Vec<u8>;
    /// User provided initial data for validation
    pub(super) type InitialValidation = Vec<u8>;

    /// Total amount of data and number of objects stored in a feed
    #[derive(Debug, Decode, Encode, TypeInfo, Default, PartialEq, Eq)]
    pub struct TotalObjectsAndSize {
        /// Total size of objects in bytes
        pub size: u64,
        /// Total number of objects
        pub count: u64,
    }

    #[pallet::storage]
    #[pallet::getter(fn metadata)]
    pub(super) type Metadata<T: Config> =
        StorageMap<_, Blake2_128Concat, T::FeedId, FeedMetadata, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn feed_processor)]
    pub(super) type FeedProcessor<T: Config> =
        StorageMap<_, Blake2_128Concat, T::FeedId, FeedProcessorId, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn totals)]
    pub(super) type Totals<T: Config> =
        StorageMap<_, Blake2_128Concat, T::FeedId, TotalObjectsAndSize, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn current_feed_id)]
    pub(super) type CurrentFeedId<T: Config> = StorageValue<_, T::FeedId, ValueQuery>;

    /// `pallet-feeds` events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// New object was added.
        ObjectSubmitted {
            metadata: FeedMetadata,
            who: T::AccountId,
            object_size: u64,
        },
        /// New feed was created.
        FeedCreated {
            feed_id: T::FeedId,
            who: T::AccountId,
        },
    }

    /// `pallet-feeds` errors
    #[pallet::error]
    pub enum Error<T> {
        /// `FeedId` doesn't exist
        UnknownFeedId,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // TODO: add proper weights
        /// Create a new feed
        #[pallet::weight(10_000)]
        pub fn create(
            origin: OriginFor<T>,
            feed_processor_id: FeedProcessorId,
            initial_validation: Option<InitialValidation>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let feed_id = Self::current_feed_id();
            let next_feed_id = feed_id
                .checked_add(&T::FeedId::one())
                .ok_or(ArithmeticError::Overflow)?;

            let feed_processor = T::feed_processor(feed_processor_id);
            if let Some(init_data) = initial_validation {
                feed_processor.init(feed_id, init_data.as_slice())?;
            }

            CurrentFeedId::<T>::mutate(|feed_id| *feed_id = next_feed_id);
            FeedProcessor::<T>::insert(feed_id, feed_processor_id);
            Totals::<T>::insert(feed_id, TotalObjectsAndSize::default());

            Self::deposit_event(Event::FeedCreated { feed_id, who });

            Ok(())
        }

        // TODO: add proper weights
        // TODO: For now we don't have fees, but we will have them in the future
        /// Put a new object into a feed
        #[pallet::weight((10_000, Pays::No))]
        pub fn put(origin: OriginFor<T>, feed_id: T::FeedId, object: Object) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // ensure feed_id is valid
            ensure!(
                Self::current_feed_id() >= feed_id,
                Error::<T>::UnknownFeedId
            );

            let object_size = object.len() as u64;
            let feed_processor_id = FeedProcessor::<T>::get(feed_id);
            let feed_processor = T::feed_processor(feed_processor_id);

            let metadata = feed_processor
                .put(feed_id, object.as_slice())?
                .unwrap_or_default();
            Metadata::<T>::insert(feed_id, metadata.clone());

            Totals::<T>::mutate(feed_id, |feed_totals| {
                feed_totals.size += object_size;
                feed_totals.count += 1;
            });

            Self::deposit_event(Event::ObjectSubmitted {
                metadata,
                who,
                object_size,
            });

            Ok(())
        }
    }
}

impl<T: Config> Call<T> {
    /// Extract the call object if an extrinsic corresponds to `put` call
    pub fn extract_call_objects(&self) -> Vec<FeedObjectMapping> {
        match self {
            Self::put { feed_id, object } => {
                let feed_processor_id = FeedProcessor::<T>::get(feed_id);
                let feed_processor = T::feed_processor(feed_processor_id);
                let mut objects_mappings = feed_processor.object_mappings(*feed_id, object);
                // `FeedId` is the first field in the extrinsic. `1+` corresponds to `Call::put {}`
                // enum variant encoding.
                objects_mappings.iter_mut().for_each(|object_mapping| {
                    object_mapping.offset += 1 + mem::size_of::<T::FeedId>() as u32
                });
                objects_mappings
            }
            _ => Default::default(),
        }
    }
}
