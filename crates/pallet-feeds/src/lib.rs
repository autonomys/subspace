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

use crate::feed_processor::FeedObjectMapping;
use core::mem;
pub use pallet::*;
use sp_std::{vec, vec::Vec};

pub mod feed_processor;
#[cfg(all(feature = "std", test))]
mod mock;
#[cfg(all(feature = "std", test))]
mod tests;

#[frame_support::pallet]
mod pallet {
    use crate::feed_processor::{FeedMetadata, FeedProcessor as FeedProcessorT};
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_std::prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// `pallet-feeds` events
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        // Feed ID uniquely identifies a Feed
        type FeedId: Parameter + Member + Default + Copy + PartialOrd;

        // type that represents a feed processor id
        type FeedProcessorId: Parameter + Member + Default + Copy;

        fn feed_processor(
            feed_processor_id: Self::FeedProcessorId,
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
    pub(super) type InitData = Vec<u8>;

    /// Total amount of data and number of objects stored in a feed
    #[derive(Debug, Decode, Encode, TypeInfo, Default, PartialEq, Eq)]
    pub struct TotalObjectsAndSize {
        /// Total size of objects in bytes
        pub size: u64,
        /// Total number of objects
        pub count: u64,
    }

    #[derive(Debug, Decode, Encode, TypeInfo, Default)]
    pub struct FeedConfig<FeedProcessorId> {
        pub active: bool,
        pub feed_processor_id: FeedProcessorId,
    }

    #[pallet::storage]
    #[pallet::getter(fn metadata)]
    pub(super) type Metadata<T: Config> =
        StorageMap<_, Blake2_128Concat, T::FeedId, FeedMetadata, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn feed_configs)]
    pub(super) type FeedConfigs<T: Config> =
        StorageMap<_, Blake2_128Concat, T::FeedId, FeedConfig<T::FeedProcessorId>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn totals)]
    pub(super) type Totals<T: Config> =
        StorageMap<_, Blake2_128Concat, T::FeedId, TotalObjectsAndSize, ValueQuery>;

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

        /// An existing feed was updated.
        FeedUpdated {
            feed_id: T::FeedId,
            who: T::AccountId,
        },

        /// Feed is closed.
        FeedClosed {
            feed_id: T::FeedId,
            who: T::AccountId,
        },

        /// Feed is deleted.
        FeedDeleted {
            feed_id: T::FeedId,
            who: T::AccountId,
        },
    }

    /// `pallet-feeds` errors
    #[pallet::error]
    pub enum Error<T> {
        /// `FeedId` already taken
        FeedIdUnavailable,

        /// `FeedId` doesn't exist
        UnknownFeedId,

        /// Feed is closed
        FeedClosed,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // TODO: add proper weights
        /// Create a new feed
        #[pallet::weight((10_000, Pays::No))]
        pub fn create(
            origin: OriginFor<T>,
            feed_id: T::FeedId,
            feed_processor_id: T::FeedProcessorId,
            init_data: Option<InitData>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                !FeedConfigs::<T>::contains_key(feed_id),
                Error::<T>::FeedIdUnavailable
            );

            let feed_processor = T::feed_processor(feed_processor_id);
            if let Some(init_data) = init_data {
                feed_processor.init(feed_id, init_data.as_slice())?;
            }

            FeedConfigs::<T>::insert(
                feed_id,
                FeedConfig {
                    active: true,
                    feed_processor_id,
                },
            );
            Totals::<T>::insert(feed_id, TotalObjectsAndSize::default());

            Self::deposit_event(Event::FeedCreated { feed_id, who });

            Ok(())
        }

        #[pallet::weight((10_000, Pays::No))]
        pub fn update(
            origin: OriginFor<T>,
            feed_id: T::FeedId,
            feed_processor_id: T::FeedProcessorId,
            init_data: Option<InitData>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                FeedConfigs::<T>::contains_key(feed_id),
                Error::<T>::UnknownFeedId
            );

            let feed_processor = T::feed_processor(feed_processor_id);
            if let Some(init_data) = init_data {
                feed_processor.init(feed_id, init_data.as_slice())?;
            }

            FeedConfigs::<T>::insert(
                feed_id,
                FeedConfig {
                    active: true,
                    feed_processor_id,
                },
            );

            Self::deposit_event(Event::FeedUpdated { feed_id, who });

            Ok(())
        }

        // TODO: add proper weights
        // TODO: For now we don't have fees, but we will have them in the future
        /// Put a new object into a feed
        #[pallet::weight((10_000, Pays::No))]
        pub fn put(origin: OriginFor<T>, feed_id: T::FeedId, object: Object) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let feed_config = FeedConfigs::<T>::get(feed_id).ok_or(Error::<T>::UnknownFeedId)?;

            // ensure feed is active
            ensure!(feed_config.active, Error::<T>::FeedClosed);

            let object_size = object.len() as u64;
            let feed_processor = T::feed_processor(feed_config.feed_processor_id);

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

        #[pallet::weight((T::DbWeight::get().reads_writes(1, 1), Pays::No))]
        pub fn close(origin: OriginFor<T>, feed_id: T::FeedId) -> DispatchResult {
            let who = ensure_signed(origin)?;

            FeedConfigs::<T>::mutate(feed_id, |maybe_config| -> DispatchResult {
                let mut config = maybe_config.take().ok_or(Error::<T>::UnknownFeedId)?;
                config.active = false;
                *maybe_config = Some(config);
                Ok(())
            })?;
            Self::deposit_event(Event::FeedClosed { feed_id, who });
            Ok(())
        }

        #[pallet::weight((T::DbWeight::get().reads_writes(0, 3), Pays::No))]
        pub fn delete(origin: OriginFor<T>, feed_id: T::FeedId) -> DispatchResult {
            let who = ensure_signed(origin)?;

            FeedConfigs::<T>::remove(feed_id);
            Metadata::<T>::remove(feed_id);
            Totals::<T>::remove(feed_id);
            Self::deposit_event(Event::FeedDeleted { feed_id, who });
            Ok(())
        }
    }
}

impl<T: Config> Call<T> {
    /// Extract the call object if an extrinsic corresponds to `put` call
    pub fn extract_call_objects(&self) -> Vec<FeedObjectMapping> {
        match self {
            Self::put { feed_id, object } => {
                let feed_processor_id = match FeedConfigs::<T>::get(feed_id) {
                    Some(config) => config.feed_processor_id,
                    // return if this was a invalid extrinsic
                    None => return vec![],
                };
                let feed_processor = T::feed_processor(feed_processor_id);
                let mut objects_mappings = feed_processor.object_mappings(*feed_id, object);
                // `FeedId` is the first field in the extrinsic. `1+` corresponds to `Call::put {}`
                // enum variant encoding.
                objects_mappings.iter_mut().for_each(|object_mapping| {
                    // update the offset to include the absolute offset in the extrinsic
                    object_mapping.offset += 1 + mem::size_of::<T::FeedId>() as u32
                });
                objects_mappings
            }
            _ => Default::default(),
        }
    }
}
