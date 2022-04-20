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

use core::mem;
pub use pallet::*;
use sp_std::{vec, vec::Vec};
use subspace_core_primitives::{crypto, Sha256Hash};

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
    use sp_runtime::traits::{CheckedAdd, One, StaticLookup};
    use sp_runtime::ArithmeticError;
    use sp_std::prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// `pallet-feeds` events
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        // Feed ID uniquely identifies a Feed
        type FeedId: Parameter + Member + Default + Copy + PartialOrd + CheckedAdd + One;

        // Type that references to a particular impl of feed processor
        type FeedProcessorKind: Parameter + Member + Default + Clone;

        #[pallet::constant]
        type MaxFeeds: Get<u32>;

        fn feed_processor(
            feed_processor_kind: Self::FeedProcessorKind,
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
    pub struct FeedConfig<FeedProcessorId, AccountId> {
        pub active: bool,
        pub feed_processor_id: FeedProcessorId,
        pub owner: AccountId,
    }

    #[pallet::storage]
    #[pallet::getter(fn metadata)]
    pub(super) type Metadata<T: Config> =
        StorageMap<_, Identity, T::FeedId, FeedMetadata, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn feed_configs)]
    pub(super) type FeedConfigs<T: Config> = StorageMap<
        _,
        Identity,
        T::FeedId,
        FeedConfig<T::FeedProcessorKind, T::AccountId>,
        OptionQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn feeds)]
    pub(super) type Feeds<T: Config> =
        StorageMap<_, Identity, T::AccountId, BoundedVec<T::FeedId, T::MaxFeeds>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn totals)]
    pub(super) type Totals<T: Config> =
        StorageMap<_, Identity, T::FeedId, TotalObjectsAndSize, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn next_feed_id)]
    pub(super) type NextFeedId<T: Config> = StorageValue<_, T::FeedId, ValueQuery>;

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

        /// Feed was closed.
        FeedClosed {
            feed_id: T::FeedId,
            who: T::AccountId,
        },

        /// Feed was deleted.
        FeedDeleted {
            feed_id: T::FeedId,
            who: T::AccountId,
        },

        /// feed ownership transferred
        OwnershipTransferred {
            feed_id: T::FeedId,
            old_owner: T::AccountId,
            new_owner: T::AccountId,
        },
    }

    /// `pallet-feeds` errors
    #[pallet::error]
    pub enum Error<T> {
        /// `FeedId` doesn't exist
        UnknownFeedId,

        /// Feed was closed
        FeedClosed,

        /// Not a feed owner
        NotFeedOwner,

        /// Maximum feeds created by the caller
        MaxFeedsReached,
    }

    macro_rules! ensure_owner {
        ( $origin:expr, $feed_id:expr ) => {{
            let sender = ensure_signed($origin)?;
            let feed_config = FeedConfigs::<T>::get($feed_id).ok_or(Error::<T>::UnknownFeedId)?;
            ensure!(feed_config.owner == sender, Error::<T>::NotFeedOwner);
            (sender, feed_config)
        }};
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // TODO: add proper weights
        /// Create a new feed
        #[pallet::weight((10_000, Pays::No))]
        pub fn create(
            origin: OriginFor<T>,
            feed_processor_id: T::FeedProcessorKind,
            init_data: Option<InitData>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let feed_id = NextFeedId::<T>::get();
            let next_feed_id = feed_id
                .checked_add(&One::one())
                .ok_or(ArithmeticError::Overflow)?;
            let feed_processor = T::feed_processor(feed_processor_id.clone());
            if let Some(init_data) = init_data {
                feed_processor.init(feed_id, init_data.as_slice())?;
            }

            // check if max feeds are reached
            let mut owned_feeds = Feeds::<T>::get(who.clone()).unwrap_or_default();
            owned_feeds
                .try_push(feed_id)
                .map_err(|_| Error::<T>::MaxFeedsReached)?;

            NextFeedId::<T>::set(next_feed_id);
            FeedConfigs::<T>::insert(
                feed_id,
                FeedConfig {
                    active: true,
                    feed_processor_id,
                    owner: who.clone(),
                },
            );
            Feeds::<T>::insert(who.clone(), owned_feeds);
            Totals::<T>::insert(feed_id, TotalObjectsAndSize::default());

            Self::deposit_event(Event::FeedCreated { feed_id, who });

            Ok(())
        }

        /// Updates the feed with init data provided.
        #[pallet::weight((10_000, Pays::No))]
        pub fn update(
            origin: OriginFor<T>,
            feed_id: T::FeedId,
            feed_processor_id: T::FeedProcessorKind,
            init_data: Option<InitData>,
        ) -> DispatchResult {
            let (owner, feed_config) = ensure_owner!(origin, feed_id);
            let feed_processor = T::feed_processor(feed_processor_id.clone());
            if let Some(init_data) = init_data {
                feed_processor.init(feed_id, init_data.as_slice())?;
            }

            FeedConfigs::<T>::insert(
                feed_id,
                FeedConfig {
                    active: feed_config.active,
                    feed_processor_id,
                    owner: owner.clone(),
                },
            );

            Self::deposit_event(Event::FeedUpdated {
                feed_id,
                who: owner,
            });

            Ok(())
        }

        // TODO: add proper weights
        // TODO: For now we don't have fees, but we will have them in the future
        /// Put a new object into a feed
        #[pallet::weight((10_000, Pays::No))]
        pub fn put(origin: OriginFor<T>, feed_id: T::FeedId, object: Object) -> DispatchResult {
            let (owner, feed_config) = ensure_owner!(origin, feed_id);
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
                who: owner,
                object_size,
            });

            Ok(())
        }

        /// Closes the feed and stops accepting new feed.
        #[pallet::weight((T::DbWeight::get().reads_writes(1, 1), Pays::No))]
        pub fn close(origin: OriginFor<T>, feed_id: T::FeedId) -> DispatchResult {
            let (owner, mut feed_config) = ensure_owner!(origin, feed_id);
            feed_config.active = false;
            FeedConfigs::<T>::insert(feed_id, feed_config);
            Self::deposit_event(Event::FeedClosed {
                feed_id,
                who: owner,
            });
            Ok(())
        }

        /// Transfers feed from current owner to new owner
        #[pallet::weight((T::DbWeight::get().reads_writes(3, 3), Pays::No))]
        pub fn transfer(
            origin: OriginFor<T>,
            feed_id: T::FeedId,
            new_owner: <T::Lookup as StaticLookup>::Source,
        ) -> DispatchResult {
            let (owner, mut feed_config) = ensure_owner!(origin, feed_id);
            let new_owner = T::Lookup::lookup(new_owner)?;

            // remove current owner details
            let mut current_owner_feeds = Feeds::<T>::get(owner.clone()).unwrap_or_default();
            current_owner_feeds.retain(|x| *x != feed_id);

            // update new owner details
            feed_config.owner = new_owner.clone();
            let mut new_owner_feeds = Feeds::<T>::get(new_owner.clone()).unwrap_or_default();
            new_owner_feeds
                .try_push(feed_id)
                .map_err(|_| Error::<T>::MaxFeedsReached)?;

            // if the owner doesn't own any feed, then reclaim empty storage
            if current_owner_feeds.is_empty() {
                Feeds::<T>::remove(owner.clone());
            } else {
                Feeds::<T>::insert(owner.clone(), current_owner_feeds);
            }

            Feeds::<T>::insert(new_owner.clone(), new_owner_feeds);
            FeedConfigs::<T>::insert(feed_id, feed_config);
            Self::deposit_event(Event::OwnershipTransferred {
                feed_id,
                old_owner: owner,
                new_owner,
            });
            Ok(())
        }
    }
}

/// Mapping to the object offset within an extrinsic associated with given key
#[derive(Debug)]
pub struct CallObject {
    /// Key to the object located at the offset.
    pub key: Sha256Hash,
    /// Offset of object in the encoded call.
    pub offset: u32,
}

impl<T: Config> Call<T> {
    /// Extract the call objects if an extrinsic corresponds to `put` call
    pub fn extract_call_objects(&self) -> Vec<CallObject> {
        match self {
            Self::put { feed_id, object } => {
                let feed_processor_id = match FeedConfigs::<T>::get(feed_id) {
                    Some(config) => config.feed_processor_id,
                    // return if this was a invalid extrinsic
                    None => return vec![],
                };
                let feed_processor = T::feed_processor(feed_processor_id);
                let objects_mappings = feed_processor.object_mappings(*feed_id, object);
                objects_mappings
                    .into_iter()
                    .filter_map(|object_mapping| {
                        let mut co = object_mapping.try_into_call_object(
                            feed_id,
                            object.as_slice(),
                            |data| crypto::sha256_hash(data),
                        )?;
                        co.offset += 1 + mem::size_of::<T::FeedId>() as u32;
                        Some(co)
                    })
                    .collect()
            }
            _ => Default::default(),
        }
    }
}
