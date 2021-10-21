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

use codec::{Compact, CompactLen};
use core::mem;
pub use pallet::*;
use sp_std::vec::Vec;

#[frame_support::pallet]
mod pallet {
    use super::*;
    use frame_support::dispatch::DispatchResult;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use scale_info::TypeInfo;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// `pallet-feeds` events
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
    }

    /// Pallet feeds, used for storing arbitrary user-provided data combined into feeds.
    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    /// User-provided object to store
    pub(super) type PutDataObject = Vec<u8>;
    /// ID of the feed
    pub(super) type FeedId = u64;
    /// User-provided object metadata (not addressable directly, but available in an even)
    pub(super) type ObjectMetadata = Vec<u8>;

    /// Total amount of data and number of objects stored in a feed
    #[derive(Decode, Encode, TypeInfo, Default)]
    #[cfg_attr(feature = "std", derive(Debug))]
    pub(super) struct TotalObjectsAndSize {
        /// Total size of objects in bytes
        pub(super) size: u64,
        /// Total number of objects
        pub(super) count: u64,
    }

    #[pallet::storage]
    pub(super) type Feeds<T: Config> =
        StorageMap<_, Blake2_128Concat, FeedId, ObjectMetadata, OptionQuery>;

    #[pallet::storage]
    pub(super) type Totals<T: Config> =
        StorageMap<_, Blake2_128Concat, FeedId, TotalObjectsAndSize, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn current_feed_id)]
    pub(super) type CurrentFeedId<T: Config> = StorageValue<_, FeedId, ValueQuery>;

    /// `pallet-feeds` events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// New object is added \[object_metadata, account_id, object_size\]
        DataSubmitted(ObjectMetadata, T::AccountId, u64),
        /// New feed is created \[feed_id, account_id\]
        FeedCreated(FeedId, T::AccountId),
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
        pub fn create(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let feed_id = Self::current_feed_id();

            CurrentFeedId::<T>::mutate(|feed_id| *feed_id = feed_id.saturating_add(1));

            Totals::<T>::insert(feed_id, TotalObjectsAndSize::default());

            Self::deposit_event(Event::FeedCreated(feed_id, who));

            Ok(())
        }

        // TODO: add proper weights
        /// Put a new object into a feed
        #[pallet::weight(10_000)]
        pub fn put(
            origin: OriginFor<T>,
            feed_id: FeedId,
            data: PutDataObject,
            metadata: ObjectMetadata,
        ) -> DispatchResultWithPostInfo {
            let who = ensure_signed(origin)?;

            let object_size = data.len() as u64;

            log::debug!("metadata: {:?}", metadata);
            log::debug!("object_size: {:?}", object_size);

            let current_feed_id = Self::current_feed_id();

            ensure!(current_feed_id >= feed_id, Error::<T>::UnknownFeedId);

            Feeds::<T>::insert(feed_id, metadata.clone());

            Totals::<T>::mutate(feed_id, |feed_totals| {
                feed_totals.size += object_size;
                feed_totals.count += 1;
            });

            Self::deposit_event(Event::DataSubmitted(metadata, who, object_size));

            // TODO: For now we don't have fees, but we will have them in the future
            Ok(Pays::No.into())
        }
    }
}

/// Mapping to the object offset and size within an extrinsic
#[derive(Debug)]
pub struct CallObjectLocation {
    /// Offset
    pub offset: usize,
    /// Size
    pub size: usize,
}

impl<T: Config> Call<T> {
    /// Extract object location if an extrinsic corresponds to `put` call
    pub fn extract_object_location(&self) -> Option<CallObjectLocation> {
        match self {
            Self::put { data, .. } => {
                // FeedId is the first field in the extrinsic followed by compact length prefix of
                // the actual data and data itself.
                // `+1` corresponds to `Call::put {}` enum variant encoding.
                Some(CallObjectLocation {
                    offset: mem::size_of::<FeedId>()
                        + Compact::compact_len(&(data.len() as u32))
                        + 1,
                    size: data.len(),
                })
            }
            _ => None,
        }
    }
}
