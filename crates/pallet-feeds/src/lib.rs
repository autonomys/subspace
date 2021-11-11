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

//! # Feeds pallet.
//!
//! The Feeds pallet provides the functionality for storing arbitrary user
//! data to the network.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

use codec::{Decode, Encode};
use core::mem;
pub use pallet::*;
use scale_info::TypeInfo;
use sp_core::RuntimeDebug;
use sp_std::vec::Vec;
use subspace_core_primitives::{crypto, Sha256Hash};

#[cfg(all(feature = "std", test))]
mod mock;
#[cfg(all(feature = "std", test))]
mod tests;

/// Simple index type that we use to count feeds.
pub type FeedId = u64;

/// Arbitrary user data stored to the network.
///
/// The size of each object is typically limited by the transaction size limit.
pub type Object = Vec<u8>;

/// Some meta information about [`Object`].
pub type Metaobject = Vec<u8>;

/// Total size and number of objects stored in a feed.
#[derive(Decode, Encode, TypeInfo, Default, PartialEq, Eq, RuntimeDebug)]
pub struct FeedInfo {
    /// Total size of objects in bytes
    pub total_size: u64,
    /// Total number of objects
    pub total_objects: u64,
}

#[frame_support::pallet]
mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use super::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// `pallet-feeds` events
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
    }

    /// Pallet feeds, used for storing arbitrary user-provided data combined into feeds.
    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    /// `pallet-feeds` events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// New feed was created. \[who, feed_id\]
        FeedCreated(T::AccountId, FeedId),
        /// New object was submitted. \[who, metaobject, object_size\]
        ObjectSubmitted(T::AccountId, Metaobject, u64),
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
            Feeds::<T>::insert(feed_id, FeedInfo::default());
            Self::deposit_event(Event::FeedCreated(who, feed_id));
            Ok(())
        }

        // TODO: add proper weights
        // TODO: For now we don't have fees, but we will have them in the future
        /// Put a new object into a feed
        #[pallet::weight((10_000, Pays::No))]
        pub fn put(
            origin: OriginFor<T>,
            feed_id: FeedId,
            object: Object,
            metaobject: Metaobject,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let object_size = object.len() as u64;

            log::debug!("object_size: {}, metaobject: {:?}", object_size, metaobject);

            let current_feed_id = Self::current_feed_id();
            ensure!(current_feed_id >= feed_id, Error::<T>::UnknownFeedId);

            Metaobjects::<T>::insert(feed_id, metaobject.clone());
            Feeds::<T>::mutate(feed_id, |feed_info| {
                feed_info.total_size += object_size;
                feed_info.total_objects += 1;
            });

            Self::deposit_event(Event::ObjectSubmitted(who, metaobject, object_size));

            Ok(())
        }
    }

    #[pallet::storage]
    #[pallet::getter(fn metaobjects)]
    pub(super) type Metaobjects<T: Config> =
        StorageMap<_, Blake2_128Concat, FeedId, Metaobject, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn feeds)]
    pub(super) type Feeds<T: Config> =
        StorageMap<_, Blake2_128Concat, FeedId, FeedInfo, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn current_feed_id)]
    pub(super) type CurrentFeedId<T: Config> = StorageValue<_, FeedId, ValueQuery>;
}

/// Mapping to the object offset and size within an extrinsic
#[derive(Debug)]
pub struct CallObjectLocation {
    /// Object hash
    pub hash: Sha256Hash,
    /// Offset
    pub offset: u32,
}

impl<T: Config> Call<T> {
    /// Extract object location if an extrinsic corresponds to `put` call
    pub fn extract_object_location(&self) -> Option<CallObjectLocation> {
        match self {
            Self::put { object, .. } => {
                // `FeedId` is the first field in the extrinsic. `1+` corresponds to `Call::put {}`
                // enum variant encoding.
                Some(CallObjectLocation {
                    hash: crypto::sha256_hash(object),
                    offset: 1 + mem::size_of::<FeedId>() as u32,
                })
            }
            _ => None,
        }
    }
}
