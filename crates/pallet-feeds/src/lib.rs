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
use frame_support::sp_runtime::DispatchResult;
pub use pallet::*;
use subspace_core_primitives::{crypto, Sha256Hash};

pub mod feed_processor;
#[cfg(all(feature = "std", test))]
mod mock;
#[cfg(all(feature = "std", test))]
mod tests;

#[frame_support::pallet]
mod pallet {
    use crate::FeedValidator;
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

        /// Feed Validator
        type Validator: FeedValidator<Self::FeedId>;
    }

    /// Pallet feeds, used for storing arbitrary user-provided data combined into feeds.
    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// User-provided object to store
    pub(super) type Object = Vec<u8>;
    /// User-provided object metadata (not addressable directly, but available in an even)
    pub(super) type ObjectMetadata = Vec<u8>;
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
        StorageMap<_, Blake2_128Concat, T::FeedId, ObjectMetadata, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn should_validate)]
    pub(super) type ShouldValidate<T: Config> =
        StorageMap<_, Blake2_128Concat, T::FeedId, bool, ValueQuery>;

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
            metadata: ObjectMetadata,
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
            initial_validation: Option<InitialValidation>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let feed_id = Self::current_feed_id();

            let next_feed_id = feed_id
                .checked_add(&T::FeedId::one())
                .ok_or(ArithmeticError::Overflow)?;
            let mut should_validate = false;
            if let Some(init_data) = initial_validation {
                should_validate = true;
                T::Validator::initialize(feed_id, init_data.as_slice())?;
            }

            CurrentFeedId::<T>::mutate(|feed_id| *feed_id = next_feed_id);
            ShouldValidate::<T>::mutate(feed_id, |validate| *validate = should_validate);
            Totals::<T>::insert(feed_id, TotalObjectsAndSize::default());

            Self::deposit_event(Event::FeedCreated { feed_id, who });

            Ok(())
        }

        // TODO: add proper weights
        // TODO: For now we don't have fees, but we will have them in the future
        /// Put a new object into a feed
        #[pallet::weight((10_000, Pays::No))]
        pub fn put(
            origin: OriginFor<T>,
            feed_id: T::FeedId,
            object: Object,
            metadata: ObjectMetadata,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let object_size = object.len() as u64;

            log::debug!("metadata: {:?}", metadata);
            log::debug!("object_size: {:?}", object_size);

            let current_feed_id = Self::current_feed_id();

            ensure!(current_feed_id >= feed_id, Error::<T>::UnknownFeedId);
            if ShouldValidate::<T>::get(feed_id) {
                T::Validator::validate(feed_id, object.as_slice())?
            }

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

/// Mapping to the object offset and size within an extrinsic
#[derive(Debug)]
pub struct CallObject {
    /// Object hash
    pub hash: Sha256Hash,
    /// Offset of object in the encoded call.
    pub offset: u32,
}

impl<T: Config> Call<T> {
    /// Extract the call object if an extrinsic corresponds to `put` call
    pub fn extract_call_object(&self) -> Option<CallObject> {
        match self {
            Self::put { object, .. } => {
                // `FeedId` is the first field in the extrinsic. `1+` corresponds to `Call::put {}`
                // enum variant encoding.
                Some(CallObject {
                    hash: crypto::sha256_hash(object),
                    offset: 1 + mem::size_of::<T::FeedId>() as u32,
                })
            }
            _ => None,
        }
    }
}

/// FeedValidator validates a given feed before accepting the feed
pub trait FeedValidator<FeedId> {
    fn initialize(feed_id: FeedId, data: &[u8]) -> DispatchResult;
    fn validate(feed_id: FeedId, object: &[u8]) -> DispatchResult;
}
