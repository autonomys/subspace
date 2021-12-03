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

//! Pallet object store, used for simple object storage on the network.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

#[cfg(all(feature = "std", test))]
mod mock;
#[cfg(all(feature = "std", test))]
mod tests;

pub use pallet::*;
use subspace_core_primitives::{crypto, Sha256Hash};

#[frame_support::pallet]
mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use log::debug;
    use sp_std::prelude::*;
    use subspace_core_primitives::{crypto, Sha256Hash};

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// `pallet-object-store` events
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
    }

    /// Pallet object-store, used for storing arbitrary user-provided data combined into object-store.
    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    /// `pallet-object-store` events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// New object is added \[who, object_id, object_size\]
        DataSubmitted(T::AccountId, Sha256Hash, u32),
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // TODO: add proper weights
        // TODO: For now we don't have fees, but we will have them in the future
        /// Put a new object into a feed
        #[pallet::weight((10_000, Pays::No))]
        pub fn put(origin: OriginFor<T>, data: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let object_size = data.len() as u32;

            let object_id = crypto::sha256_hash(&data);

            debug!(
                target: "runtime:object-store",
                "New object {}, size {} bytes",
                hex::encode(&object_id),
                object_size
            );

            Self::deposit_event(Event::DataSubmitted(who, object_id, object_size));

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
    /// Extract object location if an extrinsic corresponds to `put` call
    pub fn extract_call_object(&self) -> Option<CallObject> {
        match self {
            Self::put { data } => {
                // `1` corresponds to `Call::put {}` enum variant encoding.
                Some(CallObject {
                    hash: crypto::sha256_hash(data),
                    offset: 1,
                })
            }
            _ => None,
        }
    }
}
