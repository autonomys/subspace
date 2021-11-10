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

//! Subspace pallet for issuing rewards to block producers.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

mod default_weights;

use codec::{Decode, Encode};
use frame_support::traits::{Currency, Get};
use frame_support::weights::Weight;
pub use pallet::*;
use sp_consensus_subspace::digests::PreDigest;
use sp_consensus_subspace::SUBSPACE_ENGINE_ID;

type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

pub trait WeightInfo {
    fn on_initialize() -> Weight;
}

#[frame_support::pallet]
mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// `pallet-rewards` events
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        type Currency: Currency<Self::AccountId>;

        /// Fixed reward for block producer.
        #[pallet::constant]
        type BlockReward: Get<BalanceOf<Self>>;

        type WeightInfo: WeightInfo;
    }

    /// Pallet rewards for issuing rewards to block producers.
    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    /// `pallet-rewards` events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Issued reward for the block author. \[block_author, reward\]
        BlockReward(T::AccountId, BalanceOf<T>),
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(now: BlockNumberFor<T>) -> Weight {
            Self::do_initialize(now);
            T::WeightInfo::on_initialize()
        }
    }
}

impl<T: Config> Pallet<T> {
    fn do_initialize(_n: T::BlockNumber) {
        if let Some(block_author) = frame_system::Pallet::<T>::digest()
            .logs
            .iter()
            .filter_map(|s| s.as_pre_runtime())
            .find_map(|(id, mut data)| {
                if id == SUBSPACE_ENGINE_ID {
                    PreDigest::decode(&mut data).ok()
                } else {
                    None
                }
            })
            .and_then(|pre_digest| {
                T::AccountId::decode(&mut pre_digest.solution.public_key.encode().as_ref()).ok()
            })
        {
            let reward = T::BlockReward::get();
            T::Currency::deposit_creating(&block_author, reward);

            Self::deposit_event(Event::BlockReward(block_author, reward));
        }
    }
}
