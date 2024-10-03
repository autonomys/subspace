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

//! Default weights for the Rewards Pallet
//! This file was not auto-generated.

use crate::WeightInfo;
use core::marker::PhantomData;
use frame_support::traits::Get;
use frame_support::weights::Weight;

#[derive(Debug)]
pub struct SubstrateWeight<T>(PhantomData<T>);

impl<T> WeightInfo for SubstrateWeight<T>
where
    T: frame_system::Config,
{
    fn on_initialize() -> Weight {
        Weight::from_parts(0, 0)
            .saturating_add(T::DbWeight::get().reads(1_u64))
            .saturating_add(T::DbWeight::get().writes(4_u64))
    }
}
