// Copyright (C) 2022 Subspace Labs, Inc.
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

//! Pallet that provides necessary Leaf data for MMR.

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(associated_type_bounds)]

use frame_system::pallet_prelude::BlockNumberFor;
use log::error;
pub use pallet::*;
use sp_mmr_primitives::{LeafDataProvider, OnNewRoot};
use sp_runtime::traits::One;
use sp_runtime::{DigestItem, Saturating};
use sp_subspace_mmr::subspace_mmr_runtime_interface::get_mmr_leaf_data;
use sp_subspace_mmr::{LeafDataV0, MmrDigest, MmrLeaf};

#[frame_support::pallet]
mod pallet {
    use frame_support::Parameter;
    use sp_core::H256;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<Hash: Into<H256> + From<H256>> {
        type MmrRootHash: Parameter + Copy;
    }
}

impl<T: Config> OnNewRoot<T::MmrRootHash> for Pallet<T> {
    fn on_new_root(root: &T::MmrRootHash) {
        let digest = DigestItem::new_mmr_root(*root);
        <frame_system::Pallet<T>>::deposit_log(digest);
    }
}

impl<T: Config> LeafDataProvider for Pallet<T> {
    type LeafData = MmrLeaf<BlockNumberFor<T>, T::Hash>;

    fn leaf_data() -> Self::LeafData {
        let block_number = frame_system::Pallet::<T>::block_number().saturating_sub(One::one());
        let block_hash = frame_system::Pallet::<T>::parent_hash();
        // unfortunately, we Leaf data provider trait expects the impl to be infallible
        // but our host function might fail for any reason but practically shouldn't since
        // we are querying the immediate parent block
        // We will just log an error in case of such ever happening
        let leaf_data = get_mmr_leaf_data(block_hash.into()).unwrap_or_else(|| {
            error!(target: "runtime::subspace_mmr", "Failed to fetch leaf data for Block hash{block_hash:?}");
            Default::default()
        });
        MmrLeaf::V0(LeafDataV0 {
            block_number,
            block_hash,
            state_root: leaf_data.state_root.into(),
            extrinsics_root: leaf_data.extrinsics_root.into(),
        })
    }
}
