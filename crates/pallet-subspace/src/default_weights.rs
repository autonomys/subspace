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

//! Default weights for the Subspace Pallet
//! This file was not auto-generated.

use frame_support::weights::Weight;

impl crate::WeightInfo for () {
    fn report_equivocation() -> Weight {
        // TODO: Proper value
        Weight::from_ref_time(10_000)
    }

    fn store_root_blocks(root_blocks_count: usize) -> Weight {
        // TODO: Proper value
        Weight::from_ref_time(10_000 * (root_blocks_count as u64 + 1))
    }

    fn vote() -> Weight {
        // TODO: Proper value
        Weight::from_ref_time(10_000)
    }
}
