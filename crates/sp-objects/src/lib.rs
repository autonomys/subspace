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

//! Primitives for Objects.

#![cfg_attr(not(feature = "std"), no_std)]

use sp_std::vec::Vec;
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_runtime_primitives::Hash;

sp_api::decl_runtime_apis! {
    pub trait ObjectsApi {
        /// Returns all the validated object call hashes for a given block
        fn validated_object_call_hashes() -> Vec<Hash>;


        /// Extract block object mapping for a given block
        fn extract_block_object_mapping(block: Block, validated_object_calls: Vec<Hash>) -> BlockObjectMapping;
    }
}
