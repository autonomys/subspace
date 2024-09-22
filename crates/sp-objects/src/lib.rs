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
// TODO: Suppression because of https://github.com/paritytech/polkadot-sdk/issues/3533
#![allow(clippy::multiple_bound_locations)]

use subspace_core_primitives::objects::BlockObjectMapping;

sp_api::decl_runtime_apis! {
    pub trait ObjectsApi {
        /// Extract block object mapping for a given block
        fn extract_block_object_mapping(block: Block) -> BlockObjectMapping;
    }
}
