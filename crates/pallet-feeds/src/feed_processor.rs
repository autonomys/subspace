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

//! Defines FeedProcessor and its types

use sp_runtime::{DispatchError, DispatchResult};
use sp_std::{vec, vec::Vec};
use subspace_core_primitives::crypto;

/// Object mapping that points to an object in a block
#[derive(Debug)]
pub struct FeedObjectMapping {
    /// Key scoped to the feed
    pub key: Vec<u8>,
    /// Offset of the data within object
    pub offset: u32,
}

/// Metadata of a feed object as raw bytes.
pub type FeedMetadata = Vec<u8>;

/// FeedProcessor dictates a flow import and constituents of a Feed
pub trait FeedProcessor<FeedId> {
    /// initiates a specific Feed with data transparent to FeedProcessor
    /// can be called when re-initializing the feed.
    fn init(&self, _feed_id: FeedId, _data: &[u8]) -> DispatchResult {
        Ok(())
    }

    /// puts a feed and returns the Metadata if any
    /// this is called once per extrinsic that puts a feed into a give feed.
    fn put(&self, _feed_id: FeedId, _object: &[u8]) -> Result<Option<FeedMetadata>, DispatchError> {
        Ok(None)
    }

    /// returns any object mappings inside the given object
    fn object_mappings(&self, _feed_id: FeedId, object: &[u8]) -> Vec<FeedObjectMapping> {
        vec![FeedObjectMapping {
            key: crypto::sha256_hash(object).to_vec(),
            offset: 0,
        }]
    }

    /// signals a delete to any underlying feed data.
    fn delete(&self, _feed_id: FeedId) -> DispatchResult {
        Ok(())
    }
}

impl<FeedId> FeedProcessor<FeedId> for () {}
