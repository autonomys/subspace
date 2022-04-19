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

use crate::CallObject;
use codec::{Compact, Decode};
use sp_runtime::{DispatchError, DispatchResult};
use sp_std::{vec, vec::Vec};
use subspace_core_primitives::Sha256Hash;

/// Holds the offset to some portion of data within/or the object
#[derive(Debug)]
pub enum FeedObjectMapping {
    /// Maps the entire object treating it as content
    /// If key is provided, it is namespaced to feed to avoid collisions
    Object { key: Option<Vec<u8>> },
    /// Maps some data within the object at the specific offset.
    /// Data must be a scale encoded `Vec<u8>`
    /// If key is provided, it namespaced to feed to avoid collisions
    Content { key: Option<Vec<u8>>, offset: u32 },
}

impl FeedObjectMapping {
    pub(crate) fn try_into_call_object<KNS, CO, CH>(
        self,
        object: &[u8],
        key_namespace: KNS,
        call_offset: CO,
        content_hasher: CH,
    ) -> Option<CallObject>
    where
        KNS: Fn(&[u8]) -> Sha256Hash,
        CO: Fn(u32, bool) -> u32,
        CH: Fn(&[u8]) -> Sha256Hash,
    {
        match self {
            FeedObjectMapping::Object { key } => Some(CallObject {
                key: key
                    .map(|key| key_namespace(key.as_slice()))
                    .unwrap_or_else(|| content_hasher(object)),
                // since the object passed is already scale decode, offset is 0
                offset: call_offset(0, false),
            }),
            // derive key from the content at the offset
            FeedObjectMapping::Content { key, offset } => {
                let key = if let Some(key) = key {
                    key_namespace(key.as_slice())
                } else {
                    // extract the content from the object.
                    // extract encoded vector length
                    let mut start = offset as usize;

                    // since this wont be called in runtime, decode Compact<u32> by a new
                    // allocation of just the encoded bytes of length.
                    let data = match object[start] & 3 {
                        0 => vec![object[start]],
                        1 => Vec::from(&object[start..start + 2]),
                        2 => Vec::from(&object[start..start + 4]),
                        // too big. dont care
                        _ => return None,
                    };

                    start += data.len();
                    let length = match Compact::<u32>::decode(&mut data.as_slice()) {
                        Ok(length) => length.0 as usize,
                        _ => return None,
                    };
                    content_hasher(&object[start..start + length])
                };

                Some(CallObject {
                    key,
                    // this is the offset from decoded object
                    // when the DSN is fetching the data, we need to consider the encoded length bytes of the object itself inside the call
                    // offset needs to be incremented by those byte spaces
                    offset: call_offset(offset, true),
                })
            }
        }
    }
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
    /// this is called once per extrinsic that puts a feed into a given feed stream.
    fn put(&self, _feed_id: FeedId, _object: &[u8]) -> Result<Option<FeedMetadata>, DispatchError> {
        Ok(None)
    }

    /// returns any object mappings inside the given object
    fn object_mappings(&self, _feed_id: FeedId, object: &[u8]) -> Vec<FeedObjectMapping>;

    /// signals a delete to any underlying feed data.
    fn delete(&self, _feed_id: FeedId) -> DispatchResult {
        Ok(())
    }
}

/// Content addressable feed processor impl
/// Offsets the whole object as content thereby signalling to derive `key = hash(object)`
/// put do not provide any metadata.
impl<FeedId> FeedProcessor<FeedId> for () {
    /// maps the entire object as content.
    fn object_mappings(&self, _feed_id: FeedId, _object: &[u8]) -> Vec<FeedObjectMapping> {
        vec![FeedObjectMapping::Object { key: None }]
    }
}
