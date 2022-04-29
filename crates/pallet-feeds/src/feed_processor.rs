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
use codec::{Compact, CompactLen, Decode, Encode};
use sp_runtime::{DispatchError, DispatchResult};
use sp_std::{vec, vec::Vec};
use subspace_core_primitives::Sha256Hash;

/// Holds the offset to some portion of data within/or the object
#[derive(Debug)]
pub enum FeedObjectMapping {
    /// Maps the object or some data within the object at the specific offset.
    /// The key is derived from the content.
    Content { offset: u32 },

    /// Maps the object or some data within the object at the specific offset.
    /// The key provided is namespaced to feed to avoid collisions
    Custom { key: Vec<u8>, offset: u32 },
}

impl FeedObjectMapping {
    pub(crate) fn try_into_call_object<FeedID: Encode, Hasher: Fn(&[u8]) -> Sha256Hash>(
        self,
        feed_id: FeedID,
        object: &[u8],
        hasher: Hasher,
    ) -> Option<CallObject> {
        match self {
            // If this is a custom key, then name space the key.
            FeedObjectMapping::Custom { key, offset } => {
                let mut data = feed_id.encode();
                data.extend_from_slice(&key);
                Some(CallObject {
                    key: hasher(&data),
                    offset,
                })
            }
            // For content, we try to extract the content to derive the key
            FeedObjectMapping::Content { offset } => {
                // If offset is 0, then then we want to map the entire object.
                // Since the object is already decoded, no need to decode it further
                let key = if offset == 0 {
                    hasher(object)
                } else {
                    // This is referring to some content within the object that is encoded.
                    // Move the offset back by the encoded bytes of object to get the right offset since the object is already decoded.
                    let offset = offset
                        .saturating_sub(Compact::<u32>::compact_len(&(object.len() as u32)) as u32);
                    hasher(&Vec::decode(&mut &object[offset as usize..]).ok()?)
                };

                Some(CallObject { key, offset })
            }
        }
    }
}

/// Metadata of a feed object as raw bytes.
pub type FeedMetadata = Vec<u8>;

/// # Feed Processor
/// Feed Processor defines some useful abstractions that are used during the life cycle of the Feed and its objects.
/// We can provide some custom logic specific to the Feed by implementing a Custom Feed Processor.
///
/// ## Feed Metadata
///
/// Before an object is added to Subspace storage, `put` on Feed processor to give the impl an opportunity to run the object
/// through their custom logic and returns some metadata about the object. Metadata is then stored in the runtime overwriting
/// any metadata of the previous object. The default implementation of Feed processor gives empty metadata about the object.
///
/// ## Feed object mapping
/// Feed indexes the objects in the DSN using offsets within the Block the object is present in. `object_mappings` is the
/// only that must be implemented by the Feed processor. Since DSN is a key value store, there are two different ways keys
/// are derived for given data at the offset within the block
/// - Key derived from content. Feeds use Sha256 to derive the key for the data at the offset.
/// - Key provided by the feed processor. Feed processor implementations can instead provide a key for object at the offset.
///
/// ## Examples
/// ### Content based addressing with default hasher
/// ```rust
/// use pallet_feeds::feed_processor::{FeedProcessor, FeedObjectMapping};
/// struct IPFSLike;
/// impl<FeedId> FeedProcessor<FeedId> for IPFSLike { ///
///     fn object_mappings(&self, _feed_id: FeedId, _object: &[u8]) -> Vec<FeedObjectMapping> {
///         vec![FeedObjectMapping::Content { offset: 0 }]
///     }
/// }
/// ```
/// This implements a Content addressable Feed using default Hasher. The entire object is treated as data and hence the offset is zero.
///
/// ### Content based addressing using custom Hasher
/// ```rust
/// use sp_runtime::traits::{BlakeTwo256, Hash};
/// use pallet_feeds::feed_processor::{FeedProcessor, FeedObjectMapping};
/// struct IPFSLike;
/// impl<FeedId> FeedProcessor<FeedId> for IPFSLike { ///
///     fn object_mappings(&self, _feed_id: FeedId, object: &[u8]) -> Vec<FeedObjectMapping> {
///         vec![FeedObjectMapping::Custom { key: BlakeTwo256::hash(object).as_bytes().to_vec(), offset: 0 }]
///     }
/// }
/// ```
/// This implements a Content addressable Feed using BlakeTwo256 hasher. The entire object is treated as data and hence the offset is zero.
pub trait FeedProcessor<FeedId> {
    /// Initiates a specific Feed with data transparent to FeedProcessor
    /// Can be called when re-initializing the feed.
    fn init(&self, _feed_id: FeedId, _data: &[u8]) -> DispatchResult {
        Ok(())
    }

    /// Puts a feed and returns the Metadata if any.
    /// This is called once per extrinsic that puts a feed into a given feed stream.
    fn put(&self, _feed_id: FeedId, _object: &[u8]) -> Result<Option<FeedMetadata>, DispatchError> {
        Ok(None)
    }

    /// Returns any object mappings inside the given object
    fn object_mappings(&self, _feed_id: FeedId, object: &[u8]) -> Vec<FeedObjectMapping>;

    /// Signals a delete to any underlying feed data.
    fn delete(&self, _feed_id: FeedId) -> DispatchResult {
        Ok(())
    }
}

/// Content addressable feed processor impl
/// Offsets the whole object as content thereby signalling to derive `key = hash(object)`
/// Put do not provide any metadata.
impl<FeedId> FeedProcessor<FeedId> for () {
    /// Maps the entire object as content.
    fn object_mappings(&self, _feed_id: FeedId, _object: &[u8]) -> Vec<FeedObjectMapping> {
        vec![FeedObjectMapping::Content { offset: 0 }]
    }
}
