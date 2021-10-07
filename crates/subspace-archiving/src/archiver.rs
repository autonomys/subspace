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

use crate::merkle_tree::{MerkleTree, Witness};
use parity_scale_codec::{Decode, Encode};
use reed_solomon_erasure::galois_16::ReedSolomon;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::io::Write;
use std::iter;
use std::marker::PhantomData;
use subspace_core_primitives::{
    crypto, BlockObjectMapping, LastArchivedBlock, Piece, RootBlock, Sha256Hash, PIECE_SIZE,
    SHA256_HASH_SIZE,
};
use thiserror::Error;

const INITIAL_LAST_ARCHIVED_BLOCK: LastArchivedBlock = LastArchivedBlock {
    number: 0,
    bytes: Some(0),
};

/// Segment represents a collection of items stored in archival history of the Subspace blockchain
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Encode, Decode)]
pub enum Segment {
    // V0 of the segment data structure
    #[codec(index = 0)]
    V0 {
        /// Segment items
        items: Vec<SegmentItem>,
    },
}

impl Segment {
    fn push_item(&mut self, segment_item: SegmentItem) {
        let Self::V0 { items } = self;
        items.push(segment_item);
    }

    fn pop_item(&mut self) -> Option<SegmentItem> {
        let Self::V0 { items } = self;
        items.pop()
    }
}

/// Kinds of items that are contained within a segment
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Encode, Decode)]
pub enum SegmentItem {
    /// Contains full object inside
    #[codec(index = 0)]
    Object(Vec<u8>),
    /// Contains the beginning of the object inside, remainder will be found in subsequent segments
    #[codec(index = 1)]
    ObjectStart(Vec<u8>),
    /// Continuation of the partial object spilled over into the next segment
    #[codec(index = 2)]
    ObjectContinuation(Vec<u8>),
    /// Contains full block inside
    #[codec(index = 3)]
    Block {
        /// Block bytes
        bytes: Vec<u8>,
        /// This is a convenience implementation detail and will not be available on decoding
        #[doc(hidden)]
        #[codec(skip)]
        object_mapping: BlockObjectMapping,
    },
    /// Contains the beginning of the block inside, remainder will be found in subsequent segments
    #[codec(index = 4)]
    BlockStart {
        /// Block bytes
        bytes: Vec<u8>,
        /// This is a convenience implementation detail and will not be available on decoding
        #[doc(hidden)]
        #[codec(skip)]
        object_mapping: BlockObjectMapping,
    },
    /// Continuation of the partial block spilled over into the next segment
    #[codec(index = 5)]
    BlockContinuation {
        /// Block bytes
        bytes: Vec<u8>,
        /// This is a convenience implementation detail and will not be available on decoding
        #[doc(hidden)]
        #[codec(skip)]
        object_mapping: BlockObjectMapping,
    },
    /// Root block
    #[codec(index = 6)]
    RootBlock(RootBlock),
}

#[derive(Debug, Clone, Eq, PartialEq)]
/// Archived segment as a combination of root block hash, segment index and corresponding pieces
pub struct ArchivedSegment {
    /// Root block of the segment
    pub root_block: RootBlock,
    /// Pieces that correspond to this segment
    pub pieces: Vec<Piece>,
}

/// Archiver instantiation error
#[derive(Debug, Error, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ArchiverInstantiationError {
    /// Record size it smaller that needed to hold any information
    #[error("Record size it smaller that needed to hold any information")]
    RecordSizeTooSmall,
    /// Segment size is not bigger than record size
    #[error("Segment size is not bigger than record size")]
    SegmentSizeTooSmall,
    /// Segment size is not a multiple of record size
    #[error("Segment size is not a multiple of record size")]
    SegmentSizesNotMultipleOfRecordSize,
    /// Wrong record and segment size, it will not be possible to produce pieces
    #[error("Wrong record and segment size, it will not be possible to produce pieces")]
    WrongRecordAndSegmentCombination,
    /// Invalid last archived block, its size is the same as encoded block
    #[error("Invalid last archived block, its size {0} bytes is the same as encoded block")]
    InvalidLastArchivedBlock(u32),
    /// Invalid block, its size is smaller than already archived number of bytes
    #[error("Invalid block, its size {block_bytes} bytes is smaller than already archived {archived_block_bytes} bytes")]
    InvalidBlockSmallSize {
        /// Full block size
        block_bytes: u32,
        /// Already archived portion of the block
        archived_block_bytes: u32,
    },
    /// No archived blocks, invalid initial state
    #[error("No archived blocks, invalid initial state")]
    NoBlocksInvalidInitialState,
}

mod private {
    pub trait ArchiverState {}

    /// Marker struct used in archiver to define a state where archiver is used for archiving object
    /// before genesis block
    #[derive(Debug)]
    pub struct ObjectArchiverState;

    impl ArchiverState for ObjectArchiverState {}

    /// Marker struct used in archiver to define a state where archiver is used for archiving blocks
    /// at or after genesis block
    #[derive(Debug)]
    pub struct BlockArchiverState;

    impl ArchiverState for BlockArchiverState {}
}

/// Object archiver for Subspace blockchain.
///
/// It takes pre-genesis objects and concatenates them into a buffer, buffer is
/// sliced into segments of `RECORDED_HISTORY_SEGMENT_SIZE` size, segments are sliced into source
/// records of `RECORD_SIZE`, records are erasure coded, Merkle Tree is built over them, and
/// with Merkle Proofs appended records become pieces that are returned alongside corresponding root
/// block header.
///
/// Object archiver is only used pre-genesis and should be turned into block archiver for later use.
pub type ObjectArchiver = Archiver<private::ObjectArchiverState>;

/// Block archiver for Subspace blockchain.
///
/// It takes new confirmed (at `K` depth) blocks and concatenates them into a buffer, buffer is
/// sliced into segments of `RECORDED_HISTORY_SEGMENT_SIZE` size, segments are sliced into source
/// records of `RECORD_SIZE`, records are erasure coded, Merkle Tree is built over them, and
/// with Merkle Proofs appended records become pieces that are returned alongside corresponding root
/// block header.
pub type BlockArchiver = Archiver<private::BlockArchiverState>;

// TODO: Use block object mapping and produce piece object mapping
/// Generic archiver for Subspace blockchain.
///
/// Shouldn't be used directly, but rather through `ObjectArchiver` or `BlockArchiver` type aliases.
#[derive(Debug)]
pub struct Archiver<State: private::ArchiverState> {
    /// Buffer containing blocks and other buffered items that are pending to be included into the
    /// next segment
    buffer: VecDeque<SegmentItem>,
    /// Configuration parameter defining the size of one record (data in one piece excluding witness
    /// size)
    record_size: usize,
    /// Configuration parameter defining the size of one recorded history segment
    segment_size: usize,
    /// Erasure coding data structure
    reed_solomon: ReedSolomon,
    /// An index of the current segment
    segment_index: u64,
    /// Hash of the root block of the previous segment
    prev_root_block_hash: Sha256Hash,
    /// Last archived block
    last_archived_block: LastArchivedBlock,
    /// Just a marker for otherwise unused generic parameter
    state_marker: PhantomData<State>,
}

impl<State: private::ArchiverState> Archiver<State> {
    /// Create a new instance with specified record size and recorded history segment size.
    ///
    /// Note: this is the only way to instantiate object archiver, while block archiver can be
    /// instantiated with `BlockArchiver::with_initial_state()` in case of restarts.
    ///
    /// Panics if:
    /// * record size it smaller that needed to hold any information
    /// * segment size is not bigger than record size
    /// * segment size is not a multiple of record size
    /// * segment size and record size do not make sense together
    pub fn new(
        record_size: usize,
        segment_size: usize,
    ) -> Result<Self, ArchiverInstantiationError> {
        let tiny_segment = Segment::V0 {
            items: vec![SegmentItem::Block {
                bytes: vec![0u8],
                object_mapping: BlockObjectMapping::default(),
            }],
        };
        if record_size <= tiny_segment.encoded_size() {
            return Err(ArchiverInstantiationError::RecordSizeTooSmall);
        }
        if segment_size <= record_size {
            return Err(ArchiverInstantiationError::SegmentSizeTooSmall);
        }
        if segment_size % record_size != 0 {
            return Err(ArchiverInstantiationError::SegmentSizesNotMultipleOfRecordSize);
        }

        // We take N data records and will creates the same number of parity records, hence `*2`
        let merkle_num_leaves = segment_size / record_size * 2;
        let witness_size = SHA256_HASH_SIZE * merkle_num_leaves.log2() as usize;
        if record_size + witness_size != PIECE_SIZE {
            return Err(ArchiverInstantiationError::WrongRecordAndSegmentCombination);
        }

        let shards = segment_size / record_size;
        let reed_solomon = ReedSolomon::new(shards, shards)
            .expect("ReedSolomon should always be correctly instantiated");

        Ok(Self {
            buffer: VecDeque::default(),
            record_size,
            segment_size,
            reed_solomon,
            segment_index: 0,
            prev_root_block_hash: Sha256Hash::default(),
            last_archived_block: INITIAL_LAST_ARCHIVED_BLOCK,
            state_marker: PhantomData::default(),
        })
    }

    /// Try to slice buffer contents into segments if there is enough data, producing one segment at
    /// a time
    fn produce_segment(&mut self) -> Option<Segment> {
        let mut segment = Segment::V0 {
            items: Vec::with_capacity(self.buffer.len()),
        };

        let mut last_archived_block = self.last_archived_block;

        // `-2` because even the smallest segment item will take 2 bytes to encode, so it makes
        // sense to stop earlier here
        while segment.encoded_size() < (self.segment_size - 2) {
            let segment_item = match self.buffer.pop_front() {
                Some(segment_item) => segment_item,
                None => {
                    let Segment::V0 { items } = segment;
                    // Push all of the items back into the buffer, we don't have enough data yet
                    for segment_item in items.into_iter().rev() {
                        self.buffer.push_front(segment_item);
                    }

                    return None;
                }
            };

            // Push segment item into the segment temporarily to measure encoded size of resulting
            // segment
            segment.push_item(segment_item);
            let encoded_segment_length = segment.encoded_size();
            // Pop segment item back from segment
            let segment_item = segment.pop_item().unwrap();

            // Check if there would be enough data collected with above segment item inserted
            if encoded_segment_length >= self.segment_size {
                // Check if there is an excess of data that should be spilled over into the next
                // segment
                let spill_over = encoded_segment_length - self.segment_size;

                // Due to compact vector length encoding in scale codec, spill over might happen to
                // be the same or even bigger than the inserted segment item bytes, in which case
                // last segment item insertion needs to be skipped to avoid out of range panic when
                // trying to cut segment item internal bytes.
                let inner_bytes_size = match &segment_item {
                    SegmentItem::Object(bytes) => bytes.len(),
                    SegmentItem::ObjectStart(_) => {
                        unreachable!("Buffer never contains SegmentItem::ObjectStart; qed");
                    }
                    SegmentItem::ObjectContinuation(bytes) => bytes.len(),
                    SegmentItem::Block { bytes, .. } => bytes.len(),
                    SegmentItem::BlockStart { .. } => {
                        unreachable!("Buffer never contains SegmentItem::BlockStart; qed");
                    }
                    SegmentItem::BlockContinuation { bytes, .. } => bytes.len(),
                    SegmentItem::RootBlock(_) => {
                        unreachable!(
                            "SegmentItem::RootBlock is always the first element in the buffer and \
                            fits into the segment; qed",
                        );
                    }
                };

                if spill_over > inner_bytes_size {
                    self.buffer.push_front(segment_item);
                    break;
                }
            }

            match &segment_item {
                SegmentItem::Object(_)
                | SegmentItem::ObjectStart(_)
                | SegmentItem::ObjectContinuation(_) => {
                    // We are not interested in object here
                }
                SegmentItem::Block { .. } => {
                    // Skip block number increase in case of the very first block
                    if last_archived_block != INITIAL_LAST_ARCHIVED_BLOCK {
                        // Increase archived block number and assume the whole block was
                        // archived
                        last_archived_block.number += 1;
                    }
                    last_archived_block.bytes = None;
                }
                SegmentItem::BlockStart { .. } => {
                    unreachable!("Buffer never contains SegmentItem::BlockStart; qed");
                }
                SegmentItem::BlockContinuation { bytes, .. } => {
                    // Same block, but assume for now that the whole block was archived, but
                    // also store the number of bytes as opposed to `None`, we'll transform
                    // it into `None` if needed later
                    let archived_bytes = last_archived_block.bytes.expect(
                        "Block continuation implies that there are some bytes \
                                archived already; qed",
                    );
                    last_archived_block.bytes.replace(
                        archived_bytes
                            + u32::try_from(bytes.len())
                                .expect("Blocks length is never bigger than u32; qed"),
                    );
                }
                SegmentItem::RootBlock(_) => {
                    // We are not interested in root block here
                }
            }

            segment.push_item(segment_item);
        }

        // Check if there is an excess of data that should be spilled over into the next segment
        let segment_encoded_length = segment.encoded_size();
        let spill_over = segment_encoded_length
            .checked_sub(self.segment_size)
            .unwrap_or_default();

        if spill_over > 0 {
            let Segment::V0 { items } = &mut segment;
            let segment_item = items
                .pop()
                .expect("Segment over segment size always has at least one item; qed");

            let segment_item = match segment_item {
                SegmentItem::Object(mut bytes) => {
                    let split_point = bytes.len() - spill_over;
                    let continuation_bytes = bytes[split_point..].to_vec();

                    bytes.truncate(split_point);

                    // Push continuation element back into the buffer where removed segment item was
                    self.buffer
                        .push_front(SegmentItem::ObjectContinuation(continuation_bytes));

                    SegmentItem::ObjectStart(bytes)
                }
                SegmentItem::ObjectStart(_) => {
                    unreachable!("Buffer never contains SegmentItem::ObjectStart; qed");
                }
                SegmentItem::ObjectContinuation(mut bytes) => {
                    let split_point = bytes.len() - spill_over;
                    let continuation_bytes = bytes[split_point..].to_vec();

                    bytes.truncate(split_point);

                    // Push continuation element back into the buffer where removed segment item was
                    self.buffer
                        .push_front(SegmentItem::ObjectContinuation(continuation_bytes));

                    SegmentItem::ObjectContinuation(bytes)
                }
                SegmentItem::Block { mut bytes, .. } => {
                    let split_point = bytes.len() - spill_over;
                    let continuation_bytes = bytes[split_point..].to_vec();

                    bytes.truncate(split_point);

                    // Update last archived block to include partial archiving info
                    last_archived_block.bytes.replace(
                        u32::try_from(bytes.len())
                            .expect("Blocks length is never bigger than u32; qed"),
                    );

                    // Push continuation element back into the buffer where removed segment item was
                    self.buffer.push_front(SegmentItem::BlockContinuation {
                        bytes: continuation_bytes,
                        object_mapping: Default::default(),
                    });

                    SegmentItem::BlockStart {
                        bytes,
                        object_mapping: Default::default(),
                    }
                }
                SegmentItem::BlockStart { .. } => {
                    unreachable!("Buffer never contains SegmentItem::BlockStart; qed");
                }
                SegmentItem::BlockContinuation { mut bytes, .. } => {
                    let split_point = bytes.len() - spill_over;
                    let continuation_bytes = bytes[split_point..].to_vec();

                    bytes.truncate(split_point);

                    // Above code assumed that block was archived fully, now remove spilled-over
                    // bytes from the size
                    let archived_bytes = last_archived_block.bytes.expect(
                        "Block continuation implies that there are some bytes archived \
                        already; qed",
                    );
                    last_archived_block.bytes.replace(
                        archived_bytes
                            - u32::try_from(spill_over)
                                .expect("Blocks length is never bigger than u32; qed"),
                    );

                    // Push continuation element back into the buffer where removed segment item was
                    self.buffer.push_front(SegmentItem::BlockContinuation {
                        bytes: continuation_bytes,
                        object_mapping: Default::default(),
                    });

                    SegmentItem::BlockContinuation {
                        bytes,
                        object_mapping: Default::default(),
                    }
                }
                SegmentItem::RootBlock(_) => {
                    unreachable!(
                        "SegmentItem::RootBlock is always the first element in the buffer and \
                        fits into the segment; qed",
                    );
                }
            };

            // Push back shortened segment item
            items.push(segment_item);
        } else {
            // Above code added bytes length even though it was assumed that all continuation bytes
            // fit into the segment, now we need to tweak that
            last_archived_block.bytes.take();
        }

        self.last_archived_block = last_archived_block;

        Some(segment)
    }

    // Take segment as an input, apply necessary transformations and produce archived segment
    fn produce_archived_segment(&mut self, segment: Segment) -> ArchivedSegment {
        let segment = {
            let mut segment = segment.encode();
            // Add a few bytes of padding if needed to get constant size (caused by compact length
            // encoding of scale codec)
            assert!(self.segment_size >= segment.len());
            segment.resize(self.segment_size, 0u8);
            segment
        };

        fn slice_to_arrays(slice: &[u8]) -> Vec<[u8; 2]> {
            slice
                .chunks_exact(2)
                .map(|s| s.try_into().unwrap())
                .collect()
        }

        let data_shards: Vec<Vec<[u8; 2]>> = segment
            .chunks_exact(self.record_size)
            .map(slice_to_arrays)
            .collect();

        drop(segment);

        let mut parity_shards: Vec<Vec<[u8; 2]>> =
            iter::repeat(vec![[0u8; 2]; self.record_size / 2])
                .take(data_shards.len())
                .collect();

        // Apply erasure coding to to create parity shards/records
        self.reed_solomon
            .encode_sep(&data_shards, &mut parity_shards)
            .expect("Encoding is running with fixed parameters and should never fail");

        // Combine data and parity records back into vectors for further processing
        let records: Vec<Vec<u8>> = data_shards
            .into_iter()
            .chain(parity_shards)
            .map(|shard| {
                let mut record = Vec::with_capacity(self.record_size);

                for chunk in shard {
                    record.extend_from_slice(&chunk);
                }

                record
            })
            .collect();

        // Build a Merkle tree over data and parity records
        let merkle_tree = MerkleTree::from_data(records.iter());

        // Take records, combine them with witnesses (Merkle proofs) to produce data and parity
        // pieces
        let pieces: Vec<Piece> = records
            .into_iter()
            .enumerate()
            .map(|(position, record)| {
                let witness = merkle_tree
                    .get_witness(position)
                    .expect("We use the same indexes as during Merkle tree creation; qed");
                let mut piece: Piece = [0u8; PIECE_SIZE];

                piece.as_mut().write_all(&record).expect(
                    "With correct archiver parameters record is always smaller than \
                    piece size; qed",
                );
                drop(record);

                (&mut piece[self.record_size..]).write_all(&witness).expect(
                    "Parameters are verified in the archiver constructor to make sure this \
                    never happens; qed",
                );

                piece
            })
            .collect();

        let segment_index = self.segment_index;
        let merkle_tree_root = merkle_tree.root();

        // Now produce root block
        let root_block = RootBlock::V0 {
            segment_index,
            merkle_tree_root,
            prev_root_block_hash: self.prev_root_block_hash,
            last_archived_block: self.last_archived_block,
        };

        let root_block_hash = root_block.hash();

        // Update state
        self.segment_index = segment_index + 1;
        self.prev_root_block_hash = root_block_hash;

        // Add root block to the beginning of the buffer to be the first thing included in the next
        // segment
        self.buffer.push_front(SegmentItem::RootBlock(root_block));

        ArchivedSegment { root_block, pieces }
    }
}

impl ObjectArchiver {
    /// Adds new object to internal buffer, potentially producing pieces and root block headers
    pub fn add_object(&mut self, object: Vec<u8>) -> Vec<ArchivedSegment> {
        // Append new block to the buffer
        self.buffer.push_back(SegmentItem::Object(object));

        let mut archived_segments = Vec::new();

        while let Some(segment) = self.produce_segment() {
            archived_segments.push(self.produce_archived_segment(segment));
        }

        archived_segments
    }

    pub fn into_block_archiver(self) -> BlockArchiver {
        let Self {
            buffer,
            record_size,
            segment_size,
            reed_solomon,
            segment_index,
            prev_root_block_hash,
            last_archived_block,
            ..
        } = self;

        Archiver {
            buffer,
            record_size,
            segment_size,
            reed_solomon,
            segment_index,
            prev_root_block_hash,
            last_archived_block,
            state_marker: PhantomData::default(),
        }
    }
}

impl BlockArchiver {
    /// Create a new instance of block archiver with initial state in case of restart.
    ///
    /// `block` corresponds to `last_archived_block` and will be processed accordingly to its state.
    pub fn with_initial_state<B: AsRef<[u8]>>(
        record_size: usize,
        segment_size: usize,
        root_block: RootBlock,
        encoded_block: B,
        object_mapping: BlockObjectMapping,
    ) -> Result<Self, ArchiverInstantiationError> {
        if root_block.last_archived_block() == INITIAL_LAST_ARCHIVED_BLOCK {
            return Err(ArchiverInstantiationError::NoBlocksInvalidInitialState);
        }

        let mut archiver = Self::new(record_size, segment_size)?;

        archiver.segment_index = root_block.segment_index() + 1;
        archiver.prev_root_block_hash = root_block.hash();
        archiver.last_archived_block = root_block.last_archived_block();

        // The first thing in the buffer should be root block
        archiver
            .buffer
            .push_back(SegmentItem::RootBlock(root_block));

        if let Some(archived_block_bytes) = archiver.last_archived_block.bytes {
            let encoded_block = encoded_block.as_ref();
            let encoded_block_bytes = u32::try_from(encoded_block.len())
                .expect("Blocks length is never bigger than u32; qed");

            match encoded_block_bytes.cmp(&archived_block_bytes) {
                Ordering::Less => {
                    return Err(ArchiverInstantiationError::InvalidBlockSmallSize {
                        block_bytes: encoded_block_bytes,
                        archived_block_bytes,
                    });
                }
                Ordering::Equal => {
                    return Err(ArchiverInstantiationError::InvalidLastArchivedBlock(
                        encoded_block_bytes,
                    ));
                }
                Ordering::Greater => {
                    // Take part of the encoded block that wasn't archived yet and push to the
                    // buffer and block continuation
                    archiver.buffer.push_back(SegmentItem::BlockContinuation {
                        bytes: encoded_block[(archived_block_bytes as usize)..].to_vec(),
                        object_mapping,
                    });
                }
            }
        }

        Ok(archiver)
    }

    /// Get last archived block if there was any
    pub fn last_archived_block_number(&self) -> Option<u32> {
        if self.last_archived_block != INITIAL_LAST_ARCHIVED_BLOCK {
            Some(self.last_archived_block.number)
        } else {
            None
        }
    }

    /// Adds new block to internal buffer, potentially producing pieces and root block headers
    pub fn add_block(
        &mut self,
        block: Vec<u8>,
        object_mapping: BlockObjectMapping,
    ) -> Vec<ArchivedSegment> {
        // Append new block to the buffer
        self.buffer.push_back(SegmentItem::Block {
            bytes: block,
            object_mapping,
        });

        let mut archived_segments = Vec::new();

        while let Some(segment) = self.produce_segment() {
            archived_segments.push(self.produce_archived_segment(segment));
        }

        archived_segments
    }
}

/// Validate witness embedded within a piece produced by archiver
pub fn is_piece_valid(piece: &[u8], root: Sha256Hash, position: usize, record_size: usize) -> bool {
    let witness = match Witness::new(Cow::Borrowed(&piece[record_size..])) {
        Ok(witness) => witness,
        Err(_) => {
            return false;
        }
    };
    let leaf_hash = crypto::sha256_hash(&piece[..record_size]);

    witness.is_valid(root, position, leaf_hash)
}
