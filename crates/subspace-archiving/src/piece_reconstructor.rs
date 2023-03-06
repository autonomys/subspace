extern crate alloc;

use crate::utils;
use alloc::vec::Vec;
use reed_solomon_erasure::galois_16::ReedSolomon;
use subspace_core_primitives::crypto::blake2b_256_254_hash;
use subspace_core_primitives::crypto::kzg::{Kzg, Polynomial};
use subspace_core_primitives::{
    FlatPieces, Piece, BLAKE2B_256_HASH_SIZE, PIECES_IN_SEGMENT, PIECE_SIZE,
};

/// Reconstructor-related instantiation error.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum ReconstructorInstantiationError {
    /// Segment size is not bigger than record size
    #[cfg_attr(
        feature = "thiserror",
        error("Segment size is not bigger than record size")
    )]
    SegmentSizeTooSmall,
    /// Segment size is not a multiple of record size
    #[cfg_attr(
        feature = "thiserror",
        error("Segment size is not a multiple of record size")
    )]
    SegmentSizesNotMultipleOfRecordSize,
}

/// Reconstructor-related instantiation error
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum ReconstructorError {
    /// Segment size is not bigger than record size
    #[cfg_attr(
        feature = "thiserror",
        error("Error during data shards reconstruction: {0}")
    )]
    DataShardsReconstruction(reed_solomon_erasure::Error),

    /// Incorrect piece position provided.
    #[cfg_attr(feature = "thiserror", error("Incorrect piece position provided."))]
    IncorrectPiecePosition,
}

/// Reconstructor helps to retrieve blocks from archived pieces.
#[derive(Debug, Clone)]
pub struct PiecesReconstructor {
    /// Configuration parameter defining the size of one record (data in one piece excluding witness
    /// size)
    record_size: u32,
    /// Configuration parameter defining the size of one recorded history segment
    segment_size: u32,
    /// Erasure coding data structure
    reed_solomon: ReedSolomon,
    /// KZG instance
    kzg: Kzg,
}

impl PiecesReconstructor {
    fn shards_count(segment_size: u32, record_size: u32) -> u32 {
        segment_size / record_size
    }

    fn data_shards(&self) -> u32 {
        Self::shards_count(self.segment_size, self.record_size)
    }

    fn parity_shards(&self) -> u32 {
        self.data_shards()
    }

    pub fn new(
        record_size: u32,
        segment_size: u32,
        kzg: Kzg,
    ) -> Result<Self, ReconstructorInstantiationError> {
        if segment_size <= record_size {
            return Err(ReconstructorInstantiationError::SegmentSizeTooSmall);
        }
        if segment_size % record_size != 0 {
            return Err(ReconstructorInstantiationError::SegmentSizesNotMultipleOfRecordSize);
        }

        let data_shards = Self::shards_count(segment_size, record_size);
        let parity_shards = data_shards;
        let reed_solomon = ReedSolomon::new(data_shards as usize, parity_shards as usize)
            .expect("ReedSolomon must always be correctly instantiated");

        Ok(Self {
            record_size,
            segment_size,
            reed_solomon,
            kzg,
        })
    }

    fn reconstruct_shards(
        &self,
        segment_pieces: &[Option<Piece>],
    ) -> Result<(Vec<Vec<u8>>, Polynomial), ReconstructorError> {
        // If not all data pieces are available, need to reconstruct data shards using erasure
        // coding.
        let mut shards = segment_pieces
            .iter()
            .map(|maybe_piece| maybe_piece.as_ref().map(utils::slice_to_arrays))
            .collect::<Vec<_>>();

        self.reed_solomon
            .reconstruct(&mut shards)
            .map_err(ReconstructorError::DataShardsReconstruction)?;

        let reconstructed_record_shards = shards
            .iter()
            .map(|maybe_shard| {
                maybe_shard
                    .as_ref()
                    .map(|shard| {
                        let mut bytes = shard.iter().fold(
                            Vec::with_capacity(self.record_size as usize),
                            |mut acc, shard_part| {
                                acc.extend_from_slice(shard_part);

                                acc
                            },
                        );

                        bytes.truncate(self.record_size as usize);

                        bytes
                    })
                    .expect("Record must be reconstructed here.")
            })
            .collect::<Vec<_>>();

        //TODO: Parity hashes will be erasure coded instead in the future
        //TODO: reuse already present commitments from segment_pieces, so we don't re-derive what
        // we already have
        let record_shards_hashes = reconstructed_record_shards
            .iter()
            .map(|item| blake2b_256_254_hash(item))
            .collect::<Vec<_>>();

        let data = {
            let mut data = Vec::with_capacity(
                (self.data_shards() + self.parity_shards()) as usize * BLAKE2B_256_HASH_SIZE,
            );

            for shard in &record_shards_hashes {
                data.extend_from_slice(shard);
            }

            data
        };
        let polynomial = self
            .kzg
            .poly(&data)
            .expect("Internally produced values must never fail; qed");

        Ok((reconstructed_record_shards, polynomial))
    }

    /// Returns all the pieces for a segment using given set of pieces of a segment of the archived
    /// history (any half of all pieces are required to be present, the rest will be recovered
    /// automatically due to use of erasure coding if needed).
    pub fn reconstruct_segment(
        &self,
        segment_pieces: &[Option<Piece>],
    ) -> Result<FlatPieces, ReconstructorError> {
        let (reconstructed_record_shards, polynomial) = self.reconstruct_shards(segment_pieces)?;

        let mut pieces = FlatPieces::new(reconstructed_record_shards.len());
        pieces
            .as_pieces_mut()
            .enumerate()
            .zip(reconstructed_record_shards.iter())
            .for_each(|((position, piece), shard_chunk)| {
                let (record_part, witness_part) = piece.split_at_mut(self.record_size as usize);

                record_part.copy_from_slice(shard_chunk);
                witness_part.copy_from_slice(
                    &self
                        .kzg
                        .create_witness(&polynomial, position as u32)
                        .expect("We use the same indexes as during Merkle tree creation; qed")
                        .to_bytes(),
                );
            });

        Ok(pieces)
    }

    /// Returns the missing piece for a segment using given set of pieces of a segment of the archived
    /// history (any half of all pieces are required to be present).
    pub fn reconstruct_piece(
        &self,
        segment_pieces: &[Option<Piece>],
        piece_position: usize, // piece position within the segment (offset)
    ) -> Result<Piece, ReconstructorError> {
        let (reconstructed_records, polynomial) = self.reconstruct_shards(segment_pieces)?;

        if piece_position >= PIECES_IN_SEGMENT as usize {
            return Err(ReconstructorError::IncorrectPiecePosition);
        }

        let record_bytes = reconstructed_records
            .get(piece_position)
            .expect("We must have a reconstructed collection with the valid length here.");

        let mut piece = [0; PIECE_SIZE].to_vec();

        let (record_part, witness_part) = piece.split_at_mut(self.record_size as usize);

        record_part.copy_from_slice(record_bytes);
        witness_part.copy_from_slice(
            &self
                .kzg
                .create_witness(&polynomial, piece_position as u32)
                .expect("We use the same indexes as during Merkle tree creation; qed")
                .to_bytes(),
        );

        Ok(Piece::try_from(piece).expect("Piece size is set manually."))
    }
}
