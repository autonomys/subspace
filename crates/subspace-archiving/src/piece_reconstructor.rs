#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use subspace_core_primitives::crypto::kzg::{Commitment, Kzg, Polynomial};
use subspace_core_primitives::crypto::{blake3_254_hash_to_scalar, Scalar};
use subspace_core_primitives::pieces::{Piece, RawRecord};
use subspace_core_primitives::segments::ArchivedHistorySegment;
use subspace_erasure_coding::ErasureCoding;

/// Reconstructor-related instantiation error
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum ReconstructorError {
    /// Segment size is not bigger than record size
    #[cfg_attr(
        feature = "thiserror",
        error("Error during data shards reconstruction: {0}")
    )]
    DataShardsReconstruction(String),

    /// Commitment of input piece is invalid.
    #[cfg_attr(feature = "thiserror", error("Commitment of input piece is invalid."))]
    InvalidInputPieceCommitment,

    /// Incorrect piece position provided.
    #[cfg_attr(feature = "thiserror", error("Incorrect piece position provided."))]
    IncorrectPiecePosition,
}

/// Reconstructor helps to retrieve blocks from archived pieces.
#[derive(Debug, Clone)]
pub struct PiecesReconstructor {
    /// Erasure coding data structure
    erasure_coding: ErasureCoding,
    /// KZG instance
    kzg: Kzg,
}

impl PiecesReconstructor {
    /// Create a new instance
    pub fn new(kzg: Kzg, erasure_coding: ErasureCoding) -> Self {
        Self {
            erasure_coding,
            kzg,
        }
    }

    /// Returns incomplete pieces (witness missing) and polynomial that can be used to generate
    /// necessary witnesses later.
    fn reconstruct_shards(
        &self,
        input_pieces: &[Option<Piece>],
    ) -> Result<(ArchivedHistorySegment, Polynomial), ReconstructorError> {
        let mut reconstructed_pieces = ArchivedHistorySegment::default();

        // Scratch buffer to avoid re-allocation
        let mut tmp_shards_scalars =
            Vec::<Option<Scalar>>::with_capacity(ArchivedHistorySegment::NUM_PIECES);
        // Iterate over the chunks of `Scalar::SAFE_BYTES` bytes of all records
        for record_offset in 0..RawRecord::NUM_CHUNKS {
            // Collect chunks of each record at the same offset
            for maybe_piece in input_pieces.iter() {
                let maybe_scalar = maybe_piece
                    .as_ref()
                    .map(|piece| {
                        piece
                            .record()
                            .get(record_offset)
                            .expect("Statically guaranteed to exist in a piece; qed")
                    })
                    .map(Scalar::try_from)
                    .transpose()
                    .map_err(ReconstructorError::DataShardsReconstruction)?;

                tmp_shards_scalars.push(maybe_scalar);
            }

            self.erasure_coding
                .recover(&tmp_shards_scalars)
                .map_err(ReconstructorError::DataShardsReconstruction)?
                .into_iter()
                .zip(reconstructed_pieces.iter_mut().map(|piece| {
                    piece
                        .record_mut()
                        .get_mut(record_offset)
                        .expect("Statically guaranteed to exist in a piece; qed")
                }))
                .for_each(|(source_scalar, segment_data)| {
                    segment_data.copy_from_slice(&source_scalar.to_bytes());
                });

            tmp_shards_scalars.clear();
        }

        let source_record_commitments = {
            #[cfg(not(feature = "parallel"))]
            let iter = reconstructed_pieces.iter_mut().zip(input_pieces).step_by(2);
            #[cfg(feature = "parallel")]
            let iter = reconstructed_pieces
                .par_iter_mut()
                .zip_eq(input_pieces)
                .step_by(2);

            iter.map(|(piece, maybe_input_piece)| {
                if let Some(input_piece) = maybe_input_piece {
                    Commitment::try_from_bytes(input_piece.commitment())
                        .map_err(|_error| ReconstructorError::InvalidInputPieceCommitment)
                } else {
                    let scalars = {
                        let mut scalars =
                            Vec::with_capacity(piece.record().len().next_power_of_two());

                        for record_chunk in piece.record().iter() {
                            scalars.push(
                                Scalar::try_from(record_chunk)
                                    .map_err(ReconstructorError::DataShardsReconstruction)?,
                            );
                        }

                        // Number of scalars for KZG must be a power of two elements
                        scalars.resize(scalars.capacity(), Scalar::default());

                        scalars
                    };

                    let polynomial = self.kzg.poly(&scalars).expect(
                        "KZG instance must be configured to support this many scalars; qed",
                    );
                    let commitment = self.kzg.commit(&polynomial).expect(
                        "KZG instance must be configured to support this many scalars; qed",
                    );

                    Ok(commitment)
                }
            })
            .collect::<Result<Vec<_>, _>>()?
        };
        let record_commitments = self
            .erasure_coding
            .extend_commitments(&source_record_commitments)
            .expect(
                "Erasure coding instance is deliberately configured to support this input; qed",
            );
        drop(source_record_commitments);

        let record_commitment_hashes = reconstructed_pieces
            .iter_mut()
            .zip(record_commitments)
            .map(|(reconstructed_piece, commitment)| {
                let commitment_bytes = commitment.to_bytes();
                reconstructed_piece
                    .commitment_mut()
                    .copy_from_slice(&commitment_bytes);
                blake3_254_hash_to_scalar(&commitment_bytes)
            })
            .collect::<Vec<_>>();

        let polynomial = self
            .kzg
            .poly(&record_commitment_hashes)
            .expect("Internally produced values must never fail; qed");

        Ok((reconstructed_pieces, polynomial))
    }

    /// Returns all the pieces for a segment using given set of pieces of a segment of the archived
    /// history (any half of all pieces are required to be present, the rest will be recovered
    /// automatically due to use of erasure coding if needed).
    pub fn reconstruct_segment(
        &self,
        segment_pieces: &[Option<Piece>],
    ) -> Result<ArchivedHistorySegment, ReconstructorError> {
        let (mut pieces, polynomial) = self.reconstruct_shards(segment_pieces)?;

        #[cfg(not(feature = "parallel"))]
        let iter = pieces.iter_mut().enumerate();
        #[cfg(feature = "parallel")]
        let iter = pieces.par_iter_mut().enumerate();

        iter.for_each(|(position, piece)| {
            piece.witness_mut().copy_from_slice(
                &self
                    .kzg
                    .create_witness(
                        &polynomial,
                        ArchivedHistorySegment::NUM_PIECES,
                        position as u32,
                    )
                    .expect("Position is statically known to be valid; qed")
                    .to_bytes(),
            );
        });

        Ok(pieces.to_shared())
    }

    /// Returns the missing piece for a segment using given set of pieces of a segment of the archived
    /// history (any half of all pieces are required to be present).
    pub fn reconstruct_piece(
        &self,
        segment_pieces: &[Option<Piece>],
        piece_position: usize,
    ) -> Result<Piece, ReconstructorError> {
        if piece_position >= ArchivedHistorySegment::NUM_PIECES {
            return Err(ReconstructorError::IncorrectPiecePosition);
        }

        let (reconstructed_records, polynomial) = self.reconstruct_shards(segment_pieces)?;

        let mut piece = Piece::from(&reconstructed_records[piece_position]);

        piece.witness_mut().copy_from_slice(
            &self
                .kzg
                .create_witness(
                    &polynomial,
                    ArchivedHistorySegment::NUM_PIECES,
                    piece_position as u32,
                )
                .expect("Position is verified to be valid above; qed")
                .to_bytes(),
        );

        Ok(piece.to_shared())
    }
}
