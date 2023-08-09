use crate::auditing::ChunkCandidate;
use crate::reading::{read_record_metadata, read_sector_record_chunks, ReadingError};
use crate::sector::{
    SectorContentsMap, SectorContentsMapFromBytesError, SectorMetadataChecksummed,
};
use std::collections::VecDeque;
use subspace_core_primitives::crypto::kzg::{Commitment, Kzg, Witness};
use subspace_core_primitives::crypto::Scalar;
use subspace_core_primitives::{
    PieceOffset, PosProof, PublicKey, Record, SBucket, SectorId, SectorIndex, Solution,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_proof_of_space::{Quality, Table, TableGenerator};
use thiserror::Error;

/// Errors that happen during proving
#[derive(Debug, Error)]
pub enum ProvingError {
    /// Invalid erasure coding instance
    #[error("Invalid erasure coding instance")]
    InvalidErasureCodingInstance,
    /// Failed to create polynomial for record
    #[error("Failed to create polynomial for record at offset {piece_offset}: {error}")]
    FailedToCreatePolynomialForRecord {
        /// Piece offset
        piece_offset: PieceOffset,
        /// Lower-level error
        error: String,
    },
    /// Failed to decode metadata for record
    #[error("Failed to decode metadata for record at offset {piece_offset}: {error}")]
    FailedToDecodeMetadataForRecord {
        /// Piece offset
        piece_offset: PieceOffset,
        /// Lower-level error
        error: String,
    },
    /// Failed to create chunk witness
    #[error(
        "Failed to create chunk witness for record at offset {piece_offset} chunk {chunk_offset}: \
        {error}"
    )]
    FailedToCreateChunkWitness {
        /// Piece offset
        piece_offset: PieceOffset,
        /// Chunk index
        chunk_offset: u32,
        /// Lower-level error
        error: String,
    },
    /// Failed to decode sector contents map
    #[error("Failed to decode sector contents map: {0}")]
    FailedToDecodeSectorContentsMap(#[from] SectorContentsMapFromBytesError),
    /// Record reading error
    #[error("Record reading error: {0}")]
    RecordReadingError(#[from] ReadingError),
}

#[derive(Debug, Clone)]
struct WinningChunk {
    /// Chunk offset within s-bucket
    chunk_offset: u32,
    /// Piece offset in a sector
    piece_offset: PieceOffset,
    /// Audit chunk offsets in above chunk
    audit_chunk_offsets: VecDeque<u8>,
}

/// Container for solutions
#[derive(Debug, Clone)]
pub struct SolutionCandidates<'a> {
    public_key: &'a PublicKey,
    sector_index: SectorIndex,
    sector_id: SectorId,
    s_bucket: SBucket,
    sector: &'a [u8],
    sector_metadata: &'a SectorMetadataChecksummed,
    chunk_candidates: VecDeque<ChunkCandidate>,
}

impl<'a> SolutionCandidates<'a> {
    pub(crate) fn new(
        public_key: &'a PublicKey,
        sector_index: SectorIndex,
        sector_id: SectorId,
        s_bucket: SBucket,
        sector: &'a [u8],
        sector_metadata: &'a SectorMetadataChecksummed,
        chunk_candidates: VecDeque<ChunkCandidate>,
    ) -> Self {
        Self {
            public_key,
            sector_index,
            sector_id,
            s_bucket,
            sector,
            sector_metadata,
            chunk_candidates,
        }
    }

    /// Total number of candidates
    pub fn len(&self) -> usize {
        self.chunk_candidates
            .iter()
            .map(|winning_chunk| winning_chunk.audit_chunk_offsets.len())
            .sum()
    }

    /// Returns true if no candidates inside
    pub fn is_empty(&self) -> bool {
        self.chunk_candidates.is_empty()
    }

    pub fn into_iter<RewardAddress, PosTable>(
        self,
        reward_address: &'a RewardAddress,
        kzg: &'a Kzg,
        erasure_coding: &'a ErasureCoding,
        table_generator: &'a mut PosTable::Generator,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<Solution<PublicKey, RewardAddress>, ProvingError>> + 'a,
        ProvingError,
    >
    where
        RewardAddress: Copy,
        PosTable: Table,
    {
        SolutionCandidatesIterator::<'a, RewardAddress, PosTable>::new(
            self.public_key,
            reward_address,
            self.sector_index,
            self.sector_id,
            self.s_bucket,
            self.sector,
            self.sector_metadata,
            kzg,
            erasure_coding,
            self.chunk_candidates,
            table_generator,
        )
    }
}

struct ChunkCache {
    chunk: Scalar,
    chunk_offset: u32,
    record_commitment: Commitment,
    record_witness: Witness,
    chunk_witness: Witness,
    proof_of_space: PosProof,
}

struct SolutionCandidatesIterator<'a, RewardAddress, PosTable>
where
    PosTable: Table,
{
    public_key: &'a PublicKey,
    reward_address: &'a RewardAddress,
    sector_index: SectorIndex,
    sector_id: SectorId,
    s_bucket: SBucket,
    sector_metadata: &'a SectorMetadataChecksummed,
    s_bucket_offsets: Box<[u32; Record::NUM_S_BUCKETS]>,
    kzg: &'a Kzg,
    erasure_coding: &'a ErasureCoding,
    sector_contents_map: SectorContentsMap,
    sector: &'a [u8],
    winning_chunks: VecDeque<WinningChunk>,
    count: usize,
    chunk_cache: Option<ChunkCache>,
    table_generator: &'a mut PosTable::Generator,
}

// TODO: This can be potentially parallelized with rayon
impl<RewardAddress, PosTable> Iterator for SolutionCandidatesIterator<'_, RewardAddress, PosTable>
where
    RewardAddress: Copy,
    PosTable: Table,
{
    type Item = Result<Solution<PublicKey, RewardAddress>, ProvingError>;

    fn next(&mut self) -> Option<Self::Item> {
        let (chunk_offset, piece_offset, audit_chunk_offset) = {
            let winning_chunk = self.winning_chunks.front_mut()?;

            let audit_chunk_offset = winning_chunk.audit_chunk_offsets.pop_front()?;
            let chunk_offset = winning_chunk.chunk_offset;
            let piece_offset = winning_chunk.piece_offset;

            if winning_chunk.audit_chunk_offsets.is_empty() {
                // When all audit chunk offsets are removed, the winning chunks entry itself can be removed
                self.winning_chunks.pop_front();
            }

            (chunk_offset, piece_offset, audit_chunk_offset)
        };

        self.count -= 1;

        let chunk_cache = 'outer: {
            if let Some(chunk_cache) = &self.chunk_cache {
                if chunk_cache.chunk_offset == chunk_offset {
                    break 'outer chunk_cache;
                }
            }

            // Derive PoSpace table
            let pos_table = self.table_generator.generate_parallel(
                &self
                    .sector_id
                    .derive_evaluation_seed(piece_offset, self.sector_metadata.history_size),
            );

            let maybe_chunk_cache: Result<_, ProvingError> =
                try {
                    let sector_record_chunks = read_sector_record_chunks(
                        piece_offset,
                        self.sector_metadata.pieces_in_sector,
                        &self.s_bucket_offsets,
                        &self.sector_contents_map,
                        &pos_table,
                        self.sector,
                    )?;

                    let chunk = sector_record_chunks
                        .get(usize::from(self.s_bucket))
                        .expect("Within s-bucket range; qed")
                        .expect("Winning chunk was plotted; qed");

                    let source_chunks_polynomial = self
                        .erasure_coding
                        .recover_poly(sector_record_chunks.as_slice())
                        .map_err(|error| ReadingError::FailedToErasureDecodeRecord {
                            piece_offset,
                            error,
                        })?;
                    drop(sector_record_chunks);

                    // NOTE: We do not check plot consistency using checksum because it is more
                    // expensive and consensus will verify validity of the proof anyway
                    let record_metadata = read_record_metadata(
                        piece_offset,
                        self.sector_metadata.pieces_in_sector,
                        self.sector,
                    )?;

                    let record_commitment = Commitment::try_from_bytes(&record_metadata.commitment)
                        .map_err(|error| ProvingError::FailedToDecodeMetadataForRecord {
                            piece_offset,
                            error,
                        })?;
                    let record_witness = Witness::try_from_bytes(&record_metadata.witness)
                        .map_err(|error| ProvingError::FailedToDecodeMetadataForRecord {
                            piece_offset,
                            error,
                        })?;

                    let proof_of_space = pos_table
                        .find_quality(self.s_bucket.into())
                        .expect(
                            "Quality exists for this s-bucket, otherwise it wouldn't be a \
                            winning chunk; qed",
                        )
                        .create_proof();

                    let chunk_witness = self
                        .kzg
                        .create_witness(
                            &source_chunks_polynomial,
                            Record::NUM_S_BUCKETS,
                            self.s_bucket.into(),
                        )
                        .map_err(|error| ProvingError::FailedToCreateChunkWitness {
                            piece_offset,
                            chunk_offset,
                            error,
                        })?;

                    ChunkCache {
                        chunk,
                        chunk_offset,
                        record_commitment,
                        record_witness,
                        chunk_witness,
                        proof_of_space,
                    }
                };

            let chunk_cache = match maybe_chunk_cache {
                Ok(chunk_cache) => chunk_cache,
                Err(error) => {
                    if let Some(winning_chunk) = self.winning_chunks.front() {
                        if winning_chunk.chunk_offset == chunk_offset {
                            // Subsequent attempts to generate solutions for this chunk offset will
                            // fail too, remove it so save potential computation
                            self.count -= winning_chunk.audit_chunk_offsets.len();
                            self.winning_chunks.pop_front();
                        }
                    }

                    return Some(Err(error));
                }
            };

            self.chunk_cache.insert(chunk_cache)
        };

        Some(Ok(Solution {
            public_key: *self.public_key,
            reward_address: *self.reward_address,
            sector_index: self.sector_index,
            history_size: self.sector_metadata.history_size,
            piece_offset,
            record_commitment: chunk_cache.record_commitment,
            record_witness: chunk_cache.record_witness,
            chunk: chunk_cache.chunk,
            chunk_witness: chunk_cache.chunk_witness,
            audit_chunk_offset,
            proof_of_space: chunk_cache.proof_of_space,
        }))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.count, Some(self.count))
    }

    fn count(self) -> usize
    where
        Self: Sized,
    {
        self.count
    }
}

impl<RewardAddress, PosTable> ExactSizeIterator
    for SolutionCandidatesIterator<'_, RewardAddress, PosTable>
where
    RewardAddress: Copy,
    PosTable: Table,
{
}

impl<'a, RewardAddress, PosTable> SolutionCandidatesIterator<'a, RewardAddress, PosTable>
where
    PosTable: Table,
{
    #[allow(clippy::too_many_arguments)]
    fn new(
        public_key: &'a PublicKey,
        reward_address: &'a RewardAddress,
        sector_index: SectorIndex,
        sector_id: SectorId,
        s_bucket: SBucket,
        sector: &'a [u8],
        sector_metadata: &'a SectorMetadataChecksummed,
        kzg: &'a Kzg,
        erasure_coding: &'a ErasureCoding,
        chunk_candidates: VecDeque<ChunkCandidate>,
        table_generator: &'a mut PosTable::Generator,
    ) -> Result<Self, ProvingError> {
        if erasure_coding.max_shards() < Record::NUM_S_BUCKETS {
            return Err(ProvingError::InvalidErasureCodingInstance);
        }

        let sector_contents_map = {
            SectorContentsMap::from_bytes(
                &sector[..SectorContentsMap::encoded_size(sector_metadata.pieces_in_sector)],
                sector_metadata.pieces_in_sector,
            )?
        };

        let mut s_bucket_records = (0u32..)
            .zip(
                sector_contents_map
                    .iter_s_bucket_records(s_bucket)
                    .expect("S-bucket audit index is guaranteed to be in range; qed"),
            )
            .take(sector_metadata.pieces_in_sector.into());
        let winning_chunks = chunk_candidates
            .into_iter()
            .filter_map(move |chunk_candidate| loop {
                let (chunk_offset, (piece_offset, encoded_chunk_used)) = s_bucket_records
                    .next()
                    .expect("Chunk candidates are within s-bucket records; qed");

                // Not all chunks are within solution range, skip irrelevant chunk offsets until
                // desired one is found
                if chunk_offset == chunk_candidate.chunk_offset {
                    return encoded_chunk_used.then_some(WinningChunk {
                        chunk_offset,
                        piece_offset,
                        audit_chunk_offsets: chunk_candidate.audit_chunk_offsets,
                    });
                }
            })
            .collect::<VecDeque<_>>();

        let count = winning_chunks
            .iter()
            .map(|winning_chunk| winning_chunk.audit_chunk_offsets.len())
            .sum();

        let s_bucket_offsets = sector_metadata.s_bucket_offsets();

        Ok(Self {
            public_key,
            reward_address,
            sector_index,
            sector_id,
            s_bucket,
            sector_metadata,
            s_bucket_offsets,
            kzg,
            erasure_coding,
            sector_contents_map,
            sector,
            winning_chunks,
            count,
            chunk_cache: None,
            table_generator,
        })
    }
}
