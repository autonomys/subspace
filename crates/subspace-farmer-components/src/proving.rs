use crate::auditing::{AuditChunkCandidate, ChunkCandidate};
use crate::reading::{read_record_metadata, read_sector_record_chunks, ReadingError};
use crate::sector::{
    SectorContentsMap, SectorContentsMapFromBytesError, SectorMetadataChecksummed,
};
use crate::{ReadAt, ReadAtAsync, ReadAtSync};
use futures::Stream;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::crypto::Scalar;
use subspace_core_primitives::{
    ChunkWitness, PieceOffset, PosProof, PosSeed, PublicKey, Record, RecordCommitment,
    RecordWitness, SBucket, SectorId, Solution, SolutionRange,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_proof_of_space::{Quality, Table};
use thiserror::Error;

/// Solutions that can be proven if necessary.
///
/// NOTE: Even though this implements async stream, it will do blocking proof os space table
/// derivation and should be running on a dedicated thread.
pub trait ProvableSolutions: Stream {
    /// Best solution distance found, `None` in case there are no solutions
    fn best_solution_distance(&self) -> Option<SolutionRange>;

    /// Returns the exact remaining number of solutions
    fn len(&self) -> usize;

    /// Returns `true` if there are no solutions
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

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
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
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
    /// Audit chunk in above chunk
    audit_chunks: VecDeque<AuditChunkCandidate>,
}

/// Container for solution candidates.
#[derive(Debug)]
pub struct SolutionCandidates<'a, Sector>
where
    Sector: 'a,
{
    public_key: &'a PublicKey,
    sector_id: SectorId,
    s_bucket: SBucket,
    sector: Sector,
    sector_metadata: &'a SectorMetadataChecksummed,
    chunk_candidates: VecDeque<ChunkCandidate>,
}

impl<'a, Sector> Clone for SolutionCandidates<'a, Sector>
where
    Sector: Clone + 'a,
{
    fn clone(&self) -> Self {
        Self {
            public_key: self.public_key,
            sector_id: self.sector_id,
            s_bucket: self.s_bucket,
            sector: self.sector.clone(),
            sector_metadata: self.sector_metadata,
            chunk_candidates: self.chunk_candidates.clone(),
        }
    }
}

impl<'a, S, A> SolutionCandidates<'a, ReadAt<S, A>>
where
    S: ReadAtSync + 'a,
    A: ReadAtAsync + 'a,
{
    pub(crate) fn new(
        public_key: &'a PublicKey,
        sector_id: SectorId,
        s_bucket: SBucket,
        sector: ReadAt<S, A>,
        sector_metadata: &'a SectorMetadataChecksummed,
        chunk_candidates: VecDeque<ChunkCandidate>,
    ) -> Self {
        Self {
            public_key,
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
            .map(|winning_chunk| winning_chunk.audit_chunks.len())
            .sum()
    }

    /// Returns true if no candidates inside
    pub fn is_empty(&self) -> bool {
        self.chunk_candidates.is_empty()
    }

    /// Turn solution candidates into actual solutions
    pub async fn into_solutions<RewardAddress, PosTable, TableGenerator>(
        self,
        reward_address: &'a RewardAddress,
        kzg: &'a Kzg,
        erasure_coding: &'a ErasureCoding,
        table_generator: TableGenerator,
    ) -> Result<impl ProvableSolutions<Item = MaybeSolution<RewardAddress>> + 'a, ProvingError>
    where
        RewardAddress: Copy,
        PosTable: Table,
        TableGenerator: (FnMut(&PosSeed) -> PosTable) + 'a,
    {
        let solutions_iterator_fut =
            SolutionsIterator::<'a, RewardAddress>::new::<PosTable, TableGenerator, S, A>(
                self.public_key,
                reward_address,
                self.sector_id,
                self.s_bucket,
                self.sector,
                self.sector_metadata,
                kzg,
                erasure_coding,
                self.chunk_candidates,
                table_generator,
            );

        solutions_iterator_fut.await
    }
}

struct ChunkCache {
    chunk: Scalar,
    chunk_offset: u32,
    record_commitment: RecordCommitment,
    record_witness: RecordWitness,
    chunk_witness: ChunkWitness,
    proof_of_space: PosProof,
}

struct SolutionsIteratorState<'a, RewardAddress, PosTable, TableGenerator, Sector>
where
    Sector: 'a,
    PosTable: Table,
    TableGenerator: (FnMut(&PosSeed) -> PosTable) + 'a,
{
    public_key: &'a PublicKey,
    reward_address: &'a RewardAddress,
    sector_id: SectorId,
    s_bucket: SBucket,
    sector_metadata: &'a SectorMetadataChecksummed,
    s_bucket_offsets: Box<[u32; Record::NUM_S_BUCKETS]>,
    kzg: &'a Kzg,
    erasure_coding: &'a ErasureCoding,
    sector_contents_map: SectorContentsMap,
    sector: Sector,
    winning_chunks: VecDeque<WinningChunk>,
    count: Arc<AtomicUsize>,
    chunk_cache: Option<ChunkCache>,
    table_generator: TableGenerator,
}

type MaybeSolution<RewardAddress> = Result<Solution<PublicKey, RewardAddress>, ProvingError>;

#[pin_project::pin_project]
struct SolutionsIterator<'a, RewardAddress> {
    #[pin]
    stream: Pin<Box<dyn Stream<Item = MaybeSolution<RewardAddress>> + 'a>>,
    count: Arc<AtomicUsize>,
    best_solution_distance: Option<SolutionRange>,
}

impl<'a, RewardAddress> Stream for SolutionsIterator<'a, RewardAddress>
where
    RewardAddress: Copy,
{
    type Item = MaybeSolution<RewardAddress>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().stream.poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = self.count.load(Ordering::Acquire);
        (count, Some(count))
    }
}

impl<'a, RewardAddress> ProvableSolutions for SolutionsIterator<'a, RewardAddress>
where
    RewardAddress: Copy,
{
    fn best_solution_distance(&self) -> Option<SolutionRange> {
        self.best_solution_distance
    }

    fn len(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }
}

impl<'a, RewardAddress> SolutionsIterator<'a, RewardAddress>
where
    RewardAddress: Copy,
{
    #[allow(clippy::too_many_arguments)]
    async fn new<PosTable, TableGenerator, S, A>(
        public_key: &'a PublicKey,
        reward_address: &'a RewardAddress,
        sector_id: SectorId,
        s_bucket: SBucket,
        sector: ReadAt<S, A>,
        sector_metadata: &'a SectorMetadataChecksummed,
        kzg: &'a Kzg,
        erasure_coding: &'a ErasureCoding,
        chunk_candidates: VecDeque<ChunkCandidate>,
        table_generator: TableGenerator,
    ) -> Result<Self, ProvingError>
    where
        S: ReadAtSync + 'a,
        A: ReadAtAsync + 'a,
        PosTable: Table,
        TableGenerator: (FnMut(&PosSeed) -> PosTable) + 'a,
    {
        if erasure_coding.max_shards() < Record::NUM_S_BUCKETS {
            return Err(ProvingError::InvalidErasureCodingInstance);
        }

        let sector_contents_map = {
            let mut sector_contents_map_bytes =
                vec![0; SectorContentsMap::encoded_size(sector_metadata.pieces_in_sector)];

            match &sector {
                ReadAt::Sync(sector) => {
                    sector.read_at(&mut sector_contents_map_bytes, 0)?;
                }
                ReadAt::Async(sector) => {
                    sector_contents_map_bytes =
                        sector.read_at(sector_contents_map_bytes, 0).await?;
                }
            }

            SectorContentsMap::from_bytes(
                &sector_contents_map_bytes,
                sector_metadata.pieces_in_sector,
            )?
        };

        let s_bucket_records = sector_contents_map
            .iter_s_bucket_records(s_bucket)
            .expect("S-bucket audit index is guaranteed to be in range; qed")
            .collect::<Vec<_>>();
        let winning_chunks = chunk_candidates
            .into_iter()
            .filter_map(move |chunk_candidate| {
                let (piece_offset, encoded_chunk_used) = s_bucket_records
                    .get(chunk_candidate.chunk_offset as usize)
                    .expect("Wouldn't be a candidate if wasn't within s-bucket; qed");

                encoded_chunk_used.then_some(WinningChunk {
                    chunk_offset: chunk_candidate.chunk_offset,
                    piece_offset: *piece_offset,
                    audit_chunks: chunk_candidate.audit_chunks.into(),
                })
            })
            .collect::<VecDeque<_>>();

        let count = winning_chunks
            .iter()
            .map(|winning_chunk| winning_chunk.audit_chunks.len())
            .sum();

        let best_solution_distance = winning_chunks.front().and_then(|winning_chunk| {
            winning_chunk
                .audit_chunks
                .front()
                .map(|audit_chunk| audit_chunk.solution_distance)
        });

        let s_bucket_offsets = sector_metadata.s_bucket_offsets();

        let count = Arc::new(AtomicUsize::new(count));

        let state = SolutionsIteratorState {
            public_key,
            reward_address,
            sector_id,
            s_bucket,
            sector_metadata,
            s_bucket_offsets,
            kzg,
            erasure_coding,
            sector_contents_map,
            sector,
            winning_chunks,
            count: Arc::clone(&count),
            chunk_cache: None,
            table_generator,
        };

        let stream = futures::stream::unfold(state, solutions_iterator_next);

        Ok(Self {
            stream: Box::pin(stream),
            count,
            best_solution_distance,
        })
    }
}

async fn solutions_iterator_next<'a, RewardAddress, PosTable, TableGenerator, S, A>(
    mut state: SolutionsIteratorState<'a, RewardAddress, PosTable, TableGenerator, ReadAt<S, A>>,
) -> Option<(
    MaybeSolution<RewardAddress>,
    SolutionsIteratorState<'a, RewardAddress, PosTable, TableGenerator, ReadAt<S, A>>,
)>
where
    RewardAddress: Copy,
    PosTable: Table,
    TableGenerator: (FnMut(&PosSeed) -> PosTable) + 'a,
    S: ReadAtSync + 'a,
    A: ReadAtAsync + 'a,
{
    let (chunk_offset, piece_offset, audit_chunk_offset) = {
        let winning_chunk = state.winning_chunks.front_mut()?;

        let audit_chunk = winning_chunk.audit_chunks.pop_front()?;
        let chunk_offset = winning_chunk.chunk_offset;
        let piece_offset = winning_chunk.piece_offset;

        if winning_chunk.audit_chunks.is_empty() {
            // When all audit chunk offsets are removed, the winning chunks entry itself can be removed
            state.winning_chunks.pop_front();
        }

        (chunk_offset, piece_offset, audit_chunk.offset)
    };

    state.count.fetch_sub(1, Ordering::SeqCst);

    let chunk_cache = 'outer: {
        if let Some(chunk_cache) = &state.chunk_cache {
            if chunk_cache.chunk_offset == chunk_offset {
                break 'outer chunk_cache;
            }
        }

        // Derive PoSpace table
        let pos_table = (state.table_generator)(
            &state
                .sector_id
                .derive_evaluation_seed(piece_offset, state.sector_metadata.history_size),
        );

        let maybe_chunk_cache: Result<_, ProvingError> = try {
            let sector_record_chunks_fut = read_sector_record_chunks(
                piece_offset,
                state.sector_metadata.pieces_in_sector,
                &state.s_bucket_offsets,
                &state.sector_contents_map,
                &pos_table,
                &state.sector,
            );
            let sector_record_chunks = sector_record_chunks_fut.await?;

            let chunk = sector_record_chunks
                .get(usize::from(state.s_bucket))
                .expect("Within s-bucket range; qed")
                .expect("Winning chunk was plotted; qed");

            let source_chunks_polynomial = state
                .erasure_coding
                .recover_poly(sector_record_chunks.as_slice())
                .map_err(|error| ReadingError::FailedToErasureDecodeRecord {
                    piece_offset,
                    error,
                })?;
            drop(sector_record_chunks);

            // NOTE: We do not check plot consistency using checksum because it is more
            // expensive and consensus will verify validity of the proof anyway
            let record_metadata_fut = read_record_metadata(
                piece_offset,
                state.sector_metadata.pieces_in_sector,
                &state.sector,
            );
            let record_metadata = record_metadata_fut.await?;

            let proof_of_space = pos_table
                .find_quality(state.s_bucket.into())
                .expect(
                    "Quality exists for this s-bucket, otherwise it wouldn't be a winning \
                        chunk; qed",
                )
                .create_proof();

            let chunk_witness = state
                .kzg
                .create_witness(
                    &source_chunks_polynomial,
                    Record::NUM_S_BUCKETS,
                    state.s_bucket.into(),
                )
                .map_err(|error| ProvingError::FailedToCreateChunkWitness {
                    piece_offset,
                    chunk_offset,
                    error,
                })?;

            ChunkCache {
                chunk,
                chunk_offset,
                record_commitment: record_metadata.commitment,
                record_witness: record_metadata.witness,
                chunk_witness: ChunkWitness::from(chunk_witness),
                proof_of_space,
            }
        };

        let chunk_cache = match maybe_chunk_cache {
            Ok(chunk_cache) => chunk_cache,
            Err(error) => {
                if let Some(winning_chunk) = state.winning_chunks.front() {
                    if winning_chunk.chunk_offset == chunk_offset {
                        // Subsequent attempts to generate solutions for this chunk offset will
                        // fail too, remove it so save potential computation
                        state
                            .count
                            .fetch_sub(winning_chunk.audit_chunks.len(), Ordering::SeqCst);
                        state.winning_chunks.pop_front();
                    }
                }

                return Some((Err(error), state));
            }
        };

        state.chunk_cache.insert(chunk_cache)
    };

    let solution = Solution {
        public_key: *state.public_key,
        reward_address: *state.reward_address,
        sector_index: state.sector_metadata.sector_index,
        history_size: state.sector_metadata.history_size,
        piece_offset,
        record_commitment: chunk_cache.record_commitment,
        record_witness: chunk_cache.record_witness,
        chunk: chunk_cache.chunk,
        chunk_witness: chunk_cache.chunk_witness,
        audit_chunk_offset,
        proof_of_space: chunk_cache.proof_of_space,
    };

    Some((Ok(solution), state))
}
