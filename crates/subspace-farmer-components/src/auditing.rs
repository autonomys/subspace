use crate::proving::SolutionCandidates;
use crate::sector::{SectorContentsMap, SectorMetadata};
use std::collections::VecDeque;
use std::io::SeekFrom;
use std::{io, mem};
use subspace_core_primitives::crypto::Scalar;
use subspace_core_primitives::{Blake2b256Hash, PublicKey, SectorId, SolutionRange};
use subspace_verification::is_within_solution_range;
use thiserror::Error;

/// Errors that happen during auditing
#[derive(Debug, Error)]
pub enum AuditingError {
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone)]
pub(crate) struct ChunkCandidate {
    /// Chunk offset within s-bucket
    pub(crate) chunk_offset: u32,
    /// Audit chunk offsets in above chunk
    pub(crate) audit_chunk_offsets: VecDeque<u8>,
}

/// Audit a single sector and generate a stream of solutions, where `sector` must be positioned
/// correctly at the beginning of the sector (seek to desired offset before calling this function
/// and seek back afterwards if necessary).
pub fn audit_sector<'a, S>(
    public_key: &'a PublicKey,
    sector_index: u64,
    global_challenge: &Blake2b256Hash,
    solution_range: SolutionRange,
    sector: &mut S,
    sector_metadata: &'a SectorMetadata,
) -> Result<Option<SolutionCandidates<'a>>, AuditingError>
where
    S: io::Read + io::Seek,
{
    let sector_id = SectorId::new(public_key.hash(), sector_index);

    let sector_slot_challenge = sector_id.derive_sector_slot_challenge(global_challenge);
    let s_bucket_audit_index = sector_slot_challenge.s_bucket_audit_index();
    let s_bucket_audit_size = Scalar::FULL_BYTES
        * usize::from(sector_metadata.s_bucket_sizes[usize::from(s_bucket_audit_index)]);
    let s_bucket_audit_offset = Scalar::FULL_BYTES
        * sector_metadata
            .s_bucket_sizes
            .iter()
            .take(s_bucket_audit_index.into())
            .copied()
            .map(usize::from)
            .sum::<usize>();

    let sector_contents_map_size =
        SectorContentsMap::encoded_size(sector_metadata.pieces_in_sector);

    // Seek to the beginning of `s_bucket_audit_index`
    sector.seek(SeekFrom::Current(
        sector_contents_map_size as i64 + s_bucket_audit_offset as i64,
    ))?;
    // Read s-bucket
    let mut s_bucket = vec![0u8; s_bucket_audit_size];
    sector.read_exact(s_bucket.as_mut())?;

    // Map all winning chunks
    let winning_chunks = s_bucket
        .array_chunks::<{ Scalar::FULL_BYTES }>()
        .enumerate()
        .filter_map(|(chunk_offset, chunk)| {
            // Check all audit chunks within chunk, there might be more than one winning
            let winning_audit_chunk_offsets = chunk
                .array_chunks::<{ mem::size_of::<SolutionRange>() }>()
                .enumerate()
                .filter_map(|(audit_chunk_offset, &audit_chunk)| {
                    is_within_solution_range(
                        global_challenge,
                        SolutionRange::from_le_bytes(audit_chunk),
                        &sector_slot_challenge,
                        solution_range,
                    )
                    .then_some(audit_chunk_offset as u8)
                })
                .collect::<VecDeque<_>>();

            // In case none of the audit chunks are winning, we don't care about this sector
            if winning_audit_chunk_offsets.is_empty() {
                return None;
            }

            Some(ChunkCandidate {
                chunk_offset: chunk_offset as u32,
                audit_chunk_offsets: winning_audit_chunk_offsets,
            })
        })
        .collect::<VecDeque<_>>();

    // Check if there are any solutions possible
    if winning_chunks.is_empty() {
        return Ok(None);
    }

    Ok(Some(SolutionCandidates::new(
        public_key,
        sector_index,
        sector_id,
        s_bucket_audit_index,
        sector_metadata,
        winning_chunks,
    )))
}
