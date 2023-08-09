use crate::proving::SolutionCandidates;
use crate::sector::{SectorContentsMap, SectorMetadataChecksummed};
use std::collections::VecDeque;
use std::mem;
use subspace_core_primitives::crypto::Scalar;
use subspace_core_primitives::{Blake2b256Hash, PublicKey, SectorId, SectorIndex, SolutionRange};
use subspace_verification::is_within_solution_range;

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
pub fn audit_sector<'a>(
    public_key: &'a PublicKey,
    sector_index: SectorIndex,
    global_challenge: &Blake2b256Hash,
    solution_range: SolutionRange,
    sector: &'a [u8],
    sector_metadata: &'a SectorMetadataChecksummed,
) -> Option<SolutionCandidates<'a>> {
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

    // Read s-bucket
    let s_bucket =
        &sector[sector_contents_map_size + s_bucket_audit_offset..][..s_bucket_audit_size];

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
        return None;
    }

    Some(SolutionCandidates::new(
        public_key,
        sector_index,
        sector_id,
        s_bucket_audit_index,
        sector,
        sector_metadata,
        winning_chunks,
    ))
}
