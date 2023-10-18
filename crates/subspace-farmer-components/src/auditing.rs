use crate::proving::SolutionCandidates;
use crate::sector::{SectorContentsMap, SectorMetadataChecksummed};
use crate::{ReadAt, ReadAtAsync, ReadAtSync};
use std::mem;
use subspace_core_primitives::crypto::Scalar;
use subspace_core_primitives::{
    Blake3Hash, PublicKey, SBucket, SectorId, SectorSlotChallenge, SolutionRange,
};
use subspace_verification::is_within_solution_range;
use tracing::warn;

/// Result of sector audit
#[derive(Debug, Clone)]
pub struct AuditResult<'a, Sector>
where
    Sector: 'a,
{
    /// Solution candidates
    pub solution_candidates: SolutionCandidates<'a, Sector>,
    /// Best solution distance found
    pub best_solution_distance: SolutionRange,
}

/// Audit chunk candidate
#[derive(Debug, Clone)]
pub(crate) struct AuditChunkCandidate {
    /// Audit chunk offset
    pub(crate) offset: u8,
    /// Solution distance of this audit chunk, can be used to prioritize higher quality solutions
    pub(crate) solution_distance: SolutionRange,
}

/// Chunk candidate, contains one or more potentially winning audit chunks (in case chunk itself was
/// encoded and eligible for claiming a reward)
#[derive(Debug, Clone)]
pub(crate) struct ChunkCandidate {
    /// Chunk offset within s-bucket
    pub(crate) chunk_offset: u32,
    /// Audit chunk candidates in above chunk
    pub(crate) audit_chunks: Vec<AuditChunkCandidate>,
}

/// Audit a single sector and generate a stream of solutions, where `sector` must be positioned
/// correctly at the beginning of the sector (seek to desired offset before calling this function
/// and seek back afterwards if necessary).
pub async fn audit_sector<'a, S, A>(
    public_key: &'a PublicKey,
    global_challenge: &Blake3Hash,
    solution_range: SolutionRange,
    sector: ReadAt<S, A>,
    sector_metadata: &'a SectorMetadataChecksummed,
) -> Option<AuditResult<'a, ReadAt<S, A>>>
where
    S: ReadAtSync + 'a,
    A: ReadAtAsync + 'a,
{
    let SectorAuditingDetails {
        sector_id,
        sector_slot_challenge,
        s_bucket_audit_index,
        s_bucket_audit_size,
        s_bucket_audit_offset_in_sector,
    } = collect_sector_auditing_details(public_key, global_challenge, sector_metadata);

    let mut s_bucket = vec![0; s_bucket_audit_size];
    let read_s_bucket_result = match &sector {
        ReadAt::Sync(sector) => sector.read_at(&mut s_bucket, s_bucket_audit_offset_in_sector),
        ReadAt::Async(sector) => {
            sector
                .read_at(&mut s_bucket, s_bucket_audit_offset_in_sector)
                .await
        }
    };
    if let Err(error) = read_s_bucket_result {
        warn!(
            %error,
            sector_index = %sector_metadata.sector_index,
            %s_bucket_audit_index,
            "Failed read s-bucket",
        );
        return None;
    }

    let (winning_chunks, best_solution_distance) = map_winning_chunks(
        &s_bucket,
        global_challenge,
        &sector_slot_challenge,
        solution_range,
    )?;

    Some(AuditResult {
        solution_candidates: SolutionCandidates::new(
            public_key,
            sector_id,
            s_bucket_audit_index,
            sector,
            sector_metadata,
            winning_chunks.into(),
        ),
        best_solution_distance,
    })
}

struct SectorAuditingDetails {
    sector_id: SectorId,
    sector_slot_challenge: SectorSlotChallenge,
    s_bucket_audit_index: SBucket,
    /// Size in bytes
    s_bucket_audit_size: usize,
    /// Offset in bytes
    s_bucket_audit_offset_in_sector: usize,
}

fn collect_sector_auditing_details(
    public_key: &PublicKey,
    global_challenge: &Blake3Hash,
    sector_metadata: &SectorMetadataChecksummed,
) -> SectorAuditingDetails {
    let sector_id = SectorId::new(public_key.hash(), sector_metadata.sector_index);

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

    let s_bucket_audit_offset_in_sector = sector_contents_map_size + s_bucket_audit_offset;

    SectorAuditingDetails {
        sector_id,
        sector_slot_challenge,
        s_bucket_audit_index,
        s_bucket_audit_size,
        s_bucket_audit_offset_in_sector,
    }
}

/// Map all winning chunks
fn map_winning_chunks(
    s_bucket: &[u8],
    global_challenge: &Blake3Hash,
    sector_slot_challenge: &SectorSlotChallenge,
    solution_range: SolutionRange,
) -> Option<(Vec<ChunkCandidate>, SolutionRange)> {
    // Map all winning chunks
    let mut winning_chunks = s_bucket
        .array_chunks::<{ Scalar::FULL_BYTES }>()
        .enumerate()
        .filter_map(|(chunk_offset, chunk)| {
            // Check all audit chunks within chunk, there might be more than one winning
            let mut winning_audit_chunks = chunk
                .array_chunks::<{ mem::size_of::<SolutionRange>() }>()
                .enumerate()
                .filter_map(|(audit_chunk_offset, &audit_chunk)| {
                    is_within_solution_range(
                        global_challenge,
                        SolutionRange::from_le_bytes(audit_chunk),
                        sector_slot_challenge,
                        solution_range,
                    )
                    .map(|solution_distance| AuditChunkCandidate {
                        offset: audit_chunk_offset as u8,
                        solution_distance,
                    })
                })
                .collect::<Vec<_>>();

            // In case none of the audit chunks are winning, we don't care about this sector
            if winning_audit_chunks.is_empty() {
                return None;
            }

            winning_audit_chunks.sort_by(|a, b| a.solution_distance.cmp(&b.solution_distance));

            Some(ChunkCandidate {
                chunk_offset: chunk_offset as u32,
                audit_chunks: winning_audit_chunks,
            })
        })
        .collect::<Vec<_>>();

    // Check if there are any solutions possible
    if winning_chunks.is_empty() {
        return None;
    }

    winning_chunks.sort_by(|a, b| {
        let a_solution_distance = a
            .audit_chunks
            .first()
            .expect("Lists of audit chunks are non-empty; qed")
            .solution_distance;
        let b_solution_distance = b
            .audit_chunks
            .first()
            .expect("Lists of audit chunks are non-empty; qed")
            .solution_distance;

        a_solution_distance.cmp(&b_solution_distance)
    });

    let best_solution_distance = winning_chunks
        .first()
        .expect("Not empty, checked above; qed")
        .audit_chunks
        .first()
        .expect("Lists of audit chunks are non-empty; qed")
        .solution_distance;

    Some((winning_chunks, best_solution_distance))
}
