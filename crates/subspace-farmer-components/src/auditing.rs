use crate::proving::SolutionCandidates;
use crate::sector::{sector_size, SectorContentsMap, SectorMetadataChecksummed};
use crate::{ReadAtOffset, ReadAtSync};
use rayon::prelude::*;
use subspace_core_primitives::crypto::Scalar;
use subspace_core_primitives::{
    Blake3Hash, PublicKey, SBucket, SectorId, SectorIndex, SectorSlotChallenge, SolutionRange,
};
use subspace_verification::is_within_solution_range;
use tracing::warn;

/// Result of sector audit
#[derive(Debug, Clone)]
pub struct AuditResult<'a, Sector>
where
    Sector: 'a,
{
    /// Sector index
    pub sector_index: SectorIndex,
    /// Solution candidates
    pub solution_candidates: SolutionCandidates<'a, Sector>,
    /// Best solution distance found
    pub best_solution_distance: SolutionRange,
}

/// Chunk candidate, contains one or more potentially winning audit chunks (in case chunk itself was
/// encoded and eligible for claiming a reward)
#[derive(Debug, Clone)]
pub(crate) struct ChunkCandidate {
    /// Chunk offset within s-bucket
    pub(crate) chunk_offset: u32,
    /// Solution distance of this chunk, can be used to prioritize higher quality solutions
    pub(crate) solution_distance: SolutionRange,
}

/// Audit a single sector and generate a stream of solutions.
///
/// This is primarily helpful in test environment, prefer [`audit_plot_sync`] for auditing real plots.
pub fn audit_sector_sync<'a, Sector>(
    public_key: &'a PublicKey,
    global_challenge: &Blake3Hash,
    solution_range: SolutionRange,
    sector: Sector,
    sector_metadata: &'a SectorMetadataChecksummed,
) -> Option<AuditResult<'a, Sector>>
where
    Sector: ReadAtSync + 'a,
{
    let SectorAuditingDetails {
        sector_id,
        sector_slot_challenge,
        s_bucket_audit_index,
        s_bucket_audit_size,
        s_bucket_audit_offset_in_sector,
    } = collect_sector_auditing_details(public_key.hash(), global_challenge, sector_metadata);

    let mut s_bucket = vec![0; s_bucket_audit_size];
    let read_s_bucket_result = sector.read_at(&mut s_bucket, s_bucket_audit_offset_in_sector);

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
        sector_index: sector_metadata.sector_index,
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

/// Audit the whole plot and generate streams of solutions
pub fn audit_plot_sync<'a, Plot>(
    public_key: &'a PublicKey,
    global_challenge: &Blake3Hash,
    solution_range: SolutionRange,
    plot: &'a Plot,
    sectors_metadata: &'a [SectorMetadataChecksummed],
    maybe_sector_being_modified: Option<SectorIndex>,
) -> Vec<AuditResult<'a, ReadAtOffset<'a, Plot>>>
where
    Plot: ReadAtSync + 'a,
{
    let public_key_hash = public_key.hash();

    // Create auditing info for all sectors in parallel
    sectors_metadata
        .par_iter()
        .map(|sector_metadata| {
            (
                collect_sector_auditing_details(public_key_hash, global_challenge, sector_metadata),
                sector_metadata,
            )
        })
        // Read s-buckets of all sectors, map to winning chunks and then to audit results, all in
        // parallel
        .filter_map(|(sector_auditing_info, sector_metadata)| {
            if maybe_sector_being_modified == Some(sector_metadata.sector_index) {
                // Skip sector that is being modified right now
                return None;
            }

            if sector_auditing_info.s_bucket_audit_size == 0 {
                // S-bucket is empty
                return None;
            }

            let sector = plot.offset(
                usize::from(sector_metadata.sector_index)
                    * sector_size(sector_metadata.pieces_in_sector),
            );

            let mut s_bucket = vec![0; sector_auditing_info.s_bucket_audit_size];

            if let Err(error) = sector.read_at(
                &mut s_bucket,
                sector_auditing_info.s_bucket_audit_offset_in_sector,
            ) {
                warn!(
                    %error,
                    sector_index = %sector_metadata.sector_index,
                    s_bucket_audit_index = %sector_auditing_info.s_bucket_audit_index,
                    "Failed read s-bucket",
                );

                return None;
            }

            let (winning_chunks, best_solution_distance) = map_winning_chunks(
                &s_bucket,
                global_challenge,
                &sector_auditing_info.sector_slot_challenge,
                solution_range,
            )?;

            Some(AuditResult {
                sector_index: sector_metadata.sector_index,
                solution_candidates: SolutionCandidates::new(
                    public_key,
                    sector_auditing_info.sector_id,
                    sector_auditing_info.s_bucket_audit_index,
                    sector,
                    sector_metadata,
                    winning_chunks.into(),
                ),
                best_solution_distance,
            })
        })
        .collect()
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
    public_key_hash: Blake3Hash,
    global_challenge: &Blake3Hash,
    sector_metadata: &SectorMetadataChecksummed,
) -> SectorAuditingDetails {
    let sector_id = SectorId::new(public_key_hash, sector_metadata.sector_index);

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
    let mut chunk_candidates = s_bucket
        .array_chunks::<{ Scalar::FULL_BYTES }>()
        .enumerate()
        .filter_map(|(chunk_offset, chunk)| {
            is_within_solution_range(
                global_challenge,
                chunk,
                sector_slot_challenge,
                solution_range,
            )
            .map(|solution_distance| ChunkCandidate {
                chunk_offset: chunk_offset as u32,
                solution_distance,
            })
        })
        .collect::<Vec<_>>();

    // Check if there are any solutions possible
    if chunk_candidates.is_empty() {
        return None;
    }

    chunk_candidates.sort_by_key(|chunk_candidate| chunk_candidate.solution_distance);

    let best_solution_distance = chunk_candidates
        .first()
        .expect("Not empty, checked above; qed")
        .solution_distance;

    Some((chunk_candidates, best_solution_distance))
}
