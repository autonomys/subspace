//! Auditing utilities
//!
//! There is a way to both audit a single sector (primarily helpful for testing purposes) and the
//! whole plot (which is heavily parallelized and much more efficient) created by functions in
//! [`plotting`](crate::plotting) module earlier.

use crate::proving::SolutionCandidates;
use crate::sector::{sector_size, SectorContentsMap, SectorMetadataChecksummed};
use crate::{ReadAtOffset, ReadAtSync};
use rayon::prelude::*;
use std::collections::HashSet;
use std::io;
use subspace_core_primitives::hashes::Blake3Hash;
use subspace_core_primitives::sectors::{SBucket, SectorId, SectorIndex, SectorSlotChallenge};
use subspace_core_primitives::{PublicKey, ScalarBytes, SolutionRange};
use subspace_verification::is_within_solution_range;
use thiserror::Error;

/// Errors that happen during proving
#[derive(Debug, Error)]
pub enum AuditingError {
    /// Failed read s-bucket
    #[error("Failed read s-bucket {s_bucket_audit_index} of sector {sector_index}: {error}")]
    SBucketReading {
        /// Sector index
        sector_index: SectorIndex,
        /// S-bucket audit index
        s_bucket_audit_index: SBucket,
        /// Low-level error
        error: io::Error,
    },
}

/// Result of sector audit
#[derive(Debug, Clone)]
pub struct AuditResult<'a, Sector> {
    /// Sector index
    pub sector_index: SectorIndex,
    /// Solution candidates
    pub solution_candidates: SolutionCandidates<'a, Sector>,
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
) -> Result<Option<AuditResult<'a, Sector>>, AuditingError>
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
    sector
        .read_at(&mut s_bucket, s_bucket_audit_offset_in_sector)
        .map_err(|error| AuditingError::SBucketReading {
            sector_index: sector_metadata.sector_index,
            s_bucket_audit_index,
            error,
        })?;

    let Some(winning_chunks) = map_winning_chunks(
        &s_bucket,
        global_challenge,
        &sector_slot_challenge,
        solution_range,
    ) else {
        return Ok(None);
    };

    Ok(Some(AuditResult {
        sector_index: sector_metadata.sector_index,
        solution_candidates: SolutionCandidates::new(
            public_key,
            sector_id,
            s_bucket_audit_index,
            sector,
            sector_metadata,
            winning_chunks.into(),
        ),
    }))
}

/// Audit the whole plot and generate streams of results.
///
/// Each audit result contains a solution candidate that might be converted into solution (but will
/// not necessarily succeed, auditing only does quick checks and can't know for sure).
///
/// Plot is assumed to contain concatenated series of sectors as created by functions in
/// [`plotting`](crate::plotting) module earlier.
pub fn audit_plot_sync<'a, 'b, Plot>(
    public_key: &'a PublicKey,
    global_challenge: &Blake3Hash,
    solution_range: SolutionRange,
    plot: &'a Plot,
    sectors_metadata: &'a [SectorMetadataChecksummed],
    sectors_being_modified: &'b HashSet<SectorIndex>,
) -> Result<Vec<AuditResult<'a, ReadAtOffset<'a, Plot>>>, AuditingError>
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
            if sectors_being_modified.contains(&sector_metadata.sector_index) {
                // Skip sector that is being modified right now
                return None;
            }

            if sector_auditing_info.s_bucket_audit_size == 0 {
                // S-bucket is empty
                return None;
            }

            let sector = plot.offset(
                u64::from(sector_metadata.sector_index)
                    * sector_size(sector_metadata.pieces_in_sector) as u64,
            );

            let mut s_bucket = vec![0; sector_auditing_info.s_bucket_audit_size];

            if let Err(error) = sector.read_at(
                &mut s_bucket,
                sector_auditing_info.s_bucket_audit_offset_in_sector,
            ) {
                return Some(Err(AuditingError::SBucketReading {
                    sector_index: sector_metadata.sector_index,
                    s_bucket_audit_index: sector_auditing_info.s_bucket_audit_index,
                    error,
                }));
            }

            let winning_chunks = map_winning_chunks(
                &s_bucket,
                global_challenge,
                &sector_auditing_info.sector_slot_challenge,
                solution_range,
            )?;

            Some(Ok(AuditResult {
                sector_index: sector_metadata.sector_index,
                solution_candidates: SolutionCandidates::new(
                    public_key,
                    sector_auditing_info.sector_id,
                    sector_auditing_info.s_bucket_audit_index,
                    sector,
                    sector_metadata,
                    winning_chunks.into(),
                ),
            }))
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
    s_bucket_audit_offset_in_sector: u64,
}

fn collect_sector_auditing_details(
    public_key_hash: Blake3Hash,
    global_challenge: &Blake3Hash,
    sector_metadata: &SectorMetadataChecksummed,
) -> SectorAuditingDetails {
    let sector_id = SectorId::new(public_key_hash, sector_metadata.sector_index);

    let sector_slot_challenge = sector_id.derive_sector_slot_challenge(global_challenge);
    let s_bucket_audit_index = sector_slot_challenge.s_bucket_audit_index();
    let s_bucket_audit_size = ScalarBytes::FULL_BYTES
        * usize::from(sector_metadata.s_bucket_sizes[usize::from(s_bucket_audit_index)]);
    let s_bucket_audit_offset = ScalarBytes::FULL_BYTES as u64
        * sector_metadata
            .s_bucket_sizes
            .iter()
            .take(s_bucket_audit_index.into())
            .copied()
            .map(u64::from)
            .sum::<u64>();

    let sector_contents_map_size =
        SectorContentsMap::encoded_size(sector_metadata.pieces_in_sector);

    let s_bucket_audit_offset_in_sector = sector_contents_map_size as u64 + s_bucket_audit_offset;

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
) -> Option<Vec<ChunkCandidate>> {
    // Map all winning chunks
    let mut chunk_candidates = s_bucket
        .array_chunks::<{ ScalarBytes::FULL_BYTES }>()
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

    Some(chunk_candidates)
}
