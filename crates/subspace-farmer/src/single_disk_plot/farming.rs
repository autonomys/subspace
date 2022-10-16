use crate::single_disk_plot::FarmingError;
use bitvec::prelude::*;
use std::io;
use std::io::SeekFrom;
use subspace_core_primitives::{
    Blake2b256Hash, Chunk, Piece, PublicKey, SectorId, SolutionRange, PIECE_SIZE,
};
use subspace_rpc_primitives::FarmerProtocolInfo;
use subspace_verification::is_within_solution_range;

/// Sector that can be used to create a solution that is within desired solution range
#[derive(Debug, Clone)]
pub struct EligibleSector {
    /// Sector ID
    pub sector_id: SectorId,
    /// Derived local challenge
    pub local_challenge: SolutionRange,
    /// Audit index corresponding to the challenge used
    pub audit_index: u64,
    /// Chunk at audit index
    pub chunk: Chunk,
    /// Expanded version of the above chunk
    pub expanded_chunk: SolutionRange,
    /// Piece where chunk is located
    pub piece: Piece,
    /// Offset of the piece in sector
    pub audit_piece_offset: u64,
}

/// Audit a single sector
///
/// Note: auditing expects cursor to be set to the beginning of the sector and will move the cursor
/// during its operation. Make sure to return it back to the beginning of the sector if necessary.
pub fn audit_sector<S>(
    public_key: &PublicKey,
    sector_index: u64,
    farmer_protocol_info: &FarmerProtocolInfo,
    global_challenge: &Blake2b256Hash,
    solution_range: SolutionRange,
    mut sector: S,
) -> Result<Option<EligibleSector>, FarmingError>
where
    S: io::Read + io::Seek,
{
    let sector_id = SectorId::new(public_key, sector_index);
    let chunks_in_sector = u64::from(farmer_protocol_info.record_size.get()) * u64::from(u8::BITS)
        / u64::from(farmer_protocol_info.space_l.get());

    let local_challenge = sector_id.derive_local_challenge(global_challenge);
    let audit_index: u64 = local_challenge % chunks_in_sector;
    let audit_piece_offset = (audit_index / u64::from(u8::BITS)) / PIECE_SIZE as u64;
    // Offset of the piece in sector (in bytes)
    let audit_piece_bytes_offset = audit_piece_offset * PIECE_SIZE as u64;
    // Audit index (chunk) within corresponding piece
    let audit_index_within_piece = audit_index - audit_piece_bytes_offset * u64::from(u8::BITS);
    let mut piece = Piece::default();
    sector.seek(SeekFrom::Current(audit_piece_bytes_offset as i64))?;
    sector.read_exact(&mut piece)?;

    // TODO: We are skipping witness part of the piece or else it is not
    //  decodable
    let maybe_chunk = piece[..farmer_protocol_info.record_size.get() as usize]
        .view_bits()
        .chunks_exact(farmer_protocol_info.space_l.get() as usize)
        .nth(audit_index_within_piece as usize);

    let chunk = match maybe_chunk {
        Some(chunk) => Chunk::from(chunk),
        None => {
            // TODO: Record size is not multiple of `space_l`, last bits
            //  were not encoded and should not be used for solving
            return Ok(None);
        }
    };

    // TODO: This just have 20 bits of entropy as input, should we add
    //  something else?
    let expanded_chunk = chunk.expand(local_challenge);

    Ok(
        is_within_solution_range(local_challenge, expanded_chunk, solution_range).then_some(
            EligibleSector {
                sector_id,
                local_challenge,
                audit_index,
                chunk,
                expanded_chunk,
                piece,
                audit_piece_offset,
            },
        ),
    )
}
