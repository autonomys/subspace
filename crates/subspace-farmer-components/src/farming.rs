use crate::{FarmerProtocolInfo, SectorMetadata};
use parity_scale_codec::{Decode, IoReader};
use schnorrkel::Keypair;
use std::io;
use std::io::SeekFrom;
use subspace_core_primitives::crypto::blake2b_256_254_hash;
use subspace_core_primitives::crypto::kzg::Witness;
use subspace_core_primitives::sector_codec::{SectorCodec, SectorCodecError};
use subspace_core_primitives::{
    Blake2b256Hash, Piece, PieceIndex, PublicKey, Scalar, SectorId, SectorIndex, Solution,
    SolutionRange, PIECES_IN_SECTOR, PIECE_SIZE, PLOT_SECTOR_SIZE,
};
use subspace_solving::create_chunk_signature;
use subspace_verification::{derive_audit_chunk, is_within_solution_range};
use thiserror::Error;
use tracing::error;

/// Errors that happen during farming
#[derive(Debug, Error)]
pub enum FarmingError {
    /// Failed to decode sector metadata
    #[error("Failed to decode sector metadata: {error}")]
    FailedToDecodeMetadata {
        /// Lower-level error
        error: parity_scale_codec::Error,
    },
    /// Failed to decode sector
    #[error("Failed to decode sector: {0}")]
    FailedToDecodeSector(#[from] SectorCodecError),
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Chunk of the plotted piece that can be used to create a solution that is within desired solution
/// range
#[derive(Debug, Copy, Clone)]
pub struct EligibleChunk {
    /// Offset of the chunk within piece
    pub offset: u32,
    /// Chunk itself
    pub chunk: Scalar,
}

/// Sector that can be used to create a solution that is within desired solution range
#[derive(Debug, Clone)]
pub struct EligibleSector {
    /// Sector ID
    pub sector_id: SectorId,
    /// Sector index
    pub sector_index: SectorIndex,
    /// Derived local challenge
    pub local_challenge: SolutionRange,
    /// Chunks at audited piece that are within desired solution range
    pub chunks: Vec<EligibleChunk>,
    /// Offset of the piece in sector
    pub audit_piece_offset: u64,
}

impl EligibleSector {
    /// Create solutions for eligible sector (eligible sector may contain multiple)
    pub fn try_into_solutions<S, SM>(
        self,
        keypair: &Keypair,
        reward_address: PublicKey,
        farmer_protocol_info: &FarmerProtocolInfo,
        sector_codec: &SectorCodec,
        mut sector: S,
        sector_metadata: SM,
    ) -> Result<Vec<Solution<PublicKey, PublicKey>>, FarmingError>
    where
        S: io::Read,
        SM: io::Read,
    {
        if self.chunks.is_empty() {
            return Ok(Vec::new());
        }

        let mut sector_scalars = {
            let mut sector_bytes = vec![0; PLOT_SECTOR_SIZE as usize];
            sector.read_exact(&mut sector_bytes)?;

            sector_bytes
                .chunks_exact(Scalar::FULL_BYTES)
                .map(|bytes| {
                    Scalar::from(
                        <&[u8; Scalar::FULL_BYTES]>::try_from(bytes)
                            .expect("Chunked into scalar full bytes above; qed"),
                    )
                })
                .collect::<Vec<Scalar>>()
        };

        let sector_metadata = SectorMetadata::decode(&mut IoReader(sector_metadata))
            .map_err(|error| FarmingError::FailedToDecodeMetadata { error })?;

        sector_codec
            .decode(&mut sector_scalars)
            .map_err(FarmingError::FailedToDecodeSector)?;

        let mut piece = Piece::default();
        let scalars_in_piece = PIECE_SIZE / Scalar::SAFE_BYTES;
        piece
            .chunks_exact_mut(Scalar::SAFE_BYTES)
            .zip(
                sector_scalars
                    .into_iter()
                    .skip(scalars_in_piece * self.audit_piece_offset as usize)
                    .take(scalars_in_piece),
            )
            .for_each(|(output, input)| {
                // After decoding we get piece scalar bytes padded with zero byte, so we can read
                // the whole thing first and then copy just first `Scalar::SAFE_BYTES` we actually
                // care about
                output.copy_from_slice(&input.to_bytes()[..Scalar::SAFE_BYTES]);
            });

        let (record, witness_bytes) =
            piece.split_at(farmer_protocol_info.record_size.get() as usize);
        let piece_witness = match Witness::try_from_bytes(witness_bytes.try_into().expect(
            "Witness must have correct size unless implementation is broken in a big way; qed",
        )) {
            Ok(piece_witness) => piece_witness,
            Err(error) => {
                let piece_index = self
                    .sector_id
                    .derive_piece_index(self.audit_piece_offset, sector_metadata.total_pieces);
                let audit_piece_bytes_offset = self.audit_piece_offset
                    * (PIECE_SIZE / Scalar::SAFE_BYTES * Scalar::FULL_BYTES) as u64;
                error!(
                    ?error,
                    sector_id = ?self.sector_id,
                    %audit_piece_bytes_offset,
                    %piece_index,
                    "Failed to decode witness for piece, likely caused by on-disk data corruption"
                );
                return Ok(Vec::new());
            }
        };

        Ok(self
            .chunks
            .into_iter()
            .map(|EligibleChunk { offset, chunk }| Solution {
                public_key: PublicKey::from(keypair.public.to_bytes()),
                reward_address,
                sector_index: self.sector_index,
                total_pieces: sector_metadata.total_pieces,
                piece_offset: self.audit_piece_offset,
                piece_record_hash: blake2b_256_254_hash(record),
                piece_witness,
                chunk_offset: offset,
                chunk,
                chunk_signature: create_chunk_signature(keypair, &chunk.to_bytes()),
            })
            .collect())
    }
}

/// Audit a single sector
///
/// Note: auditing expects cursor to be set to the beginning of the sector and will move the cursor
/// during its operation. Make sure to return it back to the beginning of the sector if necessary.
pub fn audit_sector<S>(
    public_key: &PublicKey,
    sector_index: u64,
    global_challenge: &Blake2b256Hash,
    solution_range: SolutionRange,
    mut sector: S,
) -> Result<Option<EligibleSector>, FarmingError>
where
    S: io::Read + io::Seek,
{
    let sector_id = SectorId::new(public_key, sector_index);

    let local_challenge = sector_id.derive_local_challenge(global_challenge);
    let audit_piece_offset: PieceIndex = local_challenge % PIECES_IN_SECTOR;
    // Offset of the piece in sector (in bytes, accounts for the fact that encoded piece has its
    // chunks expanded with zero byte padding)
    let audit_piece_bytes_offset =
        audit_piece_offset * (PIECE_SIZE / Scalar::SAFE_BYTES * Scalar::FULL_BYTES) as u64;

    let mut piece = Piece::default();
    sector.seek(SeekFrom::Current(audit_piece_bytes_offset as i64))?;
    sector.read_exact(&mut piece)?;

    let chunks = piece
        .chunks_exact(Scalar::FULL_BYTES)
        .enumerate()
        .filter_map(|(offset, chunk_bytes)| {
            let chunk_bytes = chunk_bytes
                .try_into()
                .expect("Chunked into scalar full bytes above; qed");

            is_within_solution_range(
                local_challenge,
                derive_audit_chunk(&chunk_bytes),
                solution_range,
            )
            .then(|| EligibleChunk {
                offset: offset as u32,
                chunk: Scalar::from(&chunk_bytes),
            })
        })
        .collect::<Vec<_>>();

    if chunks.is_empty() {
        return Ok(None);
    }

    Ok(Some(EligibleSector {
        sector_id,
        sector_index,
        local_challenge,
        chunks,
        audit_piece_offset,
    }))
}
