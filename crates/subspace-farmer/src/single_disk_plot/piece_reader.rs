use bitvec::prelude::*;
use futures::channel::{mpsc, oneshot};
use futures::SinkExt;
use std::num::{NonZeroU16, NonZeroU32};
use subspace_core_primitives::{Piece, PublicKey, SectorId, SectorIndex, PIECE_SIZE};
use subspace_solving::derive_chunk_otp;
use tracing::warn;

#[derive(Debug)]
pub(super) struct ReadPieceRequest {
    pub(super) sector_index: SectorIndex,
    pub(super) piece_offset: u64,
    pub(super) response_sender: oneshot::Sender<Option<Piece>>,
}

/// Wrapper data structure that can be used to read pieces from single disk plot
#[derive(Debug, Clone)]
pub struct PieceReader {
    read_piece_sender: mpsc::Sender<ReadPieceRequest>,
}

impl PieceReader {
    pub(super) fn new() -> (Self, mpsc::Receiver<ReadPieceRequest>) {
        let (read_piece_sender, read_piece_receiver) = mpsc::channel::<ReadPieceRequest>(10);

        (Self { read_piece_sender }, read_piece_receiver)
    }

    pub(super) fn close_all_readers(&mut self) {
        self.read_piece_sender.close_channel();
    }

    /// Read piece from sector by offset, `None` means input parameters are incorrect or piece
    /// reader was shut down
    pub async fn read_piece(
        &mut self,
        sector_index: SectorIndex,
        piece_offset: u64,
    ) -> Option<Piece> {
        let (response_sender, response_receiver) = oneshot::channel();
        self.read_piece_sender
            .send(ReadPieceRequest {
                sector_index,
                piece_offset,
                response_sender,
            })
            .await
            .ok()?;
        response_receiver.await.ok()?
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn read_piece(
    sector_index: SectorIndex,
    piece_offset: u64,
    sector_count: u64,
    public_key: &PublicKey,
    first_sector_index: SectorIndex,
    plot_sector_size: u64,
    record_size: NonZeroU32,
    space_l: NonZeroU16,
    global_plot: &[u8],
) -> Option<Piece> {
    if sector_index < first_sector_index {
        warn!(
            %sector_index,
            %piece_offset,
            %sector_count,
            %first_sector_index,
            "Incorrect first sector index"
        );
        return None;
    }
    let sector_offset = sector_index - first_sector_index;
    // Sector must be plotted
    if sector_offset >= sector_count {
        warn!(
            %sector_index,
            %piece_offset,
            %sector_count,
            %first_sector_index,
            "Incorrect sector offset"
        );
        return None;
    }
    // Piece must be within sector
    if piece_offset >= plot_sector_size / PIECE_SIZE as u64 {
        warn!(
            %sector_index,
            %piece_offset,
            %sector_count,
            %first_sector_index,
            "Incorrect piece offset"
        );
        return None;
    }
    let sector_bytes = &global_plot[(sector_offset * plot_sector_size) as usize..];
    let piece_bytes = &sector_bytes[piece_offset as usize * PIECE_SIZE..][..PIECE_SIZE];
    let mut piece = Piece::try_from(piece_bytes).ok()?;

    let sector_id = SectorId::new(public_key, sector_index);

    // Decode piece
    let (record, witness_bytes) = piece.split_at_mut(record_size.get() as usize);
    // TODO: Extract encoding into separate function reusable in farmer and
    //  otherwise
    record
        .view_bits_mut::<Lsb0>()
        .chunks_mut(space_l.get() as usize)
        .enumerate()
        .for_each(|(chunk_index, bits)| {
            // Derive one-time pad
            let mut otp = derive_chunk_otp(&sector_id, witness_bytes, chunk_index as u32);
            // XOR chunk bit by bit with one-time pad
            bits.iter_mut()
                .zip(otp.view_bits_mut::<Lsb0>().iter())
                .for_each(|(mut a, b)| {
                    *a ^= *b;
                });
        });

    Some(piece)
}
