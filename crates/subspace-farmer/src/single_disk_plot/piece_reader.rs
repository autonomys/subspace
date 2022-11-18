use futures::channel::{mpsc, oneshot};
use futures::SinkExt;
use subspace_core_primitives::sector_codec::SectorCodec;
use subspace_core_primitives::{Piece, Scalar, SectorIndex, PIECE_SIZE, PLOT_SECTOR_SIZE};
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

pub(super) fn read_piece(
    sector_index: SectorIndex,
    piece_offset: u64,
    sector_count: u64,
    first_sector_index: SectorIndex,
    sector_codec: &SectorCodec,
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
    if piece_offset >= PLOT_SECTOR_SIZE / PIECE_SIZE as u64 {
        warn!(
            %sector_index,
            %piece_offset,
            %sector_count,
            %first_sector_index,
            "Incorrect piece offset"
        );
        return None;
    }

    let piece = {
        let sector_bytes = &global_plot[(sector_offset * PLOT_SECTOR_SIZE) as usize..]
            [..PLOT_SECTOR_SIZE as usize];

        let mut sector_bytes_scalars = sector_bytes
            .chunks_exact(Scalar::FULL_BYTES)
            .map(|bytes| {
                Scalar::from(
                    <&[u8; Scalar::FULL_BYTES]>::try_from(bytes)
                        .expect("Chunked into scalar full bytes above; qed"),
                )
            })
            .collect::<Vec<_>>();
        sector_codec.decode(&mut sector_bytes_scalars).ok()?;

        let scalars_in_piece = PIECE_SIZE / Scalar::SAFE_BYTES;
        let piece_scalars =
            &sector_bytes_scalars[piece_offset as usize * scalars_in_piece..][..scalars_in_piece];

        let mut piece = Piece::default();
        piece
            .chunks_exact_mut(Scalar::SAFE_BYTES)
            .zip(piece_scalars)
            .for_each(|(output, input)| {
                // After decoding we get piece scalar bytes padded with zero byte, so we can read
                // the whole thing first and then copy just first `Scalar::SAFE_BYTES` we actually
                // care about
                output.copy_from_slice(&input.to_bytes()[..Scalar::SAFE_BYTES]);
            });

        piece
    };

    Some(piece)
}
