use crate::plot::piece_index_hash_to_offset_db::IndexHashToOffsetDB;
use crate::plot::piece_offset_to_index_db::PieceOffsetToIndexDb;
use crate::plot::{PieceOffset, PlotError, PlotFile};
use std::collections::VecDeque;
use std::io;
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use subspace_core_primitives::{
    FlatPieces, Piece, PieceIndex, PieceIndexHash, PublicKey, PIECE_SIZE,
};

#[derive(Debug, Default)]
pub struct WriteResult {
    pieces: Arc<FlatPieces>,
    piece_offsets: Vec<Option<PieceOffset>>,
    evicted_pieces: Vec<Piece>,
}

impl WriteResult {
    /// Iterator over tuple of piece offset and piece itself as memory slice
    pub fn to_recommitment_iterator(&self) -> impl Iterator<Item = (PieceOffset, &[u8])> {
        self.piece_offsets
            .iter()
            .zip(self.pieces.as_pieces())
            .filter_map(|(maybe_piece_offset, piece)| {
                maybe_piece_offset.map(|piece_offset| (piece_offset, piece))
            })
    }

    pub fn evicted_pieces(&self) -> &[Piece] {
        &self.evicted_pieces
    }
}

#[derive(Debug)]
pub(super) enum Request {
    ReadEncoding {
        index_hash: PieceIndexHash,
        result_sender: mpsc::Sender<io::Result<Piece>>,
    },
    ReadEncodingWithIndex {
        piece_offset: PieceOffset,
        result_sender: mpsc::Sender<io::Result<(Piece, PieceIndex)>>,
    },
    ReadEncodings {
        /// Can be from 0 to the `piece_count`
        piece_offset: PieceOffset,
        count: u64,
        /// Vector containing all of the pieces as contiguous block of memory
        result_sender: mpsc::Sender<io::Result<Vec<u8>>>,
    },
    ReadPieceIndexes {
        from_index_hash: PieceIndexHash,
        count: u64,
        result_sender: mpsc::Sender<io::Result<Vec<PieceIndex>>>,
    },
    GetPieceRange {
        result_sender: mpsc::Sender<io::Result<Option<RangeInclusive<PieceIndexHash>>>>,
    },
    WriteEncodings {
        encodings: Arc<FlatPieces>,
        piece_indexes: Vec<PieceIndex>,
        /// Returns offsets of all new pieces and pieces which were replaced
        result_sender: mpsc::Sender<io::Result<WriteResult>>,
    },
    Exit {
        result_sender: mpsc::Sender<()>,
    },
}

#[derive(Debug)]
pub(super) enum RequestPriority {
    Low,
    High,
}

#[derive(Debug)]
pub(super) struct RequestWithPriority {
    pub(super) request: Request,
    pub(super) priority: RequestPriority,
}

pub(super) struct PlotWorker<T> {
    plot: T,
    piece_index_hash_to_offset_db: IndexHashToOffsetDB,
    piece_offset_to_index: PieceOffsetToIndexDb,
    max_piece_count: u64,
}

impl<T: PlotFile> PlotWorker<T> {
    pub(super) fn new(
        plot: T,
        metadata_directory: &Path,
        public_key: PublicKey,
        max_piece_count: u64,
    ) -> Result<Self, PlotError> {
        let piece_offset_to_index = PieceOffsetToIndexDb::open(
            &metadata_directory.join("plot-offset-to-index.bin"),
            max_piece_count,
        )
        .map_err(PlotError::OffsetDbOpen)?;

        let piece_index_hash_to_offset_db = IndexHashToOffsetDB::open_default(
            &metadata_directory.join("plot-index-to-offset"),
            public_key,
        )?;

        // TODO: handle `piece_count.load() > max_piece_count`, we should discard some of the pieces
        //  here

        Ok(Self {
            plot,
            piece_index_hash_to_offset_db,
            piece_offset_to_index,
            max_piece_count,
        })
    }

    pub(super) fn piece_count(&self) -> &Arc<AtomicU64> {
        self.piece_index_hash_to_offset_db.piece_count()
    }

    pub(super) fn run(mut self, requests_receiver: mpsc::Receiver<RequestWithPriority>) {
        let mut low_priority_requests = VecDeque::new();
        let mut exit_result_sender = None;

        // Process as many high priority as possible, interleaved with single low priority request
        // in case no high priority requests are available.
        'outer: while let Ok(request_with_priority) = requests_receiver.recv() {
            let RequestWithPriority {
                mut request,
                mut priority,
            } = request_with_priority;

            loop {
                if matches!(priority, RequestPriority::Low) {
                    low_priority_requests.push_back(request);
                } else {
                    match request {
                        Request::ReadEncoding {
                            index_hash,
                            result_sender,
                        } => {
                            let _ = result_sender.send(self.read_encoding(index_hash));
                        }
                        Request::ReadEncodingWithIndex {
                            piece_offset,
                            result_sender,
                        } => {
                            let result = try {
                                let mut buffer = Piece::default();
                                self.plot.read(piece_offset, &mut buffer)?;
                                let index =
                                    self.piece_offset_to_index.get_piece_index(piece_offset)?;
                                (buffer, index)
                            };
                            let _ = result_sender.send(result);
                        }
                        Request::ReadEncodings {
                            piece_offset,
                            count,
                            result_sender,
                        } => {
                            let result = try {
                                let mut buffer = vec![0u8; count as usize * PIECE_SIZE];
                                self.plot.read(piece_offset, &mut buffer)?;
                                buffer
                            };
                            let _ = result_sender.send(result);
                        }
                        Request::ReadPieceIndexes {
                            from_index_hash,
                            count,
                            result_sender,
                        } => {
                            let _ =
                                result_sender.send(self.read_piece_indexes(from_index_hash, count));
                        }
                        Request::GetPieceRange { result_sender } => {
                            let _ = result_sender
                                .send(self.piece_index_hash_to_offset_db.get_piece_range());
                        }
                        Request::WriteEncodings {
                            encodings,
                            piece_indexes,
                            result_sender,
                        } => {
                            let _ =
                                result_sender.send(self.write_encodings(encodings, piece_indexes));
                        }
                        Request::Exit { result_sender } => {
                            exit_result_sender.replace(result_sender);
                            break 'outer;
                        }
                    }
                }

                match requests_receiver.try_recv() {
                    Ok(some_request_with_priority) => {
                        request = some_request_with_priority.request;
                        priority = some_request_with_priority.priority;
                        continue;
                    }
                    Err(mpsc::TryRecvError::Empty) => {
                        // If no high priority requests available, process one low priority request.
                        if let Some(low_priority_request) = low_priority_requests.pop_front() {
                            request = low_priority_request;
                            priority = RequestPriority::High;
                            continue;
                        }
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        // Ignore
                    }
                }

                break;
            }
        }

        // Close the rest of databases
        drop(self);
    }

    fn read_encoding(&mut self, piece_index_hash: PieceIndexHash) -> io::Result<Piece> {
        let mut buffer = Piece::default();
        let offset = self
            .piece_index_hash_to_offset_db
            .get(piece_index_hash)?
            .ok_or_else(|| {
                io::Error::other(format!("Piece with hash {piece_index_hash:?} not found"))
            })?;
        self.plot.read(offset, &mut buffer).map(|()| buffer)
    }

    // TODO: Add error recovery
    fn write_encodings(
        &mut self,
        pieces: Arc<FlatPieces>,
        piece_indexes: Vec<PieceIndex>,
    ) -> io::Result<WriteResult> {
        let current_piece_count = self.piece_count().load(Ordering::SeqCst);
        let pieces_left_until_full_plot =
            (self.max_piece_count - current_piece_count).min(pieces.count() as u64);

        // Split pieces and indexes in those that can be appended to the end of plot (thus written
        // sequentially) and those that need to be checked individually and plotted one by one in
        // place of old pieces
        let (sequential_pieces, _) =
            pieces.split_at(pieces_left_until_full_plot as usize * PIECE_SIZE);
        // Iterator is more convenient for random pieces, otherwise we could take it from above
        let random_pieces = pieces
            .as_pieces()
            .skip(pieces_left_until_full_plot as usize);
        let (sequential_piece_indexes, random_piece_indexes) =
            piece_indexes.split_at(pieces_left_until_full_plot as usize);

        // Process sequential pieces
        {
            self.plot.write(sequential_pieces, current_piece_count)?;

            self.piece_index_hash_to_offset_db.batch_insert(
                sequential_piece_indexes
                    .iter()
                    .copied()
                    .map(PieceIndexHash::from_index)
                    .collect(),
                current_piece_count,
            )?;

            self.piece_offset_to_index
                .put_piece_indexes(current_piece_count, sequential_piece_indexes)?;
        }

        let mut piece_offsets = Vec::<Option<PieceOffset>>::with_capacity(pieces.count());
        piece_offsets.extend(
            (current_piece_count..)
                .take(pieces_left_until_full_plot as usize)
                .map(Some),
        );
        piece_offsets.resize(piece_offsets.capacity(), None);
        let mut evicted_pieces =
            Vec::with_capacity(pieces.count() - pieces_left_until_full_plot as usize);

        // Process random pieces
        for ((piece, &piece_index), maybe_piece_offset) in
            random_pieces.zip(random_piece_indexes).zip(
                piece_offsets
                    .iter_mut()
                    .skip(pieces_left_until_full_plot as usize),
            )
        {
            // Check if piece is out of plot range or if it is in the plot
            if !self
                .piece_index_hash_to_offset_db
                .should_store(PieceIndexHash::from_index(piece_index))
            {
                continue;
            }

            let piece_offset = self
                .piece_index_hash_to_offset_db
                .replace_furthest(PieceIndexHash::from_index(piece_index))?;

            let mut old_piece = Piece::default();
            self.plot.read(piece_offset, &mut old_piece)?;

            self.plot.write(piece, piece_offset)?;

            self.piece_offset_to_index
                .put_piece_index(piece_offset, piece_index)?;

            // TODO: This is a bit inefficient when pieces from previous iterations of this loop are
            //  evicted, causing extra tags overrides during recommitment
            maybe_piece_offset.replace(piece_offset);
            evicted_pieces.push(old_piece);
        }

        Ok(WriteResult {
            pieces,
            piece_offsets,
            evicted_pieces,
        })
    }

    fn read_piece_indexes(
        &mut self,
        from: PieceIndexHash,
        count: u64,
    ) -> io::Result<Vec<PieceIndex>> {
        self.piece_index_hash_to_offset_db
            .get_sequential(from, count as usize)
            .into_iter()
            .map(|(_, offset)| self.piece_offset_to_index.get_piece_index(offset))
            .collect()
    }
}
