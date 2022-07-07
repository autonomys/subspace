use crate::file_ext::FileExt;
use crate::plot::PieceOffset;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;
use subspace_core_primitives::PieceIndex;

pub(super) struct PieceOffsetToIndexDb(File);

const PIECE_INDEX_SIZE: u64 = std::mem::size_of::<PieceIndex>() as u64;

impl PieceOffsetToIndexDb {
    pub(super) fn open(path: &Path, max_piece_count: u64) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        file.preallocate(max_piece_count * PIECE_INDEX_SIZE)?;
        file.advise_random_access()?;

        Ok(Self(file))
    }

    pub(super) fn get_piece_index(&mut self, offset: PieceOffset) -> io::Result<PieceIndex> {
        let mut buf = [0; 8];
        self.0.read_exact_at(&mut buf, offset * PIECE_INDEX_SIZE)?;
        Ok(PieceIndex::from_le_bytes(buf))
    }

    pub(super) fn put_piece_index(
        &mut self,
        offset: PieceOffset,
        piece_index: PieceIndex,
    ) -> io::Result<()> {
        self.0
            .write_all_at(&piece_index.to_le_bytes(), offset * PIECE_INDEX_SIZE)
    }

    pub(super) fn put_piece_indexes(
        &mut self,
        start_offset: PieceOffset,
        piece_indexes: &[PieceIndex],
    ) -> io::Result<()> {
        let piece_indexes = piece_indexes
            .iter()
            .flat_map(|piece_index| piece_index.to_le_bytes())
            .collect::<Vec<_>>();
        self.0
            .write_all_at(&piece_indexes, start_offset * PIECE_INDEX_SIZE)
    }
}
