use crate::plot::PieceOffset;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use subspace_core_primitives::PieceIndex;

pub(super) struct PieceOffsetToIndexDb(File);

impl PieceOffsetToIndexDb {
    pub(super) fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .map(Self)
    }

    pub(super) fn get_piece_index(&mut self, offset: PieceOffset) -> io::Result<PieceIndex> {
        let mut buf = [0; 8];
        self.0.seek(SeekFrom::Start(
            offset * std::mem::size_of::<PieceIndex>() as u64,
        ))?;
        self.0.read_exact(&mut buf)?;
        Ok(PieceIndex::from_le_bytes(buf))
    }

    pub(super) fn put_piece_index(
        &mut self,
        offset: PieceOffset,
        piece_index: PieceIndex,
    ) -> io::Result<()> {
        self.0.seek(SeekFrom::Start(
            offset * std::mem::size_of::<PieceIndex>() as u64,
        ))?;
        self.0.write_all(&piece_index.to_le_bytes())
    }

    pub(super) fn put_piece_indexes(
        &mut self,
        start_offset: PieceOffset,
        piece_indexes: &[PieceIndex],
    ) -> io::Result<()> {
        self.0.seek(SeekFrom::Start(
            start_offset * std::mem::size_of::<PieceIndex>() as u64,
        ))?;
        let piece_indexes = piece_indexes
            .iter()
            .flat_map(|piece_index| piece_index.to_le_bytes())
            .collect::<Vec<_>>();
        self.0.write_all(&piece_indexes)
    }
}
