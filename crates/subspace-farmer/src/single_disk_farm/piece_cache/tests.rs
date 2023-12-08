use crate::single_disk_farm::piece_cache::{DiskPieceCache, Offset};
use crate::single_disk_farm::DiskPieceCacheError;
use rand::prelude::*;
use std::assert_matches::assert_matches;
use subspace_core_primitives::{Piece, PieceIndex};
use tempfile::tempdir;

#[test]
fn basic() {
    let path = tempdir().unwrap();
    {
        let disk_piece_cache = DiskPieceCache::open(path.as_ref(), 2).unwrap();

        // Initially empty
        assert_eq!(
            disk_piece_cache
                .contents()
                .filter(|(_offset, maybe_piece_index)| maybe_piece_index.is_some())
                .count(),
            0
        );

        // Write first piece into cache
        {
            let offset = Offset(0);
            let piece_index = PieceIndex::ZERO;
            let piece = {
                let mut piece = Piece::default();
                thread_rng().fill(piece.as_mut());
                piece
            };

            assert_eq!(disk_piece_cache.read_piece_index(offset).unwrap(), None);
            assert!(disk_piece_cache.read_piece(offset).unwrap().is_none());

            disk_piece_cache
                .write_piece(offset, piece_index, &piece)
                .unwrap();

            assert_eq!(
                disk_piece_cache.read_piece_index(offset).unwrap(),
                Some(piece_index)
            );
            assert!(disk_piece_cache.read_piece(offset).unwrap().is_some());
        }

        // One piece stored
        assert_eq!(
            disk_piece_cache
                .contents()
                .filter(|(_offset, maybe_piece_index)| maybe_piece_index.is_some())
                .count(),
            1
        );

        // Write second piece into cache
        {
            let offset = Offset(1);
            let piece_index = PieceIndex::from(10);
            let piece = {
                let mut piece = Piece::default();
                thread_rng().fill(piece.as_mut());
                piece
            };

            assert_eq!(disk_piece_cache.read_piece_index(offset).unwrap(), None);
            assert!(disk_piece_cache.read_piece(offset).unwrap().is_none());

            disk_piece_cache
                .write_piece(offset, piece_index, &piece)
                .unwrap();

            assert_eq!(
                disk_piece_cache.read_piece_index(offset).unwrap(),
                Some(piece_index)
            );
            assert!(disk_piece_cache.read_piece(offset).unwrap().is_some());
        }

        // Two pieces stored
        assert_eq!(
            disk_piece_cache
                .contents()
                .filter(|(_offset, maybe_piece_index)| maybe_piece_index.is_some())
                .count(),
            2
        );

        // Writing beyond capacity fails
        assert_matches!(
            disk_piece_cache.write_piece(Offset(2), PieceIndex::ZERO, &Piece::default()),
            Err(DiskPieceCacheError::OffsetOutsideOfRange { .. })
        );

        // Override works
        {
            let offset = Offset(0);
            let piece_index = PieceIndex::from(13);
            let piece = {
                let mut piece = Piece::default();
                thread_rng().fill(piece.as_mut());
                piece
            };

            disk_piece_cache
                .write_piece(offset, piece_index, &piece)
                .unwrap();

            assert_eq!(
                disk_piece_cache.read_piece_index(offset).unwrap(),
                Some(piece_index)
            );
            assert!(disk_piece_cache.read_piece(offset).unwrap().is_some());
        }
    }

    // Reopening works
    {
        let disk_piece_cache = DiskPieceCache::open(path.as_ref(), 2).unwrap();
        // Two pieces stored
        assert_eq!(
            disk_piece_cache
                .contents()
                .filter(|(_offset, maybe_piece_index)| maybe_piece_index.is_some())
                .count(),
            2
        );
    }

    // Wiping works
    {
        DiskPieceCache::wipe(path.as_ref()).unwrap();

        let disk_piece_cache = DiskPieceCache::open(path.as_ref(), 2).unwrap();
        // Wiped successfully
        assert_eq!(
            disk_piece_cache
                .contents()
                .filter(|(_offset, maybe_piece_index)| maybe_piece_index.is_some())
                .count(),
            0
        );
    }
}
