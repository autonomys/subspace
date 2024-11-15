use crate::disk_piece_cache::{DiskPieceCache, DiskPieceCacheError, PieceCacheOffset};
use rand::prelude::*;
use std::assert_matches::assert_matches;
use std::num::NonZeroU32;
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use tempfile::tempdir;

#[test]
fn basic() {
    let path = tempdir().unwrap();
    {
        let disk_piece_cache =
            DiskPieceCache::open(path.as_ref(), NonZeroU32::new(2).unwrap(), None, None).unwrap();

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
            let offset = PieceCacheOffset(0);
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
            let offset = PieceCacheOffset(1);
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
            disk_piece_cache.write_piece(PieceCacheOffset(2), PieceIndex::ZERO, &Piece::default()),
            Err(DiskPieceCacheError::OffsetOutsideOfRange { .. })
        );

        // Override works
        {
            let offset = PieceCacheOffset(0);
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
        let disk_piece_cache =
            DiskPieceCache::open(path.as_ref(), NonZeroU32::new(2).unwrap(), None, None).unwrap();
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

        let disk_piece_cache =
            DiskPieceCache::open(path.as_ref(), NonZeroU32::new(2).unwrap(), None, None).unwrap();
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
