use super::{sync, DSNSync, PieceIndexHashNumber, SyncOptions};
use crate::PiecesToPlot;
use std::{
    collections::BTreeMap,
    ops::Range,
    sync::{Arc, Mutex},
};
use subspace_core_primitives::{Piece, PieceIndex, PieceIndexHash, PIECE_SIZE};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TestDSN(BTreeMap<PieceIndexHash, (Piece, PieceIndex)>);

impl FromIterator<(Piece, PieceIndex)> for TestDSN {
    fn from_iter<T: IntoIterator<Item = (Piece, PieceIndex)>>(iter: T) -> Self {
        let map = iter
            .into_iter()
            .map(|(piece, index)| (index.into(), (piece, index)))
            .collect();
        Self(map)
    }
}

#[async_trait::async_trait]
impl DSNSync for TestDSN {
    type Stream = futures::stream::Once<futures::future::Ready<PiecesToPlot>>;

    async fn get_pieces(&mut self, Range { start, end }: Range<PieceIndexHash>) -> Self::Stream {
        let (pieces, piece_indexes) = self
            .0
            .iter()
            .skip_while(|(k, _)| **k < start)
            .take_while(|(k, _)| **k <= end)
            .fold(
                (Vec::<u8>::new(), Vec::<PieceIndex>::new()),
                |(mut flat_pieces, mut piece_indexes), (_, (piece, index))| {
                    flat_pieces.extend(piece.iter());
                    piece_indexes.push(*index);
                    (flat_pieces, piece_indexes)
                },
            );
        futures::stream::once(futures::future::ready(PiecesToPlot {
            pieces: pieces.try_into().unwrap(),
            piece_indexes,
        }))
    }
}

fn init() {
    let _ = tracing_subscriber::fmt::try_init();
}

#[tokio::test(flavor = "multi_thread")]
async fn simple_test() {
    init();
    let dsn = (0u8..=255u8)
        .map(|a| ([a; PIECE_SIZE].into(), a as PieceIndex))
        .collect::<TestDSN>();
    let new_dsn = Arc::new(Mutex::new(BTreeMap::<PieceIndexHash, (Piece, _)>::new()));

    sync(
        dsn.clone(),
        SyncOptions {
            pieces_per_request: 10,
            initial_range_size: PieceIndexHashNumber::MAX / 256,
            max_range_size: PieceIndexHashNumber::MAX / 3,
            address: Default::default(),
        },
        {
            let new_dsn = Arc::clone(&new_dsn);
            move |pieces, piece_indexes| {
                let mut new_dsn = new_dsn.lock().unwrap();
                new_dsn.extend(
                    pieces
                        .as_pieces()
                        .zip(piece_indexes)
                        .map(|(piece, index)| (index.into(), (piece.try_into().unwrap(), index))),
                );
                if new_dsn.len() == 256 {
                    std::ops::ControlFlow::Break(Ok(()))
                } else {
                    std::ops::ControlFlow::Continue(())
                }
            }
        },
    )
    .await
    .unwrap();

    assert_eq!(dsn, TestDSN(new_dsn.lock().unwrap().clone()));
}
