use super::{sync, DSNSync, PieceIndexHashNumber, SyncOptions};
use crate::PiecesToPlot;
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::{Arc, Mutex};
use subspace_core_primitives::{Piece, PieceIndex, PieceIndexHash, PIECE_SIZE};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TestDSN(BTreeMap<PieceIndexHash, (Piece, PieceIndex)>);

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

    let source = (0u8..=255u8)
        .map(|i| ([i; PIECE_SIZE].into(), i as PieceIndex))
        .map(|(piece, index)| (index.into(), (piece, index)))
        .collect::<BTreeMap<_, _>>();
    let result = Arc::new(Mutex::new(BTreeMap::new()));

    sync(
        TestDSN(source.clone()),
        SyncOptions {
            pieces_per_request: 10,
            initial_range_size: PieceIndexHashNumber::MAX / 256,
            max_range_size: PieceIndexHashNumber::MAX / 3,
            address: Default::default(),
        },
        {
            let result = Arc::clone(&result);
            move |pieces, piece_indexes| {
                let mut result = result.lock().unwrap();
                result.extend(
                    pieces
                        .as_pieces()
                        .zip(piece_indexes)
                        .map(|(piece, index)| (index.into(), (piece.try_into().unwrap(), index))),
                );
                if result.len() == 256 {
                    std::ops::ControlFlow::Break(Ok(()))
                } else {
                    std::ops::ControlFlow::Continue(())
                }
            }
        },
    )
    .await
    .unwrap();

    assert_eq!(source, *result.lock().unwrap());
}
