use super::{sync, DSNSync, NoSync, PieceIndexHashNumber, SyncOptions};
use rand::Rng;
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::{Arc, Mutex};
use subspace_core_primitives::{Piece, PieceIndex, PieceIndexHash, PIECE_SIZE};
use subspace_networking::PiecesToPlot;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TestDSN(BTreeMap<PieceIndexHash, (Piece, PieceIndex)>);

#[async_trait::async_trait]
impl DSNSync for TestDSN {
    type Stream = futures::stream::Once<futures::future::Ready<PiecesToPlot>>;
    type Error = std::convert::Infallible;

    async fn get_pieces(
        &mut self,
        Range { start, end }: Range<PieceIndexHash>,
    ) -> Result<Self::Stream, Self::Error> {
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
        Ok(futures::stream::once(futures::future::ready(
            PiecesToPlot {
                pieces: pieces.try_into().unwrap(),
                piece_indexes,
            },
        )))
    }
}

fn init() {
    let _ = tracing_subscriber::fmt::try_init();
}

#[tokio::test(flavor = "multi_thread")]
async fn simple_test() {
    init();

    let source = (0u8..=255u8)
        .map(|i| {
            let mut piece = Piece::default();
            rand::thread_rng().fill(&mut piece[..]);
            (piece, i as PieceIndex)
        })
        .map(|(piece, index)| (index.into(), (piece, index)))
        .collect::<BTreeMap<_, _>>();
    let result = Arc::new(Mutex::new(BTreeMap::new()));

    sync(
        TestDSN(source.clone()),
        SyncOptions {
            range_size: PieceIndexHashNumber::MAX / 1024,
            public_key: Default::default(),
            max_plot_size: 100 * 1024 * 1024 * 1024 / PIECE_SIZE as u64,
            total_pieces: 256,
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

                Ok(())
            }
        },
    )
    .await
    .unwrap();

    assert_eq!(source, *result.lock().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn no_sync_test() {
    init();

    let result = Arc::new(Mutex::new(
        BTreeMap::<PieceIndexHash, (Piece, PieceIndex)>::new(),
    ));

    sync(
        NoSync,
        SyncOptions {
            range_size: PieceIndexHashNumber::MAX / 1024,
            public_key: Default::default(),
            max_plot_size: 100 * 1024 * 1024 * 1024 / PIECE_SIZE as u64,
            total_pieces: 0,
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
                Ok(())
            }
        },
    )
    .await
    .unwrap();

    assert!(result.lock().unwrap().is_empty())
}
