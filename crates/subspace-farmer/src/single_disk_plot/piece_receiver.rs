use async_trait::async_trait;
use parity_scale_codec::Decode;
use std::collections::BTreeSet;
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use subspace_core_primitives::{Piece, PieceIndex, PieceIndexHash};
use subspace_farmer_components::plotting::PieceReceiver;
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::MultihashCode;
use subspace_networking::{Node, PieceByHashRequest, PieceKey, ToMultihash};
use tokio::time::sleep;
use tracing::{debug, error, info, trace, warn};

/// Defines a duration between get_piece calls.
const GET_PIECE_WAITING_DURATION_IN_SECS: u64 = 1;

// Temporary struct serving pieces from different providers using configuration arguments.
pub(crate) struct MultiChannelPieceReceiver<'a> {
    dsn_node: Node,
    cancelled: &'a AtomicBool,
}

impl<'a> MultiChannelPieceReceiver<'a> {
    pub(crate) fn new(dsn_node: Node, cancelled: &'a AtomicBool) -> Self {
        Self {
            dsn_node,
            cancelled,
        }
    }

    fn check_cancellation(&self) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        if self.cancelled.load(Ordering::Acquire) {
            debug!("Getting a piece was cancelled.");

            return Err("Getting a piece was cancelled.".into());
        }

        Ok(())
    }

    // restore after fixing https://github.com/libp2p/rust-libp2p/issues/3048
    // Get from piece cache (L2) using providers
    #[allow(dead_code)]
    async fn get_piece_from_cache_by_providers(&self, _piece_index: PieceIndex) -> Option<Piece> {
        None

        // TODO: uncomment on fixing https://github.com/libp2p/rust-libp2p/issues/3048
        // let providers_result = dsn_node.get_providers(key).await;
        //
        // info!(?key, "get_providers result: {:?}", providers_result);
        //
        // for provider in providers_result? {
        //     let response_result = dsn_node
        //         .send_generic_request(
        //             provider,
        //             PieceByHashRequest {
        //                 key: PieceKey::PieceIndex(piece_index),
        //             },
        //         )
        //         .await;
        //
        //     info!(
        //         ?key,
        //         "send_generic_request for PieceByHashRequest result: {:?}", response_result
        //     );
        //
        //     if let Some(piece) = response_result?.piece {
        //         return Ok(Some(piece));
        //     }
        // }
    }

    // Get from piece cache (L2)
    async fn get_piece_from_cache(&self, piece_index: PieceIndex) -> Option<Piece> {
        let key = PieceIndexHash::from_index(piece_index).to_multihash();

        let piece_result = self.dsn_node.get_value(key).await;

        match piece_result {
            Ok(Some(piece)) => {
                trace!(%piece_index, ?key, "get_value returned a piece");

                match piece.try_into() {
                    Ok(piece) => {
                        return Some(piece);
                    }
                    Err(error) => {
                        error!(%piece_index, ?key, ?error, "Error on piece construction");
                    }
                }
            }
            Ok(None) => {
                debug!(%piece_index,?key, "get_value returned no piece");
            }
            Err(err) => {
                error!(%piece_index,?key, ?err, "get_value returned an error");
            }
        }

        None
    }

    // Get piece from archival storage (L1) from sectors. Log errors.
    async fn get_piece_from_archival_storage(&self, piece_index: PieceIndex) -> Option<Piece> {
        let key =
            PieceIndexHash::from_index(piece_index).to_multihash_by_code(MultihashCode::Sector);

        let piece_result = self.dsn_node.get_value(key).await;

        match piece_result {
            Ok(Some(encoded_gset)) => {
                trace!(
                    %piece_index,
                    ?key,
                    "get_value returned a piece-by-sector providers"
                );

                // Workaround for archival sector until we fix https://github.com/libp2p/rust-libp2p/issues/3048
                let peer_set =
                    if let Ok(set) = BTreeSet::<Vec<u8>>::decode(&mut encoded_gset.as_slice()) {
                        set
                    } else {
                        warn!(
                            %piece_index,
                            ?key,
                            "get_value returned a non-gset value"
                        );
                        return None;
                    };

                for peer_id in peer_set.into_iter() {
                    if let Ok(piece_provider_id) = PeerId::from_bytes(&peer_id) {
                        let request_result = self
                            .dsn_node
                            .send_generic_request(
                                piece_provider_id,
                                PieceByHashRequest {
                                    key: PieceKey::Sector(PieceIndexHash::from_index(piece_index)),
                                },
                            )
                            .await;

                        match request_result {
                            Ok(request) => {
                                if let Some(piece) = request.piece {
                                    return Some(piece);
                                }
                            }
                            Err(error) => {
                                error!(%piece_index,?peer_id, ?key, ?error, "Error on piece-by-hash request.");
                            }
                        }
                    } else {
                        error!(
                            %piece_index,
                            ?peer_id,
                            ?key,
                            "Cannot convert piece-by-sector provider PeerId from received bytes"
                        );
                    }
                }
            }
            Ok(None) => {
                info!(%piece_index,?key, "get_value returned no piece-by-sector provider");
            }
            Err(err) => {
                error!(%piece_index,?key, ?err, "get_value returned an error (piece-by-sector)");
            }
        }

        None
    }
}

#[async_trait]
impl<'a> PieceReceiver for MultiChannelPieceReceiver<'a> {
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        trace!(%piece_index, "Piece request.");

        // until we get a valid piece
        loop {
            self.check_cancellation()?;

            if let Some(piece) = self.get_piece_from_cache(piece_index).await {
                return Ok(Some(piece));
            }

            if let Some(piece) = self.get_piece_from_archival_storage(piece_index).await {
                return Ok(Some(piece));
            }

            warn!(%piece_index, "Couldn't get a piece from DSN. Starting a new attempt...");

            sleep(Duration::from_secs(GET_PIECE_WAITING_DURATION_IN_SECS)).await;
        }
    }
}
