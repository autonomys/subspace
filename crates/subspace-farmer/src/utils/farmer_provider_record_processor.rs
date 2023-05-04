use crate::utils::piece_cache::PieceCache;
use crate::utils::readers_and_pieces::ReadersAndPieces;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::{Arc, Weak};
use subspace_core_primitives::{Blake2b256Hash, Piece, PieceIndexHash, BLAKE2B_256_HASH_SIZE};
use subspace_networking::libp2p::kad::handler::InboundStreamEventGuard;
use subspace_networking::libp2p::kad::ProviderRecord;
use subspace_networking::libp2p::multihash::Multihash;
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::MultihashCode;
use subspace_networking::utils::piece_announcement::announce_single_piece_index_hash_with_backoff;
use subspace_networking::{Node, PieceByHashRequest, PieceByHashResponse};
use tokio::sync::Semaphore;
use tracing::{debug, trace, warn};

pub struct FarmerProviderRecordProcessor<PC> {
    node: Node,
    piece_cache: Arc<tokio::sync::Mutex<PC>>,
    weak_readers_and_pieces: Weak<Mutex<Option<ReadersAndPieces>>>,
    announcements_semaphore: Arc<Semaphore>,
    re_announcements_semaphore: Arc<Semaphore>,
}

impl<PC> FarmerProviderRecordProcessor<PC>
where
    PC: PieceCache + Send + 'static,
{
    pub fn new(
        node: Node,
        piece_cache: Arc<tokio::sync::Mutex<PC>>,
        weak_readers_and_pieces: Weak<Mutex<Option<ReadersAndPieces>>>,
        max_concurrent_announcements: NonZeroUsize,
        max_concurrent_re_announcements: NonZeroUsize,
    ) -> Self {
        let announcements_semaphore = Arc::new(Semaphore::new(max_concurrent_announcements.get()));
        let re_announcements_semaphore =
            Arc::new(Semaphore::new(max_concurrent_re_announcements.get()));
        Self {
            node,
            piece_cache,
            weak_readers_and_pieces,
            announcements_semaphore,
            re_announcements_semaphore,
        }
    }

    pub async fn process_provider_record(
        &mut self,
        provider_record: ProviderRecord,
        guard: Arc<InboundStreamEventGuard>,
    ) {
        trace!(?provider_record.key, "Starting processing provider record...");

        let multihash = match Multihash::from_bytes(provider_record.key.as_ref()) {
            Ok(multihash) => multihash,
            Err(error) => {
                trace!(
                    ?provider_record.key,
                    %error,
                    "Record is not a correct multihash, ignoring"
                );
                return;
            }
        };

        if multihash.code() != u64::from(MultihashCode::PieceIndexHash) {
            trace!(
                ?provider_record.key,
                code = %multihash.code(),
                "Record is not a piece, ignoring"
            );
            return;
        }

        let piece_index_hash =
            Blake2b256Hash::try_from(&multihash.digest()[..BLAKE2B_256_HASH_SIZE])
                .expect(
                    "Multihash has 64-byte digest, which is sufficient for 32-byte Blake2b \
                    hash; qed",
                )
                .into();

        if let Some(readers_and_pieces) = self.weak_readers_and_pieces.upgrade() {
            if let Some(readers_and_pieces) = readers_and_pieces.lock().as_ref() {
                if readers_and_pieces.contains_piece(&piece_index_hash) {
                    // Piece is already plotted, hence it was also already announced
                    return;
                }
            }
        } else {
            // `ReadersAndPieces` was dropped, nothing left to be done
            return;
        }

        let Ok(permit) = Arc::clone(&self.announcements_semaphore).acquire_owned().await else {
            return;
        };

        let node = self.node.clone();
        let piece_cache = Arc::clone(&self.piece_cache);
        let re_announcements_semaphore = Arc::clone(&self.re_announcements_semaphore);

        tokio::spawn(async move {
            {
                let piece_cache = piece_cache.lock().await;

                if !piece_cache.should_cache(&provider_record.key) {
                    return;
                }

                if piece_cache.get_piece(&provider_record.key).is_some() {
                    trace!(key=?provider_record.key, "Skipped processing local piece...");
                    return;
                }

                // TODO: Store local intent to cache a piece such that we don't try to pull the same piece again
            }

            if let Some(piece) =
                get_piece_from_announcer(&node, piece_index_hash, provider_record.provider).await
            {
                {
                    let mut piece_cache = piece_cache.lock().await;

                    if !piece_cache.should_cache(&provider_record.key) {
                        return;
                    }

                    piece_cache.add_piece(provider_record.key.clone(), piece);
                }

                // Re-announcement is the slowest part of the process, we're moving it into a
                // separate background task with its own limit. Not re-announcing is not as bad as
                // not storing data in the first place.
                if let Ok(permit) = re_announcements_semaphore.try_acquire_owned() {
                    tokio::spawn(async move {
                        if let Err(error) =
                            announce_single_piece_index_hash_with_backoff(piece_index_hash, &node)
                                .await
                        {
                            debug!(
                                ?error,
                                ?piece_index_hash,
                                "Re-announcing cached piece index hash failed"
                            );
                        };

                        drop(permit);
                    });
                } else {
                    debug!(
                        ?piece_index_hash,
                        "Re-announcing cached piece index hash skipped due to reaching \
                        re-announcements limit"
                    );
                }
            }

            drop(permit);
            drop(guard);
        });
    }
}

async fn get_piece_from_announcer(
    node: &Node,
    piece_index_hash: PieceIndexHash,
    provider: PeerId,
) -> Option<Piece> {
    let request_result = node
        .send_generic_request(provider, PieceByHashRequest { piece_index_hash })
        .await;

    // TODO: Nothing guarantees that piece index hash is real, response must also return piece index
    //  that matches piece index hash and piece must be verified against blockchain after that
    match request_result {
        Ok(PieceByHashResponse { piece: Some(piece) }) => {
            trace!(
                %provider,
                ?piece_index_hash,
                "Piece request succeeded."
            );

            return Some(piece);
        }
        Ok(PieceByHashResponse { piece: None }) => {
            debug!(
                %provider,
                ?piece_index_hash,
                "Provider returned no piece right after announcement."
            );
        }
        Err(error) => {
            warn!(
                %provider,
                ?piece_index_hash,
                ?error,
                "Piece request to announcer provider failed."
            );
        }
    }

    None
}
