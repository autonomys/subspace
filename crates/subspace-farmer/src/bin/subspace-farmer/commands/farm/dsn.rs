use crate::commands::farm::farmer_piece_cache::FarmerPieceCache;
use crate::commands::farm::farmer_provider_storage::FarmerProviderStorage;
use crate::commands::farm::ReadersAndPieces;
use crate::DsnArgs;
use event_listener_primitives::HandlerId;
use futures::channel::mpsc;
use futures::StreamExt;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::{fs, io, thread};
use subspace_core_primitives::{Blake2b256Hash, Piece, PieceIndexHash, BLAKE2B_256_HASH_SIZE};
use subspace_farmer::utils::parity_db_store::ParityDbStore;
use subspace_networking::libp2p::identity::Keypair;
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::ProviderRecord;
use subspace_networking::libp2p::multihash::Multihash;
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::{MultihashCode, ToMultihash};
use subspace_networking::utils::pieces::announce_single_piece_index_hash_with_backoff;
use subspace_networking::{
    create, peer_id, BootstrappedNetworkingParameters, Config, Node, NodeRunner,
    ParityDbProviderStorage, PieceByHashRequest, PieceByHashRequestHandler, PieceByHashResponse,
};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tracing::{debug, info, trace, warn, Instrument, Span};

const MAX_CONCURRENT_ANNOUNCEMENTS_QUEUE: usize = 2000;
const MAX_CONCURRENT_ANNOUNCEMENTS_PROCESSING: NonZeroUsize =
    NonZeroUsize::new(20).expect("Not zero; qed");

pub(super) async fn configure_dsn(
    base_path: PathBuf,
    keypair: Keypair,
    DsnArgs {
        listen_on,
        bootstrap_nodes,
        record_cache_size,
        disable_private_ips,
        reserved_peers,
    }: DsnArgs,
    readers_and_pieces: &Arc<Mutex<Option<ReadersAndPieces>>>,
) -> Result<
    (
        Node,
        NodeRunner<FarmerProviderStorage<ParityDbProviderStorage>>,
        FarmerPieceCache,
    ),
    anyhow::Error,
> {
    let weak_readers_and_pieces = Arc::downgrade(readers_and_pieces);

    let piece_cache_db_path = base_path.join("piece_cache_db");
    // TODO: Remove this migration code in the future
    {
        let records_cache_db_path = base_path.join("records_cache_db");
        if records_cache_db_path.exists() {
            fs::rename(&records_cache_db_path, &piece_cache_db_path)?;
        }
    }
    let provider_cache_db_path = base_path.join("provider_cache_db");
    let provider_cache_size =
        record_cache_size.saturating_mul(NonZeroUsize::new(10).expect("10 > 0")); // TODO: add proper value

    info!(
        ?piece_cache_db_path,
        ?record_cache_size,
        ?provider_cache_db_path,
        ?provider_cache_size,
        "Record cache DB configured."
    );

    let handle = Handle::current();
    let default_config = Config::default();
    let peer_id = peer_id(&keypair);

    let db_provider_storage =
        ParityDbProviderStorage::new(&provider_cache_db_path, provider_cache_size, peer_id)
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    let farmer_provider_storage =
        FarmerProviderStorage::new(peer_id, readers_and_pieces.clone(), db_provider_storage);

    //TODO: rename CLI parameters
    let piece_store =
        ParityDbStore::new(&piece_cache_db_path).map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let piece_cache = FarmerPieceCache::new(piece_store.clone(), record_cache_size, peer_id);

    let config = Config {
        reserved_peers,
        keypair,
        listen_on,
        allow_non_global_addresses_in_dht: !disable_private_ips,
        networking_parameters_registry: BootstrappedNetworkingParameters::new(bootstrap_nodes)
            .boxed(),
        request_response_protocols: vec![PieceByHashRequestHandler::create(move |req| {
            let result = {
                debug!(piece_index_hash = ?req.piece_index_hash, "Piece request received. Trying cache...");
                let multihash = req.piece_index_hash.to_multihash();

                let piece_from_cache = piece_store.get(&multihash.into());

                if piece_from_cache.is_some() {
                    piece_from_cache
                } else {
                    debug!(piece_index_hash = ?req.piece_index_hash, "No piece in the cache. Trying archival storage...");

                    let (mut reader, piece_details) = {
                        let readers_and_pieces = match weak_readers_and_pieces.upgrade() {
                            Some(readers_and_pieces) => readers_and_pieces,
                            None => {
                                debug!("A readers and pieces are already dropped");
                                return None;
                            }
                        };
                        let readers_and_pieces = readers_and_pieces.lock();
                        let readers_and_pieces = match readers_and_pieces.as_ref() {
                            Some(readers_and_pieces) => readers_and_pieces,
                            None => {
                                debug!(
                                    ?req.piece_index_hash,
                                    "Readers and pieces are not initialized yet"
                                );
                                return None;
                            }
                        };
                        let piece_details = match readers_and_pieces
                            .pieces
                            .get(&req.piece_index_hash)
                            .copied()
                        {
                            Some(piece_details) => piece_details,
                            None => {
                                trace!(
                                    ?req.piece_index_hash,
                                    "Piece is not stored in any of the local plots"
                                );
                                return None;
                            }
                        };
                        let reader = readers_and_pieces
                            .readers
                            .get(piece_details.plot_offset)
                            .cloned()
                            .expect("Offsets strictly correspond to existing plots; qed");
                        (reader, piece_details)
                    };

                    let handle = handle.clone();
                    tokio::task::block_in_place(move || {
                        handle.block_on(
                            reader
                                .read_piece(piece_details.sector_index, piece_details.piece_offset),
                        )
                    })
                }
            };

            Some(PieceByHashResponse { piece: result })
        })],
        provider_storage: farmer_provider_storage,
        ..default_config
    };

    create(config)
        .await
        .map(|(node, node_runner)| (node, node_runner, piece_cache))
        .map_err(Into::into)
}

/// Start processing announcements received by the network node, returns handle that will stop
/// processing on drop.
pub(crate) fn start_announcements_processor(
    node: Node,
    piece_cache: Arc<tokio::sync::Mutex<FarmerPieceCache>>,
    weak_readers_and_pieces: Weak<Mutex<Option<ReadersAndPieces>>>,
) -> io::Result<HandlerId> {
    let (provider_records_sender, mut provider_records_receiver) =
        mpsc::channel(MAX_CONCURRENT_ANNOUNCEMENTS_QUEUE);

    let handler_id = node.on_announcement(Arc::new({
        let provider_records_sender = Mutex::new(provider_records_sender);

        move |record| {
            if let Err(error) = provider_records_sender.lock().try_send(record.clone()) {
                if error.is_disconnected() {
                    // Receiver exited, nothing left to be done
                    return;
                }
                let record = error.into_inner();
                warn!(
                    ?record.key,
                    ?record.provider,
                    "Failed to add provider record to the channel."
                );
            };
        }
    }));

    let handle = Handle::current();
    let span = Span::current();
    let mut provider_record_processor = FarmerProviderRecordProcessor::new(
        node,
        piece_cache,
        weak_readers_and_pieces.clone(),
        MAX_CONCURRENT_ANNOUNCEMENTS_PROCESSING,
    );

    // We are working with database internally, better to run in a separate thread
    thread::Builder::new()
        .name("ann-processor".to_string())
        .spawn(move || {
            let processor_fut = async {
                while let Some(provider_record) = provider_records_receiver.next().await {
                    if weak_readers_and_pieces.upgrade().is_none() {
                        // `ReadersAndPieces` was dropped, nothing left to be done
                        return;
                    }
                    provider_record_processor
                        .process_provider_record(provider_record)
                        .await;
                }
            };

            handle.block_on(processor_fut.instrument(span));
        })?;

    Ok(handler_id)
}

// TODO: This should probably moved into the library
pub(crate) struct FarmerProviderRecordProcessor<PC> {
    node: Node,
    piece_cache: Arc<tokio::sync::Mutex<PC>>,
    weak_readers_and_pieces: Weak<Mutex<Option<ReadersAndPieces>>>,
    semaphore: Arc<Semaphore>,
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
    ) -> Self {
        let semaphore = Arc::new(Semaphore::new(max_concurrent_announcements.get()));
        Self {
            node,
            piece_cache,
            weak_readers_and_pieces,
            semaphore,
        }
    }

    pub async fn process_provider_record(&mut self, provider_record: ProviderRecord) {
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
                if readers_and_pieces.pieces.contains_key(&piece_index_hash) {
                    // Piece is already plotted, hence it was also already announced
                    return;
                }
            }
        } else {
            // `ReadersAndPieces` was dropped, nothing left to be done
            return;
        }

        let Ok(permit) = self.semaphore.clone().acquire_owned().await else {
            return;
        };

        let node = self.node.clone();
        let piece_cache = Arc::clone(&self.piece_cache);

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
                if let Err(error) =
                    announce_single_piece_index_hash_with_backoff(piece_index_hash, &node).await
                {
                    debug!(
                        ?error,
                        ?piece_index_hash,
                        "Announcing cached piece index hash failed"
                    );
                }
            }

            drop(permit);
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

/// Defines persistent piece cache interface.
pub trait PieceCache: Sync + Send + 'static {
    /// Check whether key should be cached based on current cache size and key-to-peer-id distance.
    fn should_cache(&self, key: &Key) -> bool;

    /// Add piece to the cache.
    fn add_piece(&mut self, key: Key, piece: Piece);

    /// Get piece from the cache.
    fn get_piece(&self, key: &Key) -> Option<Piece>;
}
