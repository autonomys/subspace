use crate::commands::farm::farmer_provider_storage::FarmerProviderStorage;
use crate::commands::farm::piece_storage::{LimitedSizePieceStorageWrapper, ParityDbPieceStorage};
use crate::commands::farm::ReadersAndPieces;
use crate::DsnArgs;
use futures::StreamExt;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::{Blake2b256Hash, Piece, BLAKE2B_256_HASH_SIZE};
use subspace_networking::libp2p::identity::Keypair;
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::ProviderRecord;
use subspace_networking::libp2p::multihash::Multihash;
use subspace_networking::{
    create, peer_id, BootstrappedNetworkingParameters, Config, Node, NodeRunner,
    ParityDbProviderStorage, PieceByHashRequest, PieceByHashRequestHandler, PieceByHashResponse,
    ToMultihash,
};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tracing::{debug, info, trace, warn};

const MAX_KADEMLIA_RECORDS_NUMBER: usize = 32768;

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
        LimitedSizePieceStorageWrapper,
    ),
    anyhow::Error,
> {
    let record_cache_size = NonZeroUsize::new(record_cache_size).unwrap_or(
        NonZeroUsize::new(MAX_KADEMLIA_RECORDS_NUMBER)
            .expect("We don't expect an error on manually set value."),
    );
    let weak_readers_and_pieces = Arc::downgrade(readers_and_pieces);

    let record_cache_db_path = base_path.join("records_cache_db").into_boxed_path();
    let provider_cache_db_path = base_path.join("provider_cache_db").into_boxed_path();
    let provider_cache_size =
        record_cache_size.saturating_mul(NonZeroUsize::new(10).expect("10 > 0")); // TODO: add proper value

    info!(
        ?record_cache_db_path,
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
    let piece_storage = ParityDbPieceStorage::new(&record_cache_db_path)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let wrapped_piece_storage =
        LimitedSizePieceStorageWrapper::new(piece_storage.clone(), record_cache_size, peer_id);

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

                let piece_from_cache = piece_storage.get(&multihash.into());

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
        .map(|(node, node_runner)| (node, node_runner, wrapped_piece_storage))
        .map_err(Into::into)
}

// TODO: This should probably moved into the library
pub(crate) struct FarmerProviderRecordProcessor<PS> {
    node: Node,
    piece_storage: Arc<tokio::sync::Mutex<PS>>,
    semaphore: Arc<Semaphore>,
}

impl<PS> FarmerProviderRecordProcessor<PS>
where
    PS: PieceStorage + Send + 'static,
{
    pub fn new(node: Node, piece_storage: PS, max_concurrent_announcements: NonZeroUsize) -> Self {
        let semaphore = Arc::new(Semaphore::new(max_concurrent_announcements.get()));
        Self {
            node,
            piece_storage: Arc::new(tokio::sync::Mutex::new(piece_storage)),
            semaphore,
        }
    }

    pub async fn process_provider_record(&mut self, provider_record: ProviderRecord) {
        trace!(?provider_record.key, "Starting processing provider record...");

        let Ok(permit) = self.semaphore.clone().acquire_owned().await else {
            return;
        };

        let node = self.node.clone();
        let piece_storage = Arc::clone(&self.piece_storage);

        tokio::spawn(async move {
            {
                let piece_storage = piece_storage.lock().await;

                if !piece_storage.should_include_in_storage(&provider_record.key) {
                    return;
                }

                if piece_storage.get_piece(&provider_record.key).is_some() {
                    trace!(key=?provider_record.key, "Skipped processing local piece...");
                    return;
                }

                // TODO: Store local intent to cache a piece such that we don't try to pull the same piece again
            }

            if let Some(piece) = get_piece_from_announcer(&node, &provider_record).await {
                piece_storage
                    .lock()
                    .await
                    .add_piece(provider_record.key.clone(), piece);
                announce_piece(&node, provider_record.key).await;
            }

            drop(permit);
        });
    }
}

async fn get_piece_from_announcer(node: &Node, provider_record: &ProviderRecord) -> Option<Piece> {
    let multihash = Multihash::from_bytes(provider_record.key.as_ref())
        .expect("Key should represent a valid multihash");

    let piece_index_hash = Blake2b256Hash::try_from(&multihash.digest()[..BLAKE2B_256_HASH_SIZE])
        .expect("Multihash should be known 32 bytes size.")
        .into();

    let request_result = node
        .send_generic_request(
            provider_record.provider,
            PieceByHashRequest { piece_index_hash },
        )
        .await;

    match request_result {
        Ok(PieceByHashResponse { piece: Some(piece) }) => {
            trace!(
                %provider_record.provider,
                ?multihash,
                ?piece_index_hash,
                "Piece request succeeded."
            );

            return Some(piece);
        }
        Ok(PieceByHashResponse { piece: None }) => {
            debug!(
                %provider_record.provider,
                ?multihash,
                ?piece_index_hash,
                "Provider returned no piece right after announcement."
            );
        }
        Err(error) => {
            warn!(
                %provider_record.provider,
                ?multihash,
                ?piece_index_hash,
                ?error,
                "Piece request to announcer provider failed."
            );
        }
    }

    None
}

//TODO: consider introducing publish-piece helper
async fn announce_piece(node: &Node, key: Key) {
    let result = node.start_announcing(key.clone()).await;

    match result {
        Err(error) => {
            debug!(
                ?error,
                ?key,
                "Piece publishing for the cache returned an error"
            );
        }
        Ok(mut stream) => {
            if stream.next().await.is_some() {
                trace!(?key, "Piece publishing for the cache succeeded");
            } else {
                debug!(?key, "Piece publishing for the cache failed");
            }
        }
    };
}

/// Defines persistent piece storage interface.
pub trait PieceStorage: Sync + Send + 'static {
    /// Check whether key should be inserted into the storage with current storage size and
    /// key-to-peer-id distance.
    fn should_include_in_storage(&self, key: &Key) -> bool;

    /// Add piece to the storage.
    fn add_piece(&mut self, key: Key, piece: Piece);

    /// Get piece from the storage.
    fn get_piece(&self, key: &Key) -> Option<Piece>;
}
