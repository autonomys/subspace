use crate::commands::farm::piece_storage::{LimitedSizePieceStorageWrapper, ParityDbPieceStorage};
use crate::commands::farm::ReadersAndPieces;
use crate::DsnArgs;
use async_trait::async_trait;
use futures::StreamExt;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndexHash, BLAKE2B_256_HASH_SIZE};
use subspace_networking::libp2p::identity::Keypair;
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::ProviderRecord;
use subspace_networking::libp2p::multihash::Multihash;
use subspace_networking::utils::multihash::MultihashCode;
use subspace_networking::{
    create, peer_id, BootstrappedNetworkingParameters, Config, CustomRecordStore,
    FixedProviderRecordStorage, LimitedSizeProviderStorageWrapper, NoRecordStorage, Node,
    NodeRunner, ParityDbProviderStorage, PieceByHashRequest, PieceByHashRequestHandler,
    PieceByHashResponse, PieceKey, ProviderRecordProcessor, ToMultihash,
};
use tokio::runtime::Handle;
use tracing::{debug, info, trace, warn};

const MAX_KADEMLIA_RECORDS_NUMBER: usize = 32768;

// Type alias for currently configured Kademlia's custom record store.
type ConfiguredRecordStore =
    CustomRecordStore<NoRecordStorage, LimitedSizeProviderStorageWrapper<ParityDbProviderStorage>>;

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
        NodeRunner<ConfiguredRecordStore>,
        impl FixedProviderRecordStorage,
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
    let default_config = Config::with_generated_keypair();
    let peer_id = peer_id(&keypair);

    let provider_storage = ParityDbProviderStorage::new(&provider_cache_db_path, peer_id)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    //TODO: rename CLI parameters
    let piece_storage = ParityDbPieceStorage::new(&record_cache_db_path)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let wrapped_piece_storage =
        LimitedSizePieceStorageWrapper::new(piece_storage.clone(), record_cache_size, peer_id);

    let config = Config::<ConfiguredRecordStore> {
        reserved_peers,
        keypair,
        listen_on,
        allow_non_global_addresses_in_dht: !disable_private_ips,
        networking_parameters_registry: BootstrappedNetworkingParameters::new(bootstrap_nodes)
            .boxed(),
        request_response_protocols: vec![PieceByHashRequestHandler::create(move |req| {
            let result = match req.key {
                PieceKey::ArchivalStorage(piece_index_hash) => {
                    debug!(key=?req.key, "Archival storage piece request received.");

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
                                    ?piece_index_hash,
                                    "Readers and pieces are not initialized yet"
                                );
                                return None;
                            }
                        };
                        let piece_details =
                            match readers_and_pieces.pieces.get(&piece_index_hash).copied() {
                                Some(piece_details) => piece_details,
                                None => {
                                    trace!(
                                        ?piece_index_hash,
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
                PieceKey::Cache(piece_index_hash) => {
                    debug!(key=?req.key, "Cache piece request received.");

                    piece_storage.get(&piece_index_hash.to_multihash().into())
                }
            };

            Some(PieceByHashResponse { piece: result })
        })],
        record_store: CustomRecordStore::new(
            NoRecordStorage,
            LimitedSizeProviderStorageWrapper::new(
                provider_storage.clone(),
                provider_cache_size,
                peer_id,
            ),
        ),
        ..default_config
    };

    create::<ConfiguredRecordStore>(config)
        .await
        .map(|(node, mut node_runner)| {
            let provider_record_processor =
                FarmerProviderRecordProcessor::new(node.clone(), wrapped_piece_storage);
            node_runner.replace_provider_record_provider(provider_record_processor.boxed());

            (node, node_runner, provider_storage)
        })
        .map_err(Into::into)
}

struct FarmerProviderRecordProcessor<PS: PieceStorage> {
    node: Node,
    piece_storage: PS,
}

impl<PS: PieceStorage> FarmerProviderRecordProcessor<PS> {
    fn new(node: Node, piece_storage: PS) -> Self {
        Self {
            node,
            piece_storage,
        }
    }

    pub fn boxed(self) -> Box<Self> {
        Box::new(self)
    }

    //TODO: consider introducing get-piece helper
    async fn get_piece(&self, piece_index_hash: PieceIndexHash) -> Option<Piece> {
        let multihash = piece_index_hash.to_multihash();
        let piece_key = PieceKey::Cache(piece_index_hash);

        let get_providers_result = self.node.get_providers(multihash).await;

        match get_providers_result {
            Ok(mut get_providers_stream) => {
                while let Some(provider_id) = get_providers_stream.next().await {
                    trace!(?multihash, %provider_id, "get_providers returned an item");

                    let request_result = self
                        .node
                        .send_generic_request(provider_id, PieceByHashRequest { key: piece_key })
                        .await;

                    match request_result {
                        Ok(PieceByHashResponse { piece: Some(piece) }) => {
                            trace!(%provider_id, ?multihash, ?piece_key, "Piece request succeeded.");
                            return Some(piece);
                        }
                        Ok(PieceByHashResponse { piece: None }) => {
                            debug!(%provider_id, ?multihash, ?piece_key, "Piece request returned empty piece.");
                        }
                        Err(error) => {
                            warn!(%provider_id, ?multihash, ?piece_key, ?error, "Piece request failed.");
                        }
                    }
                }
            }
            Err(err) => {
                warn!(
                    ?multihash,
                    ?piece_key,
                    ?err,
                    "get_providers returned an error"
                );
            }
        }

        None
    }

    //TODO: consider introducing publish-piece helper
    async fn announce_piece(&self, key: Multihash) {
        let result = self.node.start_announcing(key).await;

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
}

#[async_trait]
impl<PS: PieceStorage> ProviderRecordProcessor for FarmerProviderRecordProcessor<PS> {
    async fn process_provider_record(&mut self, rec: ProviderRecord) {
        let multihash_bytes = rec.key.to_vec();
        let multihash = Multihash::from_bytes(multihash_bytes.as_slice())
            .expect("Key should represent a valid multihash");

        if multihash.code() == u64::from(MultihashCode::PieceIndex) {
            info!(key=?rec.key, "Starting processing provider record...");

            if self.piece_storage.should_include_in_storage(&rec.key) {
                info!(key=?rec.key, "should_include_in_storage");
                let piece_index_hash: [u8; BLAKE2B_256_HASH_SIZE] = multihash.digest()
                    [..BLAKE2B_256_HASH_SIZE]
                    .try_into()
                    .expect("Multihash should be known 32 bytes size.");

                if let Some(piece) = self.get_piece(piece_index_hash.into()).await {
                    info!(key=?rec.key, "get_piece");
                    self.piece_storage.add_piece(rec.key.clone(), piece);
                    self.announce_piece(multihash).await;
                }
            }
        } else {
            info!(key=?rec.key, "Processing of the provider record cancelled.");
        }

        info!(key=?rec.key, "Finished processing provider record...");
    }
}

/// Defines persistent piece storage interface.
pub trait PieceStorage: Sync + Send + 'static {
    /// Check whether key should be inserted into the storage with current storage size and key-to-peer-id distance.
    fn should_include_in_storage(&self, key: &Key) -> bool;

    /// Add piece to the storage.
    fn add_piece(&mut self, key: Key, piece: Piece);

    /// Get piece from the storage.
    fn get_piece(&self, key: &Key) -> Option<Piece>;
}
