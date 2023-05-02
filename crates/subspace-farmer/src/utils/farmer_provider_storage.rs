use crate::utils::piece_cache::PieceCache;
use crate::utils::readers_and_pieces::ReadersAndPieces;
use parking_lot::Mutex;
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;
use subspace_core_primitives::{Blake2b256Hash, BLAKE2B_256_HASH_SIZE};
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::ProviderRecord;
use subspace_networking::libp2p::multihash::Multihash;
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::{MultihashCode, ToMultihash};
use subspace_networking::ProviderStorage;
use tracing::trace;

#[derive(Clone)]
pub struct FarmerProviderStorage<PersistentProviderStorage: Clone, LocalPieceCache: Clone> {
    local_peer_id: PeerId,
    readers_and_pieces: Arc<Mutex<Option<ReadersAndPieces>>>,
    persistent_provider_storage: PersistentProviderStorage,
    piece_cache: LocalPieceCache,
}

impl<PersistentProviderStorage, LocalPieceCache>
    FarmerProviderStorage<PersistentProviderStorage, LocalPieceCache>
where
    PersistentProviderStorage: ProviderStorage + Clone,
    LocalPieceCache: PieceCache + Clone,
{
    pub fn new(
        local_peer_id: PeerId,
        readers_and_pieces: Arc<Mutex<Option<ReadersAndPieces>>>,
        persistent_provider_storage: PersistentProviderStorage,
        piece_cache: LocalPieceCache,
    ) -> Self {
        Self {
            local_peer_id,
            readers_and_pieces,
            persistent_provider_storage,
            piece_cache,
        }
    }
}

impl<PersistentProviderStorage, LocalPieceCache> ProviderStorage
    for FarmerProviderStorage<PersistentProviderStorage, LocalPieceCache>
where
    PersistentProviderStorage: ProviderStorage + Clone,
    LocalPieceCache: PieceCache + Clone,
{
    type ProvidedIter<'a> = impl Iterator<Item = Cow<'a, ProviderRecord>>
    where
        Self:'a;

    fn add_provider(
        &mut self,
        record: ProviderRecord,
    ) -> subspace_networking::libp2p::kad::store::Result<()> {
        // Local providers are implicit and should not be put into persistent storage
        if record.provider != self.local_peer_id {
            self.persistent_provider_storage.add_provider(record)
        } else {
            Ok(())
        }
    }

    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        let multihash = match Multihash::from_bytes(key.as_ref()) {
            Ok(multihash) => multihash,
            Err(error) => {
                trace!(
                    ?key,
                    %error,
                    "Record is not a correct multihash, ignoring"
                );
                return Vec::new();
            }
        };

        if multihash.code() != u64::from(MultihashCode::PieceIndexHash) {
            trace!(
                ?key,
                code = %multihash.code(),
                "Record is not a piece, ignoring"
            );
            return Vec::new();
        }

        let piece_index_hash =
            Blake2b256Hash::try_from(&multihash.digest()[..BLAKE2B_256_HASH_SIZE])
                .expect(
                    "Multihash has 64-byte digest, which is sufficient for 32-byte Blake2b \
                    hash; qed",
                )
                .into();

        let mut provider_records = self.persistent_provider_storage.providers(key);

        // `ReadersAndPieces` is much cheaper than getting from piece cache, so try it first
        if self
            .readers_and_pieces
            .lock()
            .as_ref()
            .expect("Should be populated at this point.")
            .contains_piece(&piece_index_hash)
            || self.piece_cache.get_piece(key).is_some()
        {
            provider_records.push(ProviderRecord {
                key: piece_index_hash.to_multihash().into(),
                provider: self.local_peer_id,
                expires: None,
                addresses: Vec::new(), // Kademlia adds addresses for local providers
            });
        }

        provider_records
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        // We are not using interior mutability in this context, so this is fine
        #[allow(clippy::mutable_key_type)]
        let provided_by_cache = self.piece_cache.keys().into_iter().collect::<HashSet<_>>();
        let provided_by_plots = self
            .readers_and_pieces
            .lock()
            .as_ref()
            .map(|readers_and_pieces| {
                readers_and_pieces
                    .piece_index_hashes()
                    .filter_map(|hash| {
                        let key = hash.to_multihash().into();

                        if provided_by_cache.contains(&key) {
                            None
                        } else {
                            Some(key)
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        provided_by_cache
            .into_iter()
            .chain(provided_by_plots)
            .map(|key| {
                ProviderRecord {
                    key,
                    provider: self.local_peer_id,
                    expires: None,
                    addresses: Vec::new(), // Kademlia adds addresses for local providers
                }
            })
            .map(Cow::Owned)
            .chain(self.persistent_provider_storage.provided())
    }

    fn remove_provider(&mut self, key: &Key, peer_id: &PeerId) {
        self.persistent_provider_storage
            .remove_provider(key, peer_id);
    }
}
