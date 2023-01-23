use crate::commands::farm::ReadersAndPieces;
use parking_lot::Mutex;
use std::borrow::Cow;
use std::sync::Arc;
use subspace_core_primitives::{Blake2b256Hash, BLAKE2B_256_HASH_SIZE};
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::ProviderRecord;
use subspace_networking::libp2p::multihash::Multihash;
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::{MultihashCode, ToMultihash};
use subspace_networking::ProviderStorage;

use tracing::trace;

pub(crate) struct FarmerProviderStorage<PersistentProviderStorage> {
    local_peer_id: PeerId,
    readers_and_pieces: Arc<Mutex<Option<ReadersAndPieces>>>,
    persistent_provider_storage: PersistentProviderStorage,
}

impl<PersistentProviderStorage> FarmerProviderStorage<PersistentProviderStorage> {
    pub(crate) fn new(
        local_peer_id: PeerId,
        readers_and_pieces: Arc<Mutex<Option<ReadersAndPieces>>>,
        persistent_provider_storage: PersistentProviderStorage,
    ) -> Self {
        Self {
            local_peer_id,
            readers_and_pieces,
            persistent_provider_storage,
        }
    }
}

impl<PersistentProviderStorage> ProviderStorage for FarmerProviderStorage<PersistentProviderStorage>
where
    PersistentProviderStorage: ProviderStorage,
{
    type ProvidedIter<'a> = impl Iterator<Item = Cow<'a, ProviderRecord>> where Self:'a;

    fn add_provider(
        &mut self,
        record: ProviderRecord,
    ) -> subspace_networking::libp2p::kad::store::Result<()> {
        self.persistent_provider_storage.add_provider(record)
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

        if self
            .readers_and_pieces
            .lock()
            .as_ref()
            .expect("Should be populated at this point.")
            .pieces
            .contains_key(&piece_index_hash)
        {
            provider_records.push(ProviderRecord {
                key: piece_index_hash.to_multihash().into(),
                provider: self.local_peer_id,
                expires: None,
                addresses: Vec::new(), // TODO: add address hints
            });
        }

        provider_records
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        self.readers_and_pieces
            .lock()
            .as_ref()
            .expect("Should be populated at this point.")
            .pieces
            .keys()
            .map(|hash| {
                ProviderRecord {
                    key: hash.to_multihash().into(),
                    provider: self.local_peer_id,
                    expires: None,
                    addresses: Vec::new(), // TODO: add address hints
                }
            })
            .map(Cow::Owned)
            .collect::<Vec<_>>()
            .into_iter()
            .chain(self.persistent_provider_storage.provided())
    }

    fn remove_provider(&mut self, key: &Key, peer_id: &PeerId) {
        self.persistent_provider_storage
            .remove_provider(key, peer_id)
    }
}
