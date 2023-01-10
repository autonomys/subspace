use crate::commands::farm::ReadersAndPieces;
use parking_lot::Mutex;
use std::borrow::Cow;
use std::sync::Arc;
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::ProviderRecord;
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::MultihashCode;
use subspace_networking::{deconstruct_record_key, ProviderStorage, ToMultihash};

pub(crate) struct FixedProviderStorage {
    local_peer_id: PeerId,
    readers_and_pieces: Arc<Mutex<Option<ReadersAndPieces>>>,
}

impl FixedProviderStorage {
    pub(crate) fn new(
        local_peer_id: PeerId,
        readers_and_pieces: Arc<Mutex<Option<ReadersAndPieces>>>,
    ) -> Self {
        Self {
            local_peer_id,
            readers_and_pieces,
        }
    }
}

impl ProviderStorage for FixedProviderStorage {
    type ProvidedIter<'a> = impl Iterator<Item = Cow<'a, ProviderRecord>> where Self:'a;

    fn add_provider(
        &mut self,
        _: ProviderRecord,
    ) -> subspace_networking::libp2p::kad::store::Result<()> {
        // doesn't support this operation

        Ok(())
    }

    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        let (piece_index_hash, multihash_code) = deconstruct_record_key(key);

        if multihash_code != MultihashCode::Sector {
            return Vec::new();
        }

        if self
            .readers_and_pieces
            .lock()
            .as_ref()
            .expect("Should be populated at this point.")
            .pieces
            .contains_key(&piece_index_hash)
        {
            return vec![ProviderRecord {
                key: piece_index_hash
                    .to_multihash_by_code(MultihashCode::Sector)
                    .into(),
                provider: self.local_peer_id,
                expires: None,
                addresses: Vec::new(), // TODO: add address hints
            }];
        }

        Vec::new()
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
                    key: hash.to_multihash_by_code(MultihashCode::Sector).into(),
                    provider: self.local_peer_id,
                    expires: None,
                    addresses: Vec::new(), // TODO: add address hints
                }
            })
            .map(Cow::Owned)
            .collect::<Vec<_>>()
            .into_iter()
    }

    fn remove_provider(&mut self, _: &Key, _: &PeerId) {
        // doesn't support this operation
    }
}
