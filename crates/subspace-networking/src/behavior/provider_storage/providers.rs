#[cfg(test)]
mod tests;

use super::ProviderStorage;
use crate::utils::record_binary_heap::RecordBinaryHeap;
use either::Either;
use libp2p::kad::record::Key;
use libp2p::kad::store::{MemoryStoreConfig, RecordStore};
use libp2p::kad::{store, ProviderRecord, K_VALUE};
use libp2p::{Multiaddr, PeerId};
use parity_db::{ColumnOptions, Db, Options};
use parity_scale_codec::{Decode, Encode};
use std::borrow::{Borrow, Cow};
use std::collections::{hash_set, BTreeMap};
use std::iter;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tracing::{debug, error, info, trace, warn};

// Defines max provider records number. Each provider record is expected to be less than 1KB.
const MEMORY_STORE_PROVIDED_KEY_LIMIT: usize = 100000; // ~100 MB

const PARITY_DB_ALL_PROVIDERS_COLUMN_NAME: u8 = 0;
const PARITY_DB_LOCAL_PROVIDER_COLUMN_NAME: u8 = 1;

/// Memory based provider records storage.
pub struct MemoryProviderStorage {
    inner: store::MemoryStore,
}

impl MemoryProviderStorage {
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            inner: store::MemoryStore::with_config(
                peer_id,
                MemoryStoreConfig {
                    max_records: 0,
                    max_value_bytes: 0,
                    max_providers_per_key: K_VALUE.get(),
                    max_provided_keys: MEMORY_STORE_PROVIDED_KEY_LIMIT,
                },
            ),
        }
    }
}

impl ProviderStorage for MemoryProviderStorage {
    type ProvidedIter<'a> = iter::Map<
        hash_set::Iter<'a, ProviderRecord>,
        fn(&'a ProviderRecord) -> Cow<'a, ProviderRecord>,
    > where Self:'a;

    fn add_provider(&mut self, record: ProviderRecord) -> store::Result<()> {
        trace!("New provider record added: {:?}", record);

        self.inner.add_provider(record)
    }

    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        self.inner.providers(key)
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        self.inner.provided()
    }

    fn remove_provider(&mut self, key: &Key, provider: &PeerId) {
        trace!(?key, ?provider, "Provider record removed.");

        self.inner.remove_provider(key, provider)
    }
}

#[derive(Clone, Debug, Decode, Encode, Default)]
struct ParityDbProviderCollection {
    // Provider PeerID -> ProviderRecord
    map: BTreeMap<Vec<u8>, ParityDbProviderRecord>,
}

impl From<ParityDbProviderCollection> for Vec<u8> {
    fn from(value: ParityDbProviderCollection) -> Self {
        value.encode()
    }
}

impl TryFrom<Vec<u8>> for ParityDbProviderCollection {
    type Error = parity_scale_codec::Error;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        ParityDbProviderCollection::decode(&mut data.as_slice()).map(Into::into)
    }
}

impl ParityDbProviderCollection {
    fn to_vec(&self) -> Vec<u8> {
        self.clone().into()
    }

    fn add_provider(&mut self, rec: ParityDbProviderRecord) {
        self.map.insert(rec.provider.clone(), rec);
    }

    fn remove_provider(&mut self, provider: Vec<u8>) {
        self.map.remove(&provider);
    }

    fn providers(&self) -> impl Iterator<Item = ParityDbProviderRecord> + '_ {
        self.map.values().cloned()
    }
}

#[derive(Clone, Debug, Decode, Encode)]
struct ParityDbProviderRecord {
    // Key of the record.
    key: Vec<u8>,
    // Provider peer ID.
    provider: Vec<u8>,
    // The expiration time as measured by a local, monotonic clock.
    expires: Option<u64>,
    // Provider addresses.
    addresses: Vec<Vec<u8>>,
}

impl From<ParityDbProviderRecord> for Vec<u8> {
    fn from(rec: ParityDbProviderRecord) -> Self {
        rec.encode()
    }
}

impl TryFrom<Vec<u8>> for ParityDbProviderRecord {
    type Error = parity_scale_codec::Error;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        ParityDbProviderRecord::decode(&mut data.as_slice()).map(Into::into)
    }
}

impl From<ProviderRecord> for ParityDbProviderRecord {
    fn from(rec: ProviderRecord) -> Self {
        Self {
            key: rec.key.to_vec(),
            provider: rec.provider.to_bytes(),
            addresses: rec.addresses.iter().map(|a| a.to_vec()).collect(),
            expires: rec.expires.map(instant_to_micros),
        }
    }
}

impl From<ParityDbProviderRecord> for ProviderRecord {
    // We don't expect an error here because ParityDbRecord contains valid bytes
    // representations.
    fn from(rec: ParityDbProviderRecord) -> Self {
        Self {
            key: rec.key.into(),
            provider: rec
                .provider
                .try_into()
                .expect("Peer ID should be valid in bytes representation."),
            addresses: rec
                .addresses
                .into_iter()
                // We don't expect an error here because ParityDbRecord contains a bytes
                // representation of the valid PeerId.
                .map(|addr| {
                    Multiaddr::try_from(addr)
                        .expect("Multiaddr should be valid in bytes representation.")
                })
                .collect::<Vec<_>>(),
            expires: rec.expires.map(micros_to_instant).unwrap_or_default(),
        }
    }
}

/// Defines provider record storage with DB persistence
#[derive(Clone)]
pub struct ParityDbProviderStorage {
    /// Parity DB instance
    db: Arc<Db>,
    /// Maintains a heap to limit total item number.
    heap: RecordBinaryHeap,
    /// Local provider PeerID
    local_peer_id: PeerId,
}

impl ParityDbProviderStorage {
    pub fn new(
        path: &Path,
        max_items_limit: NonZeroUsize,
        local_peer_id: PeerId,
    ) -> Result<Self, parity_db::Error> {
        let mut options = Options::with_columns(path, 2);
        options.columns = vec![
            ColumnOptions {
                // all providers
                btree_index: true,
                ..Default::default()
            },
            ColumnOptions {
                // local providers
                btree_index: true,
                ..Default::default()
            },
        ];

        // We don't use stats
        options.stats = false;

        let db = Db::open_or_create(&options)?;

        let mut heap = RecordBinaryHeap::new(local_peer_id, max_items_limit.get());

        let known_providers = {
            let rec_iter_result: Result<
                ParityDbProviderRecordCollectionIterator,
                parity_db::Error,
            > = try {
                let btree_iter = db.iter(PARITY_DB_ALL_PROVIDERS_COLUMN_NAME)?;
                ParityDbProviderRecordCollectionIterator::new(btree_iter)?
            };

            match rec_iter_result {
                Ok(rec_iter) => rec_iter,
                Err(err) => {
                    error!(?err, "Can't create Parity DB record storage iterator.");

                    ParityDbProviderRecordCollectionIterator::empty()
                }
            }
        };

        // Initial cache loading.
        for rec in known_providers {
            let _ = heap.insert(rec.key.clone());
        }

        if heap.size() > 0 {
            info!(size = heap.size(), ?path, "Record cache loaded.");
        } else {
            info!(?path, "New record cache initialized.");
        }

        Ok(Self {
            db: Arc::new(db),
            heap,
            local_peer_id,
        })
    }

    fn add_provider_to_db(&self, key: &Key, rec: ParityDbProviderRecord) {
        let mut providers = self.load_providers(key).unwrap_or_default();

        providers.add_provider(rec);

        self.save_providers(key, providers);
    }

    fn remove_provider_from_db(&self, key: &Key, provider: Vec<u8>) {
        let mut providers = self.load_providers(key).unwrap_or_default();

        providers.remove_provider(provider);

        self.save_providers(key, providers);
    }

    fn remove_providers_from_db(&self, key: &Key) {
        let tx = [(PARITY_DB_ALL_PROVIDERS_COLUMN_NAME, key, None)];

        let result = self.db.commit(tx);
        if let Err(err) = &result {
            error!(?key, ?err, "Failed to delete providers from Parity DB.");
        }
    }

    fn add_local_provider_to_db(&self, key: &Key, rec: ParityDbProviderRecord) {
        let key: &[u8] = key.borrow();

        let tx = [(PARITY_DB_LOCAL_PROVIDER_COLUMN_NAME, key, Some(rec.into()))];

        let result = self.db.commit(tx);
        if let Err(err) = &result {
            error!(?key, ?err, "Local provider DB adding error.");
        }
    }

    fn remove_local_provider_to_db(&self, key: &Key) {
        let key: &[u8] = key.borrow();

        let tx = [(PARITY_DB_LOCAL_PROVIDER_COLUMN_NAME, key, None)];

        let result = self.db.commit(tx);
        if let Err(err) = &result {
            error!(?key, ?err, "Local provider DB removing error.");
        }
    }

    fn save_providers(&self, key: &Key, providers: ParityDbProviderCollection) -> bool {
        let key: &[u8] = key.borrow();

        let tx = [(
            PARITY_DB_ALL_PROVIDERS_COLUMN_NAME,
            key,
            Some(providers.to_vec()),
        )];

        let result = self.db.commit(tx);
        if let Err(err) = &result {
            error!(?key, ?err, "DB saving error.");
        }

        result.is_ok()
    }

    fn load_providers(&self, key: &Key) -> Option<ParityDbProviderCollection> {
        let result = self
            .db
            .get(PARITY_DB_ALL_PROVIDERS_COLUMN_NAME, key.borrow());

        match result {
            Ok(Some(data)) => {
                let db_rec_result: Result<ParityDbProviderCollection, _> = data.try_into();

                match db_rec_result {
                    Ok(db_rec) => {
                        trace!(?key, "Provider record loaded successfully from DB");

                        Some(db_rec)
                    }
                    Err(err) => {
                        debug!(
                            ?key,
                            ?err,
                            "Parity DB provider record deserialization error"
                        );

                        None
                    }
                }
            }
            Ok(None) => {
                trace!(?key, "No Parity DB record for given key");

                None
            }
            Err(err) => {
                debug!(?key, ?err, "Parity DB record storage error");

                None
            }
        }
    }
}

impl ProviderStorage for ParityDbProviderStorage {
    type ProvidedIter<'a> = ParityDbProviderRecordIterator<'a> where Self:'a;

    fn add_provider(&mut self, record: ProviderRecord) -> store::Result<()> {
        let record_key = record.key.clone();
        let provider_peer_id = record.provider;

        trace!(?record_key, provider=%record.provider, "Saving a provider to DB");

        let db_rec = ParityDbProviderRecord::from(record);

        if provider_peer_id == self.local_peer_id {
            self.add_local_provider_to_db(&record_key, db_rec.clone());
        }

        self.add_provider_to_db(&record_key, db_rec);

        let evicted_key = self.heap.insert(record_key);

        if let Some(key) = evicted_key {
            trace!(?key, "Record evicted from cache.");

            self.remove_local_provider_to_db(&key);
            self.remove_providers_from_db(&key);
        }

        Ok(())
    }

    fn remove_provider(&mut self, key: &Key, provider: &PeerId) {
        debug!(?key, %provider, "Removing a provider from DB");

        if *provider == self.local_peer_id {
            self.remove_local_provider_to_db(key);
        }

        self.remove_provider_from_db(key, provider.to_bytes());

        self.heap.remove(key);
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        let rec_iter_result: Result<ParityDbProviderRecordIterator, parity_db::Error> = try {
            let btree_iter = self.db.iter(PARITY_DB_LOCAL_PROVIDER_COLUMN_NAME)?;
            ParityDbProviderRecordIterator::new(btree_iter)?
        };

        match rec_iter_result {
            Ok(rec_iter) => rec_iter,
            Err(err) => {
                error!(?err, "Can't create Parity DB record storage iterator.");

                // TODO: The error handling can be changed:
                // https://github.com/libp2p/rust-libp2p/issues/3035
                ParityDbProviderRecordIterator::empty()
            }
        }
    }

    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        self.load_providers(key)
            .unwrap_or_default()
            .providers()
            .map(Into::into)
            .collect()
    }
}

/// Parity DB BTree iterator wrapper.
pub struct ParityDbProviderRecordIterator<'a> {
    iter: Option<parity_db::BTreeIterator<'a>>,
}

impl<'a> ParityDbProviderRecordIterator<'a> {
    /// Defines empty iterator, a stub when new() fails.
    pub fn empty() -> Self {
        Self { iter: None }
    }
    /// Fallible iterator constructor. It requires inner DB BTreeIterator as a parameter.
    pub fn new(mut iter: parity_db::BTreeIterator<'a>) -> parity_db::Result<Self> {
        iter.seek_to_first()?;

        Ok(Self { iter: Some(iter) })
    }

    fn next_entry(&mut self) -> Option<(Vec<u8>, Vec<u8>)> {
        if let Some(ref mut iter) = self.iter {
            match iter.next() {
                Ok(value) => {
                    trace!("Parity DB provider record iterator succeeded");

                    value
                }
                Err(err) => {
                    warn!(?err, "Parity DB provider record iterator error");

                    None
                }
            }
        } else {
            None
        }
    }
}

impl<'a> Iterator for ParityDbProviderRecordIterator<'a> {
    type Item = Cow<'a, ProviderRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_entry().and_then(|(key, value)| {
            let db_rec_result: Result<ParityDbProviderRecord, _> = value.try_into();

            match db_rec_result {
                Ok(db_rec) => Some(Cow::Owned(db_rec.into())),
                Err(err) => {
                    warn!(
                        ?key,
                        ?err,
                        "Parity DB provider record deserialization error"
                    );

                    None
                }
            }
        })
    }
}

impl<L, R> ProviderStorage for Either<L, R>
where
    L: ProviderStorage,
    R: ProviderStorage,
{
    type ProvidedIter<'a> = impl Iterator<Item = Cow<'a, ProviderRecord>> where Self:'a;

    fn add_provider(&mut self, record: ProviderRecord) -> store::Result<()> {
        match self {
            Either::Left(inner) => inner.add_provider(record),
            Either::Right(inner) => inner.add_provider(record),
        }
    }

    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        match self {
            Either::Left(inner) => inner.providers(key),
            Either::Right(inner) => inner.providers(key),
        }
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        let iterator = match self {
            Either::Left(inner) => Either::Left(inner.provided()),
            Either::Right(inner) => Either::Right(inner.provided()),
        };

        EitherProviderStorageIterator::new(iterator)
    }

    fn remove_provider(&mut self, key: &Key, peer_id: &PeerId) {
        match self {
            Either::Left(inner) => inner.remove_provider(key, peer_id),
            Either::Right(inner) => inner.remove_provider(key, peer_id),
        }
    }
}

struct EitherProviderStorageIterator<'a, L, R>
where
    L: Iterator<Item = Cow<'a, ProviderRecord>>,
    R: Iterator<Item = Cow<'a, ProviderRecord>>,
{
    either_provider_iterator: Either<L, R>,
}

impl<'a, L, R> EitherProviderStorageIterator<'a, L, R>
where
    L: Iterator<Item = Cow<'a, ProviderRecord>>,
    R: Iterator<Item = Cow<'a, ProviderRecord>>,
{
    fn new(either_provider_iterator: Either<L, R>) -> Self {
        Self {
            either_provider_iterator,
        }
    }
}

impl<'a, L, R> Iterator for EitherProviderStorageIterator<'a, L, R>
where
    L: Iterator<Item = Cow<'a, ProviderRecord>>,
    R: Iterator<Item = Cow<'a, ProviderRecord>>,
{
    type Item = Cow<'a, ProviderRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.either_provider_iterator {
            Either::Left(ref mut inner) => inner.next(),
            Either::Right(ref mut inner) => inner.next(),
        }
    }
}

// Instant to microseconds conversion function.
pub(crate) fn instant_to_micros(instant: Instant) -> u64 {
    let system_now = SystemTime::now();
    let instant_now = Instant::now();

    let system_time = system_now - (instant_now - instant);
    let duration = system_time
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Cannot be earlier than the beginning of unix time; qed");

    duration.as_micros() as u64
}

// Microseconds to Instant conversion function.
pub(crate) fn micros_to_instant(micros: u64) -> Option<Instant> {
    let system_time = SystemTime::UNIX_EPOCH.checked_add(Duration::from_micros(micros))?;

    let system_now = SystemTime::now();
    let instant_now = Instant::now();
    let duration = system_now.duration_since(system_time).ok()?;

    instant_now.checked_sub(duration)
}

/// Parity DB BTree ProviderRecordCollection iterator wrapper.
pub struct ParityDbProviderRecordCollectionIterator<'a> {
    iter: Option<parity_db::BTreeIterator<'a>>,
    current_collection: Option<Vec<ParityDbProviderRecord>>,
}

impl<'a> ParityDbProviderRecordCollectionIterator<'a> {
    /// Defines empty iterator, a stub when new() fails.
    pub fn empty() -> Self {
        Self {
            iter: None,
            current_collection: None,
        }
    }

    /// Fallible iterator constructor. It requires inner DB BTreeIterator as a parameter.
    pub fn new(mut iter: parity_db::BTreeIterator<'a>) -> parity_db::Result<Self> {
        iter.seek_to_first()?;

        Ok(Self {
            iter: Some(iter),
            current_collection: None,
        })
    }

    fn next_entry(&mut self) -> Option<(Vec<u8>, Vec<u8>)> {
        if let Some(ref mut iter) = self.iter {
            match iter.next() {
                Ok(value) => {
                    trace!("Parity DB provider iterator succeeded");

                    value
                }
                Err(err) => {
                    warn!(?err, "Parity DB provider iterator error");

                    None
                }
            }
        } else {
            None
        }
    }
}

impl<'a> Iterator for ParityDbProviderRecordCollectionIterator<'a> {
    type Item = Cow<'a, ProviderRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_collection.is_none() {
            let loaded_collection = self.next_entry().and_then(|(key, value)| {
                let db_rec_result: Result<ParityDbProviderCollection, _> = value.try_into();

                match db_rec_result {
                    Ok(collection) => Some(collection.providers().collect::<Vec<_>>()),
                    Err(err) => {
                        warn!(
                            ?key,
                            ?err,
                            "Parity DB provider collection deserialization error"
                        );

                        None
                    }
                }
            });

            self.current_collection = loaded_collection;
        }

        let result = if let Some(ref mut collection) = self.current_collection {
            collection.pop().map(Into::into).map(Cow::Owned)
        } else {
            None
        };

        // Remove empty collection from the local cache.
        let is_empty_collection = self
            .current_collection
            .as_ref()
            .map(|collection| collection.is_empty())
            .unwrap_or(true);
        if is_empty_collection {
            self.current_collection = None;
        }

        result
    }
}
