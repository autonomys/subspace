use super::ProviderStorage;
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
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, trace};

// Defines max provider records number. Each provider record is expected to be less than 1KB.
const MEMORY_STORE_PROVIDED_KEY_LIMIT: usize = 100000; // ~100 MB

const PARITY_DB_COLUMN_NAME: u8 = 1;

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

impl<'a> ProviderStorage<'a> for MemoryProviderStorage {
    type ProvidedIter = iter::Map<
        hash_set::Iter<'a, ProviderRecord>,
        fn(&'a ProviderRecord) -> Cow<'a, ProviderRecord>,
    >;

    fn add_provider(&'a mut self, record: ProviderRecord) -> store::Result<()> {
        trace!("New provider record added: {:?}", record);

        self.inner.add_provider(record)
    }

    fn providers(&'a self, key: &Key) -> Vec<ProviderRecord> {
        self.inner.providers(key)
    }

    fn provided(&'a self) -> Self::ProvidedIter {
        self.inner.provided()
    }

    fn remove_provider(&'a mut self, key: &Key, provider: &PeerId) {
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

    fn providers(&self) -> Vec<ParityDbProviderRecord> {
        self.map.values().cloned().collect()
    }
}

#[derive(Clone, Debug, Decode, Encode)]
struct ParityDbProviderRecord {
    // Key of the record.
    key: Vec<u8>,
    // Provider peer ID.
    provider: Vec<u8>,

    // TODO: consider adding expiration field and convert Instant to serializable time-type
    // // The expiration time as measured by a local, monotonic clock.
    // expires: Option<Instant>,
    addresses: Vec<Vec<u8>>,
}

impl From<ProviderRecord> for ParityDbProviderRecord {
    fn from(rec: ProviderRecord) -> Self {
        Self {
            key: rec.key.to_vec(),
            provider: rec.provider.to_bytes(),
            addresses: rec.addresses.iter().map(|a| a.to_vec()).collect(),
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
            expires: None,
        }
    }
}

/// Defines provider record storage with DB persistence
#[derive(Clone)]
pub struct ParityDbProviderStorage {
    // Parity DB instance
    db: Arc<Db>,
}

impl ParityDbProviderStorage {
    pub fn new(path: &Path) -> Result<Self, parity_db::Error> {
        let mut options = Options::with_columns(path, 1);
        options.columns = vec![ColumnOptions {
            btree_index: true,
            ..Default::default()
        }];
        // We don't use stats
        options.stats = false;

        let db = Db::open_or_create(&options)?;

        Ok(Self { db: Arc::new(db) })
    }

    fn add_provider_to_db(&mut self, key: &Key, rec: ParityDbProviderRecord) {
        let mut providers = self.load_providers(key).unwrap_or_default();

        providers.add_provider(rec);

        self.save_providers(key, providers);
    }

    fn remove_provider_from_db(&mut self, key: &Key, provider: Vec<u8>) {
        let mut providers = self.load_providers(key).unwrap_or_default();

        providers.remove_provider(provider);

        self.save_providers(key, providers);
    }

    fn save_providers(&mut self, key: &Key, providers: ParityDbProviderCollection) -> bool {
        let key: &[u8] = key.borrow();

        let tx = [(PARITY_DB_COLUMN_NAME, key, Some(providers.to_vec()))];

        let result = self.db.commit(tx);
        if let Err(ref err) = result {
            debug!(?key, ?err, "DB saving error.");
        }

        result.is_ok()
    }

    fn load_providers(&self, key: &Key) -> Option<ParityDbProviderCollection> {
        let result = self.db.get(PARITY_DB_COLUMN_NAME, key.borrow());

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

    fn convert_to_record(data: Vec<u8>) -> Result<ProviderRecord, parity_scale_codec::Error> {
        ParityDbProviderRecord::decode(&mut data.as_slice()).map(Into::into)
    }
}

impl<'a> ProviderStorage<'a> for ParityDbProviderStorage {
    type ProvidedIter = ParityDbProviderRecordIterator<'a>;

    fn add_provider(&mut self, record: ProviderRecord) -> store::Result<()> {
        let key = record.key.clone();

        debug!(?key, provider=%record.provider, "Saving a provider to DB");

        let db_rec = ParityDbProviderRecord::from(record);

        self.add_provider_to_db(&key, db_rec);

        Ok(())
    }

    fn remove_provider(&'a mut self, key: &Key, provider: &PeerId) {
        debug!(?key, %provider, "Removing a provider from DB");

        self.remove_provider_from_db(key, provider.to_bytes());
    }

    fn provided(&'a self) -> Self::ProvidedIter {
        let rec_iter_result: Result<ParityDbProviderRecordIterator, parity_db::Error> = try {
            let btree_iter = self.db.iter(PARITY_DB_COLUMN_NAME)?;
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

    fn providers(&'a self, key: &Key) -> Vec<ProviderRecord> {
        self.load_providers(key)
            .unwrap_or_default()
            .providers()
            .iter()
            .cloned()
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
            iter.next().ok().flatten()
        } else {
            None
        }
    }
}

impl<'a> Iterator for ParityDbProviderRecordIterator<'a> {
    type Item = Cow<'a, ProviderRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_entry().and_then(|(key, value)| {
            let db_rec_result = ParityDbProviderStorage::convert_to_record(value);

            match db_rec_result {
                Ok(db_rec) => Some(Cow::Owned(db_rec)),
                Err(err) => {
                    debug!(?key, ?err, "Parity DB record deserialization error");

                    None
                }
            }
        })
    }
}

impl<'a, L, R> ProviderStorage<'a> for Either<L, R>
where
    L: ProviderStorage<'a>,
    R: ProviderStorage<'a>,
{
    type ProvidedIter = impl Iterator<Item = Cow<'a, ProviderRecord>>;

    fn add_provider(&'a mut self, record: ProviderRecord) -> store::Result<()> {
        match self {
            Either::Left(inner) => inner.add_provider(record),
            Either::Right(inner) => inner.add_provider(record),
        }
    }

    fn providers(&'a self, key: &Key) -> Vec<ProviderRecord> {
        match self {
            Either::Left(inner) => inner.providers(key),
            Either::Right(inner) => inner.providers(key),
        }
    }

    fn provided(&'a self) -> Self::ProvidedIter {
        let iterator = match self {
            Either::Left(inner) => Either::Left(inner.provided()),
            Either::Right(inner) => Either::Right(inner.provided()),
        };

        EitherProviderStorageIterator::new(iterator)
    }

    fn remove_provider(&'a mut self, key: &Key, peer_id: &PeerId) {
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
