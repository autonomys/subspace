use parity_db::{
    BTreeIterator, ColumnOptions, CompressionType, Db, Options as ParityOptions, Result, Value,
};
use std::fmt;
use std::path::Path;

#[derive(derive_more::Deref, derive_more::DerefMut)]
pub struct BTreeDb(Db);

impl fmt::Debug for BTreeDb {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("BTreeDb").field(&format_args!("_")).finish()
    }
}

impl BTreeDb {
    fn open_or_create(
        path: impl AsRef<Path>,
        uniform: bool,
        compression: CompressionType,
    ) -> Result<Self> {
        let options = ParityOptions {
            path: path.as_ref().to_owned(),
            sync_wal: true,
            sync_data: true,
            stats: false,
            salt: None,
            columns: vec![ColumnOptions {
                // Conflicts with `btree_index`
                preimage: false,
                btree_index: true,
                ref_counted: false,
                uniform,
                compression,
                ..ColumnOptions::default()
            }],
        };
        Db::open_or_create(&options).map(Self)
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Value>> {
        self.0.get(0, key)
    }

    pub fn commit<I, K>(&self, tx: I) -> Result<()>
    where
        I: IntoIterator<Item = (K, Option<Value>)>,
        K: AsRef<[u8]>,
    {
        self.0.commit(tx.into_iter().map(|(k, v)| (0, k, v)))
    }

    pub fn iter(&self) -> Result<BTreeIterator<'_>> {
        self.0.iter(0)
    }
}

#[derive(derive_more::Deref, derive_more::DerefMut)]
pub struct MapDb(Db);

impl fmt::Debug for MapDb {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("MapDb").field(&format_args!("_")).finish()
    }
}

impl MapDb {
    pub fn object_mappings_open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_or_create(path, true, CompressionType::Snappy)
    }

    fn open_or_create(
        path: impl AsRef<Path>,
        uniform: bool,
        compression: CompressionType,
    ) -> Result<Self> {
        let options = ParityOptions {
            path: path.as_ref().to_owned(),
            sync_wal: true,
            sync_data: true,
            stats: false,
            salt: None,
            columns: vec![ColumnOptions {
                // Conflicts with `btree_index`
                preimage: true,
                btree_index: false,
                ref_counted: false,
                uniform,
                compression,
                ..ColumnOptions::default()
            }],
        };
        Db::open_or_create(&options).map(Self)
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Value>> {
        self.0.get(0, key)
    }

    pub fn commit<I, K>(&self, tx: I) -> Result<()>
    where
        I: IntoIterator<Item = (K, Option<Value>)>,
        K: AsRef<[u8]>,
    {
        self.0.commit(tx.into_iter().map(|(k, v)| (0, k, v)))
    }
}
