#[cfg(test)]
mod tests;

use num_traits::{WrappingAdd, WrappingSub};
use parity_db::{Db, Options};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::{fmt, iter};
use subspace_core_primitives::objects::GlobalObject;
use subspace_core_primitives::{bidirectional_distance, PublicKey, Sha256Hash, U256};
use thiserror::Error;

/// How full should object mappings database be before we try to prune some values
const PRUNE_FILL_RATIO: (u64, u64) = (95, 100);
/// Target fill ratio after pruning
const RESET_FILL_RATIO: (u64, u64) = (80, 100);

#[repr(u8)]
enum Columns {
    Mappings = 0,
    Metadata = 1,
}

struct FurthestKey {
    key: Sha256Hash,
    /// Size of key + value together
    size: u16,
}

struct PruningState {
    public_key_as_number: U256,
    furthest_keys: BTreeMap<U256, FurthestKey>,
    /// Combined size of everything in `furthest_keys`
    total_size: u64,
    /// Amount of data we want to remove
    remove_size: u64,
}

impl PruningState {
    fn new(public_key_as_number: U256, remove_size: u64) -> Self {
        Self {
            public_key_as_number,
            furthest_keys: BTreeMap::new(),
            total_size: 0,
            remove_size,
        }
    }

    fn process(&mut self, furthest_key: FurthestKey) {
        let distance_from_public_key = bidirectional_distance(
            &self.public_key_as_number,
            &U256::from_be_bytes(furthest_key.key),
        );

        loop {
            if self.total_size < self.remove_size {
                self.total_size += u64::from(furthest_key.size);
                self.furthest_keys
                    .insert(distance_from_public_key, furthest_key);
                break;
            } else {
                let (closest_distance, closest_furthest_key) = self
                    .furthest_keys
                    .first_key_value()
                    .expect("Total size isn't zero, meaning at least one key is in; qed");
                let closest_furthest_size = closest_furthest_key.size;

                // Check if the key is further than the closest know distance
                if &distance_from_public_key > closest_distance {
                    // Remove existing key and loop to try inserting again
                    self.furthest_keys.pop_first();
                    self.total_size -= u64::from(closest_furthest_size);
                } else {
                    break;
                }
            }
        }
    }

    fn furthest_distance(&self) -> Option<U256> {
        self.furthest_keys
            .last_key_value()
            .map(|(distance_from_public_key, _furthest_key)| *distance_from_public_key)
    }

    fn keys_to_delete(&self) -> impl Iterator<Item = &FurthestKey> {
        self.furthest_keys.values()
    }
}

#[derive(Debug, Error)]
pub enum ObjectMappingError {
    #[error("DB error: {0}")]
    Db(#[from] parity_db::Error),
}

struct Inner {
    db: Db,
    public_key_as_number: U256,
    size: Mutex<u64>,
    /// Max distance from public key beyond which to not store anything
    max_distance: Mutex<Option<U256>>,
    prune_fill_size: u64,
    reset_fill_size: u64,
}

/// `ObjectMappings` is a mapping from arbitrary object hash to its location in archived history.
#[derive(Clone)]
pub struct ObjectMappings {
    inner: Arc<Inner>,
}

impl fmt::Debug for ObjectMappings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectMappings").finish()
    }
}

impl ObjectMappings {
    const SIZE_KEY: &'static [u8] = b"size";
    const MAX_DISTANCE_KEY: &'static [u8] = b"max_distance";

    /// Opens or creates a new object mappings database
    pub fn open_or_create(
        path: &Path,
        public_key: PublicKey,
        max_size: u64,
    ) -> Result<Self, ObjectMappingError> {
        let mut options = Options::with_columns(path, 2);
        {
            let mappings_column_options = options
                .columns
                .get_mut(Columns::Mappings as usize)
                .expect("Number of columns defined above; qed");
            mappings_column_options.uniform = true;
            // Using b-tree so we can iterate over keys
            mappings_column_options.btree_index = true;
        }
        // We don't use stats
        options.stats = false;
        // Remove salt to avoid mangling of keys
        options.salt = Some([0u8; 32]);
        let db = Db::open_or_create(&options)?;

        let size =
            db.get(Columns::Metadata as u8, Self::SIZE_KEY)?
                .map(|bytes| {
                    u64::from_le_bytes(
                        bytes.as_slice().try_into().expect(
                            "Values written into size key are always of correct length; qed",
                        ),
                    )
                })
                .unwrap_or_default();
        let max_distance = db
            .get(Columns::Metadata as u8, Self::MAX_DISTANCE_KEY)?
            .map(|bytes| {
                U256::from_le_bytes(bytes.as_slice().try_into().expect(
                    "Values written into max distance key are always of correct length; qed",
                ))
            });

        Ok(Self {
            inner: Arc::new(Inner {
                db,
                public_key_as_number: U256::from_be_bytes(public_key.into()),
                size: Mutex::new(size),
                max_distance: Mutex::new(max_distance),
                prune_fill_size: max_size.saturating_mul(PRUNE_FILL_RATIO.0) / PRUNE_FILL_RATIO.1,
                reset_fill_size: max_size.saturating_mul(RESET_FILL_RATIO.0) / RESET_FILL_RATIO.1,
            }),
        })
    }

    /// Retrieve mapping for object
    pub fn retrieve(
        &self,
        object_id: &Sha256Hash,
    ) -> Result<Option<GlobalObject>, ObjectMappingError> {
        Ok(self
            .inner
            .db
            .get(Columns::Mappings as u8, object_id)?
            .and_then(|global_object| GlobalObject::decode(&mut global_object.as_ref()).ok()))
    }

    /// Store object mappings in database, might run pruning if total size of mappings exceeds
    /// configured size
    pub fn store(
        &self,
        object_mapping: &[(Sha256Hash, GlobalObject)],
    ) -> Result<(), ObjectMappingError> {
        let bytes_to_write = RefCell::new(0u64);
        let store = self.inner.max_distance.lock().as_ref().map(|max_distance| {
            (
                self.inner.public_key_as_number.wrapping_sub(max_distance),
                self.inner.public_key_as_number.wrapping_add(max_distance),
            )
        });
        let tx = object_mapping
            .iter()
            .filter(|(object_id, _global_object)| match store {
                Some((store_from, store_to)) => {
                    let object_id = U256::from_be_bytes(*object_id);
                    store_from < object_id && object_id < store_to
                }
                None => true,
            })
            .map(|(object_id, global_object)| {
                let encoded_global_object = global_object.encode();
                *bytes_to_write.borrow_mut() +=
                    object_id.len() as u64 + encoded_global_object.len() as u64;
                (
                    Columns::Mappings as u8,
                    object_id.as_ref(),
                    Some(encoded_global_object),
                )
            });

        let mut size = self.inner.size.lock();

        let mut new_size = *size;

        let tx = tx.chain(
            iter::from_fn(|| {
                let bytes_to_write = *bytes_to_write.borrow();
                if bytes_to_write == 0 {
                    // Nothing to store
                    return None;
                }

                new_size += bytes_to_write;

                Some((
                    Columns::Metadata as u8,
                    Self::SIZE_KEY,
                    Some(new_size.to_le_bytes().to_vec()),
                ))
            })
            .take(1),
        );
        self.inner.db.commit(tx)?;

        *size = new_size;

        if new_size >= self.inner.prune_fill_size {
            self.prune(new_size - self.inner.reset_fill_size, &mut size)?;
        }

        Ok(())
    }

    fn prune(&self, remove_size: u64, size: &mut u64) -> Result<(), parity_db::Error> {
        let mut pruning_state = PruningState::new(self.inner.public_key_as_number, remove_size);
        let mut iter = self.inner.db.iter(Columns::Mappings as u8)?;
        while let Some((key, value)) = iter.next()? {
            pruning_state.process(FurthestKey {
                key: key
                    .as_slice()
                    .try_into()
                    .expect("Key read from database is always of correct size"),
                size: u16::try_from(key.len()).expect("Key always fits in u16; qed")
                    + u16::try_from(value.len()).expect("Value always fits in u16; qed"),
            });
        }

        // Update furthest distance, so unnecessary keys are not stored
        let max_distance = pruning_state
            .furthest_distance()
            .expect("Reaching this place implies there was at least one element stored; qed");
        self.inner.max_distance.lock().replace(max_distance);

        let bytes_to_delete = RefCell::new(0u64);
        let tx = pruning_state.keys_to_delete().map(|furthest_key| {
            *bytes_to_delete.borrow_mut() += u64::from(furthest_key.size);

            (Columns::Mappings as u8, furthest_key.key.as_ref(), None)
        });

        let mut new_size = *size;

        let tx = tx
            .chain(iter::once_with(|| {
                new_size -= *bytes_to_delete.borrow();

                (
                    Columns::Metadata as u8,
                    Self::SIZE_KEY,
                    Some(new_size.to_le_bytes().to_vec()),
                )
            }))
            .chain(iter::once((
                Columns::Metadata as u8,
                Self::MAX_DISTANCE_KEY,
                Some(max_distance.to_le_bytes().to_vec()),
            )));
        self.inner.db.commit(tx)?;

        *size = new_size;

        Ok(())
    }
}
