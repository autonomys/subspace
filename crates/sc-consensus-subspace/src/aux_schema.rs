//! Schema for Subspace block weight in the aux-db.

use parity_scale_codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sp_blockchain::{Error as ClientError, Result as ClientResult};
use sp_runtime::traits::{One, Saturating};
use subspace_core_primitives::BlockForkWeight;

fn load_decode<B, T>(backend: &B, key: &[u8]) -> ClientResult<Option<T>>
where
    B: AuxStore,
    T: Decode,
{
    match backend.get_aux(key)? {
        Some(t) => T::decode(&mut &t[..])
            .map(Some)
            .map_err(|e: parity_scale_codec::Error| {
                ClientError::Backend(format!("Subspace DB is corrupted. Decode error: {e}"))
            }),
        None => Ok(None),
    }
}

/// The aux storage key used to store the block weight of the given block hash.
pub(crate) fn block_weight_key<H: Encode>(block_hash: H) -> Vec<u8> {
    (b"block_weight", block_hash).encode()
}

/// The aux storage key recording how far the canonical-history sweep has progressed.
fn block_weight_cleaned_to_key() -> Vec<u8> {
    b"block_weight_cleaned_to".to_vec()
}

/// Write the cumulative chain-weight of a block to aux storage.
pub(crate) fn write_block_weight<H, F, R>(
    block_hash: H,
    block_weight: BlockForkWeight,
    write_aux: F,
) -> R
where
    H: Encode,
    F: FnOnce(&[(Vec<u8>, &[u8])]) -> R,
{
    let key = block_weight_key(block_hash);
    block_weight.using_encoded(|s| write_aux(&[(key, s)]))
}

/// Load the cumulative chain-weight associated with a block.
pub(crate) fn load_block_weight<H: Encode, B: AuxStore>(
    backend: &B,
    block_hash: H,
) -> ClientResult<Option<BlockForkWeight>> {
    load_decode(backend, block_weight_key(block_hash).as_slice())
}

/// Load the canonical-history sweep marker. `None` on a fresh DB.
pub(crate) fn load_block_weight_cleaned_to<N: Decode, B: AuxStore>(
    backend: &B,
) -> ClientResult<Option<N>> {
    load_decode(backend, block_weight_cleaned_to_key().as_slice())
}

/// Build the `(key, encoded_value)` pair recording an updated sweep marker.
pub(crate) fn block_weight_cleaned_to_aux_entry<N: Encode>(cleaned_to: N) -> (Vec<u8>, Vec<u8>) {
    (block_weight_cleaned_to_key(), cleaned_to.encode())
}

/// `(key, Some(value))` for a write, `(key, None)` for a delete — the shape
/// `BlockImportParams::auxiliary` expects.
pub(crate) type SweepAuxEntry = (Vec<u8>, Option<Vec<u8>>);

/// Advance the canonical-history sweep one batch.
///
/// Walks `(cleaned_to, min(cleaned_to + batch, finalized - 1)]` and emits a
/// tombstone per canonical block plus a marker entry for the highest height
/// actually swept. Stops one short of `finalized` so the just-finalized
/// block's weight stays available as `parent_weight` for any fork imported
/// on top of it. Stops on the first `Ok(None)` (snap-sync gap) so the marker
/// doesn't advance past entries that arrive later via gap-fill.
///
/// Callers MUST write the result as one atomic aux batch — splitting would
/// re-introduce the leak.
pub(crate) fn build_canonical_sweep_entries<N, H, F>(
    cleaned_to: N,
    finalized: N,
    batch: N,
    mut height_to_hash: F,
) -> ClientResult<Vec<SweepAuxEntry>>
where
    N: Copy + Ord + Saturating + One + Encode,
    H: Encode,
    F: FnMut(N) -> ClientResult<Option<H>>,
{
    let one = N::one();
    let end = cleaned_to
        .saturating_add(batch)
        .min(finalized.saturating_sub(one));
    let mut height = cleaned_to.saturating_add(one);
    let mut last_swept = cleaned_to;
    let mut out = Vec::new();

    while height <= end {
        let Some(hash) = height_to_hash(height)? else {
            break;
        };
        out.push((block_weight_key(hash), None));
        last_swept = height;
        // `saturating_add(one)` at `N::MAX` would loop forever; break first.
        if height == end {
            break;
        }
        height = height.saturating_add(one);
    }

    if last_swept > cleaned_to {
        let (k, v) = block_weight_cleaned_to_aux_entry(last_swept);
        out.push((k, Some(v)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::RwLock;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemAuxStore {
        store: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
    }

    impl AuxStore for MemAuxStore {
        fn insert_aux<
            'a,
            'b: 'a,
            'c: 'a,
            I: IntoIterator<Item = &'a (&'c [u8], &'c [u8])>,
            D: IntoIterator<Item = &'a &'b [u8]>,
        >(
            &self,
            insert: I,
            delete: D,
        ) -> sp_blockchain::Result<()> {
            let mut storage = self.store.write();
            for (k, v) in insert {
                storage.insert(k.to_vec(), v.to_vec());
            }
            for k in delete {
                storage.remove(*k);
            }
            Ok(())
        }

        fn get_aux(&self, key: &[u8]) -> sp_blockchain::Result<Option<Vec<u8>>> {
            Ok(self.store.read().get(key).cloned())
        }
    }

    fn seed_weight(store: &MemAuxStore, hash: u64, weight: BlockForkWeight) {
        write_block_weight(hash, weight, |values| {
            let pairs: Vec<(&[u8], &[u8])> =
                values.iter().map(|(k, v)| (k.as_slice(), *v)).collect();
            store.insert_aux(&pairs, &[]).unwrap();
        });
    }

    #[test]
    fn block_weight_key_roundtrips_through_write_and_load() {
        let store = MemAuxStore::default();
        let h: u64 = 0x1234;
        seed_weight(&store, h, 42);
        assert!(load_block_weight(&store, h).unwrap().is_some());

        let key = block_weight_key(h);
        let key_refs: &[&[u8]] = &[key.as_slice()];
        let empty: &[(&[u8], &[u8])] = &[];
        store.insert_aux(empty, key_refs).unwrap();

        assert!(load_block_weight(&store, h).unwrap().is_none());
    }

    #[test]
    fn cleaned_to_marker_roundtrips() {
        let store = MemAuxStore::default();

        let initial: Option<u32> = load_block_weight_cleaned_to(&store).unwrap();
        assert!(initial.is_none());

        let (key, value) = block_weight_cleaned_to_aux_entry::<u32>(12_345);
        let pairs: &[(&[u8], &[u8])] = &[(key.as_slice(), value.as_slice())];
        store.insert_aux(pairs, &[]).unwrap();

        let read: Option<u32> = load_block_weight_cleaned_to(&store).unwrap();
        assert_eq!(read, Some(12_345));
    }

    fn fake_hash(n: u32) -> u64 {
        0xaa00_0000_0000_0000_u64 | u64::from(n)
    }

    #[test]
    fn sweep_no_op_when_nothing_to_clean() {
        let entries =
            build_canonical_sweep_entries::<u32, u64, _>(10, 10, 100, |_| Ok(Some(0))).unwrap();
        assert!(
            entries.is_empty(),
            "finalized == cleaned_to should produce no entries"
        );
    }

    #[test]
    fn sweep_walks_up_to_finalized_minus_one_when_under_batch() {
        // finalized=6 → sweep stops at 5, leaving block 6's weight intact.
        let entries =
            build_canonical_sweep_entries::<u32, u64, _>(0, 6, 100, |n| Ok(Some(fake_hash(n))))
                .unwrap();
        // 5 tombstones (heights 1..=5) + 1 marker
        assert_eq!(entries.len(), 6);
        let expected_keys: Vec<Vec<u8>> = (1..=5).map(|h| block_weight_key(fake_hash(h))).collect();
        for (i, tomb) in entries[..5].iter().enumerate() {
            assert_eq!(
                tomb.0, expected_keys[i],
                "tombstone key mismatch at index {i}"
            );
            assert!(tomb.1.is_none());
        }
        // Finalized block (height 6) must NOT appear in the tombstones — its
        // weight is still needed as parent_weight for forks built on it.
        let finalized_key = block_weight_key(fake_hash(6));
        for tomb in &entries[..5] {
            assert_ne!(
                tomb.0, finalized_key,
                "finalized block must not be tombstoned"
            );
        }
        let (marker_key, marker_value) = block_weight_cleaned_to_aux_entry::<u32>(5);
        assert_eq!(entries[5].0, marker_key);
        assert_eq!(entries[5].1.as_deref(), Some(marker_value.as_slice()));
    }

    #[test]
    fn sweep_no_op_when_marker_exceeds_finalized() {
        let entries = build_canonical_sweep_entries::<u32, u64, _>(50, 30, 100, |_| {
            panic!("closure must not be called when finalized < cleaned_to")
        })
        .unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn sweep_no_op_when_batch_is_zero() {
        let entries = build_canonical_sweep_entries::<u32, u64, _>(0, 5, 0, |_| {
            panic!("closure must not be called when batch == 0")
        })
        .unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn sweep_propagates_height_to_hash_error() {
        let result = build_canonical_sweep_entries::<u32, u64, _>(0, 5, 100, |n| {
            if n == 3 {
                Err(sp_blockchain::Error::Backend("simulated".into()))
            } else {
                Ok(Some(fake_hash(n)))
            }
        });
        assert!(matches!(result, Err(sp_blockchain::Error::Backend(_))));
    }

    #[test]
    fn sweep_caps_at_batch_size() {
        let entries = build_canonical_sweep_entries::<u32, u64, _>(0, 1_000_000, 100, |n| {
            Ok(Some(fake_hash(n)))
        })
        .unwrap();
        // 100 tombstones + 1 marker
        assert_eq!(entries.len(), 101);
        let (marker_key, marker_value) = block_weight_cleaned_to_aux_entry::<u32>(100);
        assert_eq!(entries[100].0, marker_key);
        assert_eq!(entries[100].1.as_deref(), Some(marker_value.as_slice()));
    }

    #[test]
    fn sweep_stops_at_first_missing_height_and_marker_reflects_last_swept() {
        // Heights 2 and 4 missing → stop at 2, marker stays at 1 so 2..=5 retry next sweep.
        let entries = build_canonical_sweep_entries::<u32, u64, _>(0, 6, 100, |n| {
            if n == 2 || n == 4 {
                Ok(None)
            } else {
                Ok(Some(fake_hash(n)))
            }
        })
        .unwrap();
        assert_eq!(entries.len(), 2);
        let (marker_key, marker_value) = block_weight_cleaned_to_aux_entry::<u32>(1);
        assert_eq!(entries[1].0, marker_key);
        assert_eq!(entries[1].1.as_deref(), Some(marker_value.as_slice()));
    }

    #[test]
    fn sweep_emits_no_marker_when_first_height_is_missing() {
        let entries =
            build_canonical_sweep_entries::<u32, u64, _>(0, 6, 100, |_| Ok(None)).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn sweep_resumes_from_marker_across_calls() {
        let mut cleaned_to: u32 = 0;
        let finalized: u32 = 251;

        for expected_marker in [100u32, 200, 250] {
            let entries =
                build_canonical_sweep_entries::<u32, u64, _>(cleaned_to, finalized, 100, |n| {
                    Ok(Some(fake_hash(n)))
                })
                .unwrap();
            let (marker_key, marker_value) =
                block_weight_cleaned_to_aux_entry::<u32>(expected_marker);
            assert_eq!(entries.last().unwrap().0, marker_key);
            assert_eq!(
                entries.last().unwrap().1.as_deref(),
                Some(marker_value.as_slice())
            );
            cleaned_to = expected_marker;
        }

        let entries =
            build_canonical_sweep_entries::<u32, u64, _>(cleaned_to, finalized, 100, |n| {
                Ok(Some(fake_hash(n)))
            })
            .unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn sweep_terminates_at_numeric_max_boundary() {
        // cleaned_to = MAX-6 → tombstones MAX-5..=MAX-1, marker = MAX-1.
        // (Finalized block at MAX itself is preserved.)
        let cleaned_to = u32::MAX - 6;
        let entries =
            build_canonical_sweep_entries::<u32, u64, _>(cleaned_to, u32::MAX, 100, |n| {
                Ok(Some(fake_hash(n)))
            })
            .unwrap();
        // 5 tombstones + 1 marker
        assert_eq!(entries.len(), 6);
        let (marker_key, marker_value) = block_weight_cleaned_to_aux_entry::<u32>(u32::MAX - 1);
        assert_eq!(entries[5].0, marker_key);
        assert_eq!(entries[5].1.as_deref(), Some(marker_value.as_slice()));
    }

    #[test]
    fn sweep_is_no_op_when_cleaned_to_and_finalized_both_at_max() {
        // Without the `finalized - 1` upper bound, this would tombstone N::MAX
        // forever (marker never advances because last_swept == cleaned_to).
        let entries = build_canonical_sweep_entries::<u32, u64, _>(u32::MAX, u32::MAX, 100, |_| {
            panic!("closure must not be called")
        })
        .unwrap();
        assert!(entries.is_empty());
    }
}
