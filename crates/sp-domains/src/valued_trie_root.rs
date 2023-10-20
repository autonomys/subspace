use hash_db::Hasher;
use parity_scale_codec::{Codec, Compact, Encode};
#[cfg(feature = "std")]
use sp_state_machine::prove_read;
use sp_state_machine::TrieBackendBuilder;
use sp_std::cmp::max;
use sp_std::marker::PhantomData;
use sp_std::vec::Vec;
use sp_trie::StorageProof;
use trie_db::node::Value;
use trie_db::{
    nibble_ops, ChildReference, DBValue, NibbleSlice, NodeCodec, ProcessEncodedNode,
    TrieDBMutBuilder, TrieHash, TrieLayout, TrieMut, TrieRoot,
};

macro_rules! exponential_out {
	(@3, [$($inpp:expr),*]) => { exponential_out!(@2, [$($inpp,)* $($inpp),*]) };
	(@2, [$($inpp:expr),*]) => { exponential_out!(@1, [$($inpp,)* $($inpp),*]) };
	(@1, [$($inpp:expr),*]) => { [$($inpp,)* $($inpp),*] };
}

type CacheNode<HO> = Option<ChildReference<HO>>;

#[inline(always)]
fn new_vec_slice_buffer<HO>() -> [CacheNode<HO>; 16] {
    exponential_out!(@3, [None, None])
}

type ArrayNode<T> = [CacheNode<TrieHash<T>>; 16];

/// This is a modified version of trie root that takes trie node values instead of deriving from
/// the actual data. Taken from `trie-db` as is.
/// Note: This is an opportunity to push this change upstream but I'm not sure how to present these
/// changes yet. Need to be discussed further.
pub fn valued_ordered_trie_root<Layout>(
    input: Vec<Value>,
) -> <<Layout as TrieLayout>::Hash as Hasher>::Out
where
    Layout: TrieLayout,
{
    let input = input
        .into_iter()
        .enumerate()
        .map(|(i, v)| (Compact(i as u32).encode(), v))
        .collect();

    let mut cb = TrieRoot::<Layout>::default();
    trie_visit::<Layout, _>(input, &mut cb);
    cb.root.unwrap_or_default()
}

fn trie_visit<T, F>(input: Vec<(Vec<u8>, Value)>, callback: &mut F)
where
    T: TrieLayout,
    F: ProcessEncodedNode<TrieHash<T>>,
{
    let mut depth_queue = CacheAccum::<T>::new();
    // compare iter ordering
    let mut iter_input = input.into_iter();
    if let Some(mut previous_value) = iter_input.next() {
        // depth of last item
        let mut last_depth = 0;

        let mut single = true;
        for (k, v) in iter_input {
            single = false;
            let common_depth = nibble_ops::biggest_depth(&previous_value.0, &k);
            // 0 is a reserved value : could use option
            let depth_item = common_depth;
            if common_depth == previous_value.0.len() * nibble_ops::NIBBLE_PER_BYTE {
                // the new key include the previous one : branch value case
                // just stored value at branch depth
                depth_queue.set_cache_value(common_depth, Some(previous_value.1));
            } else if depth_item >= last_depth {
                // put previous with next (common branch previous value can be flush)
                depth_queue.flush_value(callback, depth_item, &previous_value);
            } else if depth_item < last_depth {
                // do not put with next, previous is last of a branch
                depth_queue.flush_value(callback, last_depth, &previous_value);
                let ref_branches = previous_value.0;
                depth_queue.flush_branch(callback, ref_branches, depth_item, false);
            }

            previous_value = (k, v);
            last_depth = depth_item;
        }
        // last pendings
        if single {
            // one single element corner case
            let (k2, v2) = previous_value;
            let nkey = NibbleSlice::new_offset(&k2, last_depth);
            let pr =
                NibbleSlice::new_offset(&k2, k2.len() * nibble_ops::NIBBLE_PER_BYTE - nkey.len());

            let encoded = T::Codec::leaf_node(nkey.right_iter(), nkey.len(), v2);
            callback.process(pr.left(), encoded, true);
        } else {
            depth_queue.flush_value(callback, last_depth, &previous_value);
            let ref_branches = previous_value.0;
            depth_queue.flush_branch(callback, ref_branches, 0, true);
        }
    } else {
        // nothing null root corner case
        callback.process(hash_db::EMPTY_PREFIX, T::Codec::empty_node().to_vec(), true);
    }
}

struct CacheAccum<'a, T: TrieLayout>(Vec<(ArrayNode<T>, Option<Value<'a>>, usize)>);

/// Initially allocated cache depth.
const INITIAL_DEPTH: usize = 10;

impl<'a, T> CacheAccum<'a, T>
where
    T: TrieLayout,
{
    fn new() -> Self {
        let v = Vec::with_capacity(INITIAL_DEPTH);
        CacheAccum(v)
    }

    #[inline(always)]
    fn set_cache_value(&mut self, depth: usize, value: Option<Value<'a>>) {
        if self.0.is_empty() || self.0[self.0.len() - 1].2 < depth {
            self.0.push((new_vec_slice_buffer(), None, depth));
        }
        let last = self.0.len() - 1;
        debug_assert!(self.0[last].2 <= depth);
        self.0[last].1 = value;
    }

    #[inline(always)]
    fn set_node(&mut self, depth: usize, nibble_index: usize, node: CacheNode<TrieHash<T>>) {
        if self.0.is_empty() || self.0[self.0.len() - 1].2 < depth {
            self.0.push((new_vec_slice_buffer(), None, depth));
        }

        let last = self.0.len() - 1;
        debug_assert!(self.0[last].2 == depth);

        self.0[last].0.as_mut()[nibble_index] = node;
    }

    #[inline(always)]
    fn last_depth(&self) -> usize {
        let ix = self.0.len();
        if ix > 0 {
            let last = ix - 1;
            self.0[last].2
        } else {
            0
        }
    }

    #[inline(always)]
    fn last_last_depth(&self) -> usize {
        let ix = self.0.len();
        if ix > 1 {
            let last = ix - 2;
            self.0[last].2
        } else {
            0
        }
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    #[inline(always)]
    fn is_one(&self) -> bool {
        self.0.len() == 1
    }

    fn flush_value(
        &mut self,
        callback: &mut impl ProcessEncodedNode<TrieHash<T>>,
        target_depth: usize,
        (k2, v2): &(impl AsRef<[u8]>, Value),
    ) {
        let nibble_value = nibble_ops::left_nibble_at(k2.as_ref(), target_depth);
        // is it a branch value (two candidate same ix)
        let nkey = NibbleSlice::new_offset(k2.as_ref(), target_depth + 1);
        let pr = NibbleSlice::new_offset(
            k2.as_ref(),
            k2.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE - nkey.len(),
        );

        let encoded = T::Codec::leaf_node(nkey.right_iter(), nkey.len(), v2.clone());
        let hash = callback.process(pr.left(), encoded, false);

        // insert hash in branch (first level branch only at this point)
        self.set_node(target_depth, nibble_value as usize, Some(hash));
    }

    fn flush_branch(
        &mut self,
        callback: &mut impl ProcessEncodedNode<TrieHash<T>>,
        ref_branch: impl AsRef<[u8]> + Ord,
        new_depth: usize,
        is_last: bool,
    ) {
        while self.last_depth() > new_depth || is_last && !self.is_empty() {
            let lix = self.last_depth();
            let llix = max(self.last_last_depth(), new_depth);

            let (offset, slice_size, is_root) = if llix == 0 && is_last && self.is_one() {
                // branch root
                (llix, lix - llix, true)
            } else {
                (llix + 1, lix - llix - 1, false)
            };
            let nkey = if slice_size > 0 {
                Some((offset, slice_size))
            } else {
                None
            };

            let h = self.no_extension(ref_branch.as_ref(), callback, lix, is_root, nkey);
            if !is_root {
                // put hash in parent
                let nibble: u8 = nibble_ops::left_nibble_at(ref_branch.as_ref(), llix);
                self.set_node(llix, nibble as usize, Some(h));
            }
        }
    }

    #[inline(always)]
    fn no_extension(
        &mut self,
        key_branch: &[u8],
        callback: &mut impl ProcessEncodedNode<TrieHash<T>>,
        branch_d: usize,
        is_root: bool,
        nkey: Option<(usize, usize)>,
    ) -> ChildReference<TrieHash<T>> {
        let (children, v, depth) = self.0.pop().expect("checked");

        debug_assert!(branch_d == depth);
        // encode branch
        let nkeyix = nkey.unwrap_or((branch_d, 0));
        let pr = NibbleSlice::new_offset(key_branch, nkeyix.0);
        let encoded = T::Codec::branch_node_nibbled(
            pr.right_range_iter(nkeyix.1),
            nkeyix.1,
            children.iter(),
            v,
        );
        callback.process(pr.left(), encoded, is_root)
    }
}

type MemoryDB<T> = memory_db::MemoryDB<
    <T as TrieLayout>::Hash,
    memory_db::HashKey<<T as TrieLayout>::Hash>,
    DBValue,
>;

/// Type that provides utilities to generate the storage proof.
pub struct StorageProofProvider<Layout>(PhantomData<Layout>);

impl<Layout> StorageProofProvider<Layout>
where
    Layout: TrieLayout,
    <Layout::Hash as Hasher>::Out: Codec,
{
    /// Generate storage proof for given index from the trie constructed from `input`.
    ///
    /// Returns `None` if the given `index` out of range or fail to generate the proof.
    #[cfg(feature = "std")]
    pub fn generate_enumerated_proof_of_inclusion(
        input: &[Vec<u8>],
        index: u32,
    ) -> Option<StorageProof> {
        if input.len() <= index as usize {
            return None;
        }

        let input: Vec<_> = input
            .iter()
            .enumerate()
            .map(|(i, v)| (Compact(i as u32).encode(), v))
            .collect();

        let (db, root) = {
            let mut db = <MemoryDB<Layout>>::default();
            let mut root = Default::default();
            {
                let mut trie = <TrieDBMutBuilder<Layout>>::new(&mut db, &mut root).build();
                for (key, value) in input {
                    trie.insert(&key, value).ok()?;
                }
            }
            (db, root)
        };

        let backend = TrieBackendBuilder::new(db, root).build();
        let key = Compact(index).encode();
        prove_read(backend, &[key]).ok()
    }
}

#[cfg(test)]
mod test {
    use crate::valued_trie_root::{valued_ordered_trie_root, StorageProofProvider};
    use crate::verification::StorageProofVerifier;
    use parity_scale_codec::{Compact, Encode};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use sp_core::storage::StorageKey;
    use sp_core::H256;
    use sp_runtime::traits::{BlakeTwo256, Hash};
    use sp_trie::LayoutV1;
    use trie_db::node::Value;

    #[test]
    fn test_extrinsics_root() {
        let mut rng = StdRng::seed_from_u64(10000);
        let exts_length = vec![35, 31, 50, 100, 20, 10, 120];
        let mut exts = Vec::new();
        let mut exts_hashed = Vec::new();
        for ext_length in &exts_length {
            let mut ext = vec![0u8; *ext_length];
            rng.fill(ext.as_mut_slice());
            let hashed = if *ext_length <= 32 {
                ext.clone()
            } else {
                BlakeTwo256::hash(&ext).0.to_vec()
            };
            exts.push(ext);
            exts_hashed.push(hashed);
        }

        let exts_values: Vec<_> = exts_hashed
            .iter()
            .zip(exts_length)
            .map(|(ext_hashed, ext_length)| {
                let value = if ext_length <= 32 {
                    Value::Inline(ext_hashed)
                } else {
                    Value::Node(ext_hashed)
                };
                value
            })
            .collect();

        let root = BlakeTwo256::ordered_trie_root(exts.clone(), sp_core::storage::StateVersion::V1);
        let got_root = valued_ordered_trie_root::<LayoutV1<BlakeTwo256>>(exts_values);
        assert_eq!(root, got_root);

        for (i, ext) in exts.clone().into_iter().enumerate() {
            // Generate a proof-of-inclusion and verify it with the above `root`
            let storage_key = StorageKey(Compact(i as u32).encode());
            let storage_proof =
                StorageProofProvider::<LayoutV1<BlakeTwo256>>::generate_enumerated_proof_of_inclusion(
                    &exts,
                    i as u32,
                )
                .unwrap();

            assert!(StorageProofVerifier::<BlakeTwo256>::verify_storage_proof(
                storage_proof.clone(),
                &root,
                ext.clone(),
                storage_key.clone(),
            ));

            // Verifying the proof with a wrong root/ext/index will fail
            assert!(!StorageProofVerifier::<BlakeTwo256>::verify_storage_proof(
                storage_proof.clone(),
                &H256::random(),
                ext.clone(),
                storage_key.clone(),
            ));

            assert!(!StorageProofVerifier::<BlakeTwo256>::verify_storage_proof(
                storage_proof.clone(),
                &root,
                vec![i as u8; ext.len()],
                storage_key,
            ));

            let storage_key = StorageKey(Compact(i as u32 + 1).encode());
            assert!(!StorageProofVerifier::<BlakeTwo256>::verify_storage_proof(
                storage_proof,
                &root,
                ext,
                storage_key,
            ));
        }

        // fails to generate storage key for unknown index
        assert!(
            StorageProofProvider::<LayoutV1<BlakeTwo256>>::generate_enumerated_proof_of_inclusion(
                &exts, 100,
            )
            .is_none()
        );
    }
}
