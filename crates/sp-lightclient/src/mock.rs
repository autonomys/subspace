use crate::{
    BlockWeight, HashOf, HeaderExt, HeaderImporter, RecordSize, SegmentSize, SolutionRange, Storage,
};
use environmental::environmental;
use sp_runtime::traits::{BlakeTwo256, Header as HeaderT};
use std::collections::HashMap;

environmental!(storage_data: StorageData);

pub(crate) type Header = sp_runtime::generic::Header<u32, BlakeTwo256>;
pub(crate) type NumberOf<T> = <T as HeaderT>::Number;

#[derive(Default)]
struct StorageData {
    headers: HashMap<HashOf<Header>, HeaderExt<Header>>,
    number_to_hash: HashMap<NumberOf<Header>, HashOf<Header>>,
    best_header: (NumberOf<Header>, HashOf<Header>),
}

pub(crate) struct MockStorage;
impl Storage<Header> for MockStorage {
    fn record_size() -> RecordSize {
        Default::default()
    }

    fn segment_size() -> SegmentSize {
        Default::default()
    }

    fn header(query: HashOf<Header>) -> Option<HeaderExt<Header>> {
        storage_data::with(|data| data.headers.get(&query).cloned()).unwrap()
    }

    fn store_header(header_ext: HeaderExt<Header>) {
        storage_data::with(|data| {
            if data.number_to_hash.contains_key(header_ext.header.number()) {
                panic!("header already imported")
            }

            let (number, hash) = (*header_ext.header.number(), header_ext.header.hash());
            data.headers.insert(hash, header_ext);
            data.number_to_hash.insert(number, hash);
            let best = data.best_header;
            if best.0 < number {
                data.best_header = (number, hash)
            }
        });
    }

    fn prune_descendants_of(query: HashOf<Header>) {
        storage_data::with(|data| {
            let header = data.headers.get(&query).cloned().unwrap();
            let mut start_number = header.header.number() + 1;
            let (best_number, _) = data.best_header;
            while start_number <= best_number {
                let hash = data.number_to_hash.remove(&start_number).unwrap();
                data.headers.remove(&hash);
                start_number += 1;
            }
            data.best_header = (*header.header.number(), header.header.hash());
        });
    }

    fn best_header() -> HeaderExt<Header> {
        storage_data::with(|data| {
            let (_, hash) = data.best_header;
            data.headers.get(&hash).cloned().unwrap()
        })
        .unwrap()
    }
}

impl MockStorage {
    // hack to adjust the solution range
    pub(crate) fn override_solution_range(hash: HashOf<Header>, solution_range: SolutionRange) {
        storage_data::with(|data| {
            let mut header = data.headers.remove(&hash).unwrap();
            header.derived_solution_range = solution_range;
            data.headers.insert(hash, header);
        });
    }

    // hack to adjust the cumulative weight
    pub(crate) fn override_cumulative_weight(hash: HashOf<Header>, weight: BlockWeight) {
        storage_data::with(|data| {
            let mut header = data.headers.remove(&hash).unwrap();
            header.total_weight = weight;
            data.headers.insert(hash, header);
        });
    }
}

pub(crate) struct MockImporter;
impl HeaderImporter<Header> for MockImporter {
    type Storage = MockStorage;
}

pub(crate) fn with_empty_storage<F: FnOnce()>(f: F) {
    let mut initial_data = Default::default();
    storage_data::using(&mut initial_data, f)
}
