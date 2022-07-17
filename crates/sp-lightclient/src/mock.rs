use crate::{
    BlockWeight, HashOf, HeaderExt, HeaderImporter, RecordSize, SegmentSize, SolutionRange, Storage,
};
use sp_runtime::traits::{BlakeTwo256, Header as HeaderT};
use std::collections::HashMap;

pub(crate) type Header = sp_runtime::generic::Header<u32, BlakeTwo256>;
pub(crate) type NumberOf<T> = <T as HeaderT>::Number;

#[derive(Debug, Default)]
struct StorageData {
    headers: HashMap<HashOf<Header>, HeaderExt<Header>>,
    number_to_hashes: HashMap<NumberOf<Header>, Vec<HashOf<Header>>>,
    best_header: (NumberOf<Header>, HashOf<Header>),
}

#[derive(Debug, Default)]
pub(crate) struct MockStorage(StorageData);
impl Storage<Header> for MockStorage {
    fn record_size(&self) -> RecordSize {
        Default::default()
    }

    fn segment_size(&self) -> SegmentSize {
        Default::default()
    }

    fn header(&self, query: HashOf<Header>) -> Option<HeaderExt<Header>> {
        self.0.headers.get(&query).cloned()
    }

    fn store_header(&mut self, header_ext: HeaderExt<Header>, as_best_header: bool) {
        let (number, hash) = (*header_ext.header.number(), header_ext.header.hash());
        if self.0.headers.insert(hash, header_ext).is_none() {
            let mut set = self
                .0
                .number_to_hashes
                .get(&number)
                .cloned()
                .unwrap_or_default();
            set.push(hash);
            self.0.number_to_hashes.insert(number, set);
        }
        if as_best_header {
            self.0.best_header = (number, hash)
        }
    }

    fn best_header(&self) -> HeaderExt<Header> {
        let (_, hash) = self.0.best_header;
        self.0.headers.get(&hash).cloned().unwrap()
    }
}

impl MockStorage {
    // hack to adjust the solution range
    pub(crate) fn override_solution_range(
        &mut self,
        hash: HashOf<Header>,
        solution_range: SolutionRange,
    ) {
        let mut header = self.0.headers.remove(&hash).unwrap();
        header.derived_solution_range = solution_range;
        self.0.headers.insert(hash, header);
    }

    // hack to adjust the cumulative weight
    pub(crate) fn override_cumulative_weight(&mut self, hash: HashOf<Header>, weight: BlockWeight) {
        let mut header = self.0.headers.remove(&hash).unwrap();
        header.total_weight = weight;
        self.0.headers.insert(hash, header);
    }

    pub(crate) fn headers_at(&self, number: NumberOf<Header>) -> Vec<HeaderExt<Header>> {
        println!("{:?}", self.0.number_to_hashes);
        self.0
            .number_to_hashes
            .get(&number)
            .unwrap_or(&vec![])
            .iter()
            .map(|hash| self.0.headers.get(hash).cloned().unwrap())
            .collect()
    }
}

pub(crate) struct MockImporter;
impl HeaderImporter<Header, MockStorage> for MockImporter {}
