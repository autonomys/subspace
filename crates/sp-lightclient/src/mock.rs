use crate::{
    BlockWeight, HashOf, HeaderExt, HeaderImporter, NumberOf, RecordSize, SegmentSize,
    SolutionRange, Storage,
};
use sp_arithmetic::traits::Zero;
use sp_runtime::traits::{BlakeTwo256, Header as HeaderT};
use std::collections::HashMap;

pub(crate) type Header = sp_runtime::generic::Header<u32, BlakeTwo256>;

#[derive(Debug, Default)]
struct StorageData {
    headers: HashMap<HashOf<Header>, HeaderExt<Header>>,
    number_to_hashes: HashMap<NumberOf<Header>, Vec<HashOf<Header>>>,
    best_header: (NumberOf<Header>, HashOf<Header>),
    finalized_head: Option<(NumberOf<Header>, HashOf<Header>)>,
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

    fn headers_at_number(&self, number: NumberOf<Header>) -> Vec<HeaderExt<Header>> {
        self.0
            .number_to_hashes
            .get(&number)
            .unwrap_or(&vec![])
            .iter()
            .map(|hash| self.0.headers.get(hash).cloned().unwrap())
            .collect()
    }

    fn prune_header(&mut self, pruned_hash: HashOf<Header>) {
        if let Some(pruned_header) = self.0.headers.remove(&pruned_hash) {
            let number_to_hashes = self
                .0
                .number_to_hashes
                .remove(pruned_header.header.number())
                .unwrap_or_default()
                .into_iter()
                .filter(|hash| *hash != pruned_hash)
                .collect();

            self.0
                .number_to_hashes
                .insert(*pruned_header.header.number(), number_to_hashes);
        }
    }

    fn finalize_header(&mut self, hash: HashOf<Header>) {
        let header = self.0.headers.get(&hash).unwrap();
        self.0.finalized_head = Some((*header.header.number(), header.header.hash()))
    }

    fn finalized_header(&self) -> HeaderExt<Header> {
        self.0
            .finalized_head
            .and_then(|(_, hash)| self.0.headers.get(&hash).cloned())
            .unwrap_or_else(|| {
                self.0
                    .headers
                    .get(
                        self.0
                            .number_to_hashes
                            .get(&Zero::zero())
                            .cloned()
                            .unwrap()
                            .get(0)
                            .unwrap(),
                    )
                    .cloned()
                    .unwrap()
            })
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
}

pub(crate) struct MockImporter;
impl HeaderImporter<Header, MockStorage> for MockImporter {}
