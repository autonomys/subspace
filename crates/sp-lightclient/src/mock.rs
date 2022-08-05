use crate::{
    BlockWeight, ChainConstants, HashOf, HeaderExt, NumberOf, RecordsRoot, SegmentIndex,
    SolutionRange, Storage,
};
use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_arithmetic::traits::Zero;
use sp_runtime::traits::{BlakeTwo256, Header as HeaderT};
use std::collections::{BTreeMap, HashMap};

pub(crate) type Header = sp_runtime::generic::Header<u32, BlakeTwo256>;

#[derive(Debug)]
struct StorageData {
    constants: ChainConstants<Header>,
    headers: HashMap<HashOf<Header>, HeaderExt<Header>>,
    number_to_hashes: HashMap<NumberOf<Header>, Vec<HashOf<Header>>>,
    best_header: (NumberOf<Header>, HashOf<Header>),
    finalized_head: Option<(NumberOf<Header>, HashOf<Header>)>,
    records_roots: BTreeMap<SegmentIndex, RecordsRoot>,
}

#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub(crate) struct TestOverrides {
    pub(crate) solution_range: Option<SolutionRange>,
    pub(crate) next_solution_range: Option<SolutionRange>,
}

#[derive(Debug)]
pub(crate) struct MockStorage(StorageData);
impl Storage<Header> for MockStorage {
    fn chain_constants(&self) -> ChainConstants<Header> {
        self.0.constants.clone()
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

    fn store_records_roots(&mut self, mut records_roots: BTreeMap<SegmentIndex, RecordsRoot>) {
        self.0.records_roots.append(&mut records_roots)
    }

    fn records_root(&self, segment_index: SegmentIndex) -> Option<RecordsRoot> {
        self.0.records_roots.get(&segment_index).cloned()
    }

    fn records_roots_count(&self) -> u64 {
        self.0.records_roots.len() as u64
    }
}

impl MockStorage {
    pub(crate) fn new(constants: ChainConstants<Header>) -> Self {
        MockStorage(StorageData {
            constants,
            headers: Default::default(),
            number_to_hashes: Default::default(),
            best_header: (Default::default(), Default::default()),
            finalized_head: None,
            records_roots: Default::default(),
        })
    }

    // hack to adjust the solution range
    pub(crate) fn override_solution_range(
        &mut self,
        hash: HashOf<Header>,
        solution_range: SolutionRange,
    ) {
        let mut header = self.0.headers.remove(&hash).unwrap();
        header.test_overrides.solution_range = Some(solution_range);
        self.0.headers.insert(hash, header);
    }

    // hack to adjust the next solution range
    pub(crate) fn override_next_solution_range(
        &mut self,
        hash: HashOf<Header>,
        next_solution_range: SolutionRange,
    ) {
        let mut header = self.0.headers.remove(&hash).unwrap();
        header.test_overrides.next_solution_range = Some(next_solution_range);
        self.0.headers.insert(hash, header);
    }

    // hack to adjust constants when importing Block #1
    pub(crate) fn override_constants(&mut self, constants: ChainConstants<Header>) {
        self.0.constants = constants;
    }

    // hack to adjust the cumulative weight
    pub(crate) fn override_cumulative_weight(&mut self, hash: HashOf<Header>, weight: BlockWeight) {
        let mut header = self.0.headers.remove(&hash).unwrap();
        header.total_weight = weight;
        self.0.headers.insert(hash, header);
    }

    // hack to store records roots
    pub(crate) fn store_records_root(
        &mut self,
        segment_index: SegmentIndex,
        records_root: RecordsRoot,
    ) {
        self.0.records_roots.insert(segment_index, records_root);
    }
}
