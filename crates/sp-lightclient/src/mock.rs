use crate::{
    BlockWeight, HashOf, HeaderExt, HeaderImporter, NumberOf, RecordSize, SegmentSize,
    SolutionRange, Storage,
};
use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_arithmetic::traits::Zero;
use sp_runtime::traits::{BlakeTwo256, Header as HeaderT};
use std::collections::HashMap;

pub(crate) type Header = sp_runtime::generic::Header<u32, BlakeTwo256>;

#[derive(Debug, Default)]
struct StorageData {
    global_randomness_interval: NumberOf<Header>,
    k_depth: NumberOf<Header>,
    headers: HashMap<HashOf<Header>, HeaderExt<Header>>,
    number_to_hashes: HashMap<NumberOf<Header>, Vec<HashOf<Header>>>,
    best_header: (NumberOf<Header>, HashOf<Header>),
    finalized_head: Option<(NumberOf<Header>, HashOf<Header>)>,
}

#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub(crate) struct TestOverrides {
    pub(crate) solution_range: Option<SolutionRange>,
}

#[derive(Debug)]
pub(crate) struct MockStorage(StorageData);
impl Storage<Header> for MockStorage {
    fn record_size(&self) -> RecordSize {
        Default::default()
    }

    fn segment_size(&self) -> SegmentSize {
        Default::default()
    }

    fn k_depth(&self) -> NumberOf<Header> {
        self.0.k_depth
    }

    fn randomness_update_interval(&self) -> NumberOf<Header> {
        self.0.global_randomness_interval
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

    fn finalize_header(&mut self, hash: HashOf<Header>) -> Vec<HeaderExt<Header>> {
        let header = self.0.headers.get(&hash).cloned().expect("must be present");
        let fork_headers: Vec<HeaderExt<Header>> = self
            .0
            .number_to_hashes
            .get(header.header.number())
            .cloned()
            .unwrap()
            .into_iter()
            .filter(|hash| *hash != header.header.hash())
            .map(|hash| self.0.headers.remove(&hash).unwrap())
            .collect();

        self.0
            .number_to_hashes
            .insert(header.header.number, vec![header.header.hash()]);

        self.0.finalized_head = Some((header.header.number, header.header.hash()));
        fork_headers
    }

    fn finalized_head(&self) -> (NumberOf<Header>, HashOf<Header>) {
        self.0.finalized_head.unwrap_or_else(|| {
            let genesis = self
                .0
                .number_to_hashes
                .get(&Zero::zero())
                .cloned()
                .unwrap_or_else(|| vec![Default::default()])[0];
            (0, genesis)
        })
    }

    fn heads_at_number(&self, number: NumberOf<Header>) -> Vec<HashOf<Header>> {
        self.0
            .number_to_hashes
            .get(&number)
            .cloned()
            .unwrap_or_default()
    }

    fn prune_headers_with_parents_at_number(
        &mut self,
        number: NumberOf<Header>,
        parents: Vec<HashOf<Header>>,
    ) -> Vec<HeaderExt<Header>> {
        let pruned_headers: Vec<HeaderExt<Header>> = self
            .0
            .number_to_hashes
            .get(&number)
            .unwrap()
            .iter()
            .filter_map(|hash| {
                let header = self.0.headers.get(hash).unwrap();
                if !parents.contains(&header.header.parent_hash) {
                    return None;
                }

                self.0.headers.remove(hash)
            })
            .collect();

        let pruned_hashes: Vec<HashOf<Header>> = pruned_headers
            .iter()
            .map(|header| header.header.hash())
            .collect();

        let hashes_to_keep = self
            .0
            .number_to_hashes
            .remove(&number)
            .unwrap()
            .into_iter()
            .filter(|hash| !pruned_hashes.contains(hash))
            .collect();

        self.0.number_to_hashes.insert(number, hashes_to_keep);

        pruned_headers
    }
}

impl MockStorage {
    pub(crate) fn new(
        global_randomness_interval: NumberOf<Header>,
        k_depth: NumberOf<Header>,
    ) -> Self {
        Self(StorageData {
            global_randomness_interval,
            k_depth,
            ..Default::default()
        })
    }

    // hack to adjust the solution range
    pub(crate) fn override_solution_range(
        &mut self,
        hash: HashOf<Header>,
        solution_range: SolutionRange,
    ) {
        let mut header = self.0.headers.remove(&hash).unwrap();
        header.overrides.solution_range = Some(solution_range);
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
