use crate::archiver::SegmentHeadersStore;
use parking_lot::RwLock;
use sc_client_api::AuxStore;
use std::collections::HashMap;
use std::sync::Arc;
use subspace_core_primitives::segments::SegmentIndex;
use subspace_core_primitives::{ArchivedBlockProgress, LastArchivedBlock, SegmentHeader};

struct MemAuxStore {
    store: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl MemAuxStore {
    fn new() -> Self {
        Self {
            store: RwLock::new(Default::default()),
        }
    }
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

#[test]
fn segment_headers_store_block_number_queries_work() {
    let confirmation_depth_k = 100;
    let segment_headers =
        SegmentHeadersStore::new(Arc::new(MemAuxStore::new()), confirmation_depth_k).unwrap();

    // Several starting segments from gemini-3h

    let segment_header0 = SegmentHeader::V0 {
        segment_index: SegmentIndex::ZERO,
        segment_commitment: Default::default(),
        prev_segment_header_hash: Default::default(),
        last_archived_block: LastArchivedBlock {
            number: 0,
            archived_progress: ArchivedBlockProgress::Partial(5),
        },
    };

    let segment_header1 = SegmentHeader::V0 {
        segment_index: SegmentIndex::ONE,
        segment_commitment: Default::default(),
        prev_segment_header_hash: Default::default(),
        last_archived_block: LastArchivedBlock {
            number: 652,
            archived_progress: ArchivedBlockProgress::Partial(5),
        },
    };

    let segment_header2 = SegmentHeader::V0 {
        segment_index: SegmentIndex::from(2),
        segment_commitment: Default::default(),
        prev_segment_header_hash: Default::default(),
        last_archived_block: LastArchivedBlock {
            number: 752,
            archived_progress: ArchivedBlockProgress::Partial(5),
        },
    };

    let segment_header3 = SegmentHeader::V0 {
        segment_index: SegmentIndex::from(3),
        segment_commitment: Default::default(),
        prev_segment_header_hash: Default::default(),
        last_archived_block: LastArchivedBlock {
            number: 806,
            archived_progress: ArchivedBlockProgress::Partial(5),
        },
    };

    let segment_header4 = SegmentHeader::V0 {
        segment_index: SegmentIndex::from(4),
        segment_commitment: Default::default(),
        prev_segment_header_hash: Default::default(),
        last_archived_block: LastArchivedBlock {
            number: 806,
            archived_progress: ArchivedBlockProgress::Partial(5),
        },
    };

    segment_headers
        .add_segment_headers(&[segment_header0])
        .unwrap();

    // Initial segment
    let segment_header0 = segment_headers
        .get_segment_header(SegmentIndex::ZERO)
        .unwrap();
    let result = segment_headers.segment_headers_for_block(1u32);
    assert_eq!(result, vec![segment_header0]);

    // Special case, genesis segment header is included in block 1, not later
    let result = segment_headers.segment_headers_for_block(confirmation_depth_k + 1);
    assert_eq!(result, vec![]);

    for num in 2u32..752u32 {
        let result = segment_headers.segment_headers_for_block(num);
        assert_eq!(result, vec![]);
    }

    segment_headers
        .add_segment_headers(&[
            segment_header1,
            segment_header2,
            segment_header3,
            segment_header4,
        ])
        .unwrap();

    for num in 2u32..752u32 {
        let result = segment_headers.segment_headers_for_block(num);
        assert_eq!(result, vec![]);
    }

    // End of first segment
    let segment_header1 = segment_headers
        .get_segment_header(SegmentIndex::ONE)
        .unwrap();
    // last archived block + confirmation depth + 1
    let result = segment_headers.segment_headers_for_block(753u32);
    assert_eq!(result, vec![segment_header1]);

    // No segment headers in between
    for num in 754u32..852u32 {
        let result = segment_headers.segment_headers_for_block(num);
        assert_eq!(result, vec![]);
    }

    // End of the second segment
    let segment_header2 = segment_headers
        .get_segment_header(SegmentIndex::from(2))
        .unwrap();
    let result = segment_headers.segment_headers_for_block(853u32);
    assert_eq!(result, vec![segment_header2]);

    // End of third segment
    let segment_header3 = segment_headers
        .get_segment_header(SegmentIndex::from(3))
        .unwrap();
    let result = segment_headers.segment_headers_for_block(907u32);
    assert_eq!(result, vec![segment_header3, segment_header4]);
}
