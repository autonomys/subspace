use crate::sectors::SBucket;
use crate::Record;

// Statically validate that we can store all possible s-buckets in SBucket data structure
#[test]
fn s_buckets_fit_into_data_structure() {
    assert!((SBucket::ZERO..=SBucket(u16::MAX)).count() <= Record::NUM_S_BUCKETS);
}
