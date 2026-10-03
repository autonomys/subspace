use crate::shader::constants::{MAX_BUCKET_SIZE, PARAM_BC, REDUCED_BUCKET_SIZE};
use crate::shader::find_matches_in_buckets::cpu_tests::Rmap as CorrectRmap;
use crate::shader::find_matches_in_buckets::rmap::Rmap;
use crate::shader::types::{Position, PositionExt, PositionR, R};
use chacha20::ChaCha8Rng;
use rand::prelude::*;
use std::array;

#[test]
fn test_rmap_against_reference() {
    let mut rng = ChaCha8Rng::from_seed(Default::default());

    let source_bucket = {
        let mut bucket = array::from_fn::<_, MAX_BUCKET_SIZE, _>(|i| PositionR {
            position: i as u32,
            // SAFETY: `r` is within `0..PARAM_BC` range
            r: unsafe { R::new(rng.random_range(0..u32::from(PARAM_BC))) },
        });
        bucket.shuffle(&mut rng);
        // There should be at most `REDUCED_BUCKET_SIZE` elements (safety invariant)
        bucket[REDUCED_BUCKET_SIZE..].fill(PositionR::SENTINEL);
        bucket
    };

    let mut rmap_correct = CorrectRmap::new();
    {
        let mut bucket = source_bucket;
        bucket.sort_by_key(|position_r| position_r.position);

        for position_r in bucket {
            if position_r.position == Position::SENTINEL {
                break;
            }
            // SAFETY: `r` is within `0..PARAM_BC` range, there are at most `REDUCED_BUCKET_SIZE`
            // elements in the bucket
            unsafe {
                rmap_correct.add(position_r.r.get(), position_r.position);
            }
        }
    }

    let mut rmap_concurrent = Rmap::new();
    {
        let mut bucket = source_bucket;
        bucket.sort_by_key(|position_r| position_r.position);

        for position_r in bucket {
            if position_r.position == Position::SENTINEL {
                break;
            }
            rmap_concurrent.add_with_data_parallel(position_r.r);
        }
    }

    for r in 0..u32::from(PARAM_BC) {
        // SAFETY: `r` is within `0..PARAM_BC` range
        let correct_positions = unsafe { rmap_correct.get(r) };

        assert_eq!(
            u32::from(correct_positions[0] != Position::SENTINEL)
                + u32::from(correct_positions[1] != Position::SENTINEL),
            // SAFETY: `r` is within `0..PARAM_BC` range
            rmap_concurrent.num_r_items(unsafe { R::new(r) }),
            "r={r:?}"
        );
    }
}
