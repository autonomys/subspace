use crate::SubspaceBlockWeights;
use frame_support::weights::Weight;

pub struct WeightInfo;

impl pallet_subspace::WeightInfo for WeightInfo {
    fn report_equivocation() -> Weight {
        // TODO: Proper value
        Weight::from_ref_time(10_000)
    }

    fn store_segment_headers(segment_headers_count: usize) -> Weight {
        // TODO: Proper value
        Weight::from_ref_time(10_000 * (segment_headers_count as u64 + 1))
    }

    fn vote() -> Weight {
        // TODO: Proper value, allowing up to 20 votes before block is full for now
        SubspaceBlockWeights::get().max_block.div(20)
    }
}
