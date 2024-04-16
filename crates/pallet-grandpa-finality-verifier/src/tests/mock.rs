use frame_support::weights::Weight;
use frame_support::{construct_runtime, derive_impl, parameter_types};
use sp_runtime::Perbill;

pub(crate) type ChainId = u64;
type Block = frame_system::mocking::MockBlock<TestRuntime>;

use crate as grandpa;

construct_runtime! {
    pub struct TestRuntime {
        System: frame_system,
        Grandpa: grandpa,
    }
}

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const MaximumBlockWeight: Weight = Weight::from_parts(1024, 0);
    pub const MaximumBlockLength: u32 = 2 * 1024;
    pub const AvailableBlockRatio: Perbill = Perbill::one();
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for TestRuntime {
    type Block = Block;
}

impl grandpa::Config for TestRuntime {
    type ChainId = ChainId;
}

pub fn run_test<T>(test: impl FnOnce() -> T) -> T {
    sp_io::TestExternalities::new(Default::default()).execute_with(test)
}
