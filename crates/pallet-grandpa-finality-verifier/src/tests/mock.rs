use frame_support::weights::Weight;
use frame_support::{construct_runtime, parameter_types};
use sp_runtime::testing::H256;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use sp_runtime::Perbill;

type AccountId = u64;
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

impl frame_system::Config for TestRuntime {
    type RuntimeOrigin = RuntimeOrigin;
    type Nonce = u64;
    type RuntimeCall = RuntimeCall;
    type RuntimeTask = RuntimeTask;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Block = Block;
    type RuntimeEvent = ();
    type BlockHashCount = BlockHashCount;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type BaseCallFilter = frame_support::traits::Everything;
    type SystemWeightInfo = ();
    type DbWeight = ();
    type BlockWeights = ();
    type BlockLength = ();
    type SS58Prefix = ();
    type OnSetCode = ();
    type MaxConsumers = frame_support::traits::ConstU32<16>;
}

impl grandpa::Config for TestRuntime {
    type ChainId = ChainId;
}

pub fn run_test<T>(test: impl FnOnce() -> T) -> T {
    sp_io::TestExternalities::new(Default::default()).execute_with(test)
}
