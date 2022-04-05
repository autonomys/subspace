use crate as pallet_feeds;
use crate::feed_processor::{FeedMetadata, FeedProcessor as FeedProcessorT, FeedProcessorId};
use crate::FeedObjectMapping;
use frame_support::parameter_types;
use frame_support::traits::{ConstU16, ConstU32, ConstU64};
use sp_core::H256;
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
    DispatchError, DispatchResult,
};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;
type FeedId = u64;

frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
        Feeds: pallet_feeds::{Pallet, Call, Storage, Event<T>}
    }
);

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type Origin = Origin;
    type Call = Call;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = Event;
    type BlockHashCount = ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
}

parameter_types! {
    pub const ExistentialDeposit: u64 = 1;
}

impl FeedProcessorT<FeedId> for () {
    fn init(&self, _feed_id: FeedId, _data: &[u8]) -> sp_runtime::DispatchResult {
        Ok(())
    }

    fn put(&self, _feed_id: FeedId, object: &[u8]) -> Result<Option<FeedMetadata>, DispatchError> {
        Ok(Some(FeedMetadata::from(object)))
    }

    fn object_mappings(&self, _feed_id: FeedId, _object: &[u8]) -> Vec<FeedObjectMapping> {
        vec![]
    }

    fn delete(&self, _feed_id: FeedId) -> DispatchResult {
        Ok(())
    }
}

impl pallet_feeds::Config for Test {
    type Event = Event;
    type FeedId = FeedId;

    fn feed_processor(
        _feed_processor_id: FeedProcessorId,
    ) -> Box<dyn FeedProcessorT<Self::FeedId>> {
        Box::new(())
    }
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();

    let mut t: sp_io::TestExternalities = t.into();

    t.execute_with(|| System::set_block_number(1));

    t
}
