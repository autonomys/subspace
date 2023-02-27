use crate::feed_processor::{FeedObjectMapping, FeedProcessor, FeedProcessor as FeedProcessorT};
use crate::{self as pallet_feeds};
use codec::{Compact, CompactLen, Decode, Encode};
use frame_support::parameter_types;
use frame_support::traits::{ConstU16, ConstU32, ConstU64};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::testing::Header;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;
type FeedId = u64;

frame_support::construct_runtime!(
    pub struct Test where
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
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type RuntimeEvent = RuntimeEvent;
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
    pub const MaxFeeds: u32 = 1;
}

#[derive(Default, Debug, Copy, Clone, Encode, Decode, TypeInfo, Eq, PartialEq)]
pub enum MockFeedProcessorKind {
    #[default]
    Content,
    ContentWithin,
    Custom([u8; 32]),
}

impl pallet_feeds::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type FeedId = FeedId;
    type FeedProcessorKind = MockFeedProcessorKind;
    type MaxFeeds = MaxFeeds;

    fn feed_processor(
        feed_processor_kind: Self::FeedProcessorKind,
    ) -> Box<dyn FeedProcessorT<Self::FeedId>> {
        match feed_processor_kind {
            MockFeedProcessorKind::Content => Box::new(()),
            MockFeedProcessorKind::ContentWithin => Box::new(ContentEnumFeedProcessor),
            MockFeedProcessorKind::Custom(key) => {
                Box::new(CustomContentFeedProcessor(key.to_vec()))
            }
        }
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

/// Same as default except key is not derived from object
struct CustomContentFeedProcessor(Vec<u8>);

impl FeedProcessor<FeedId> for CustomContentFeedProcessor {
    fn object_mappings(&self, _feed_id: FeedId, _object: &[u8]) -> Vec<FeedObjectMapping> {
        vec![FeedObjectMapping::Custom {
            key: self.0.clone(),
            offset: 0,
        }]
    }
}

// this is the content enum encoded as object for the put call
// we want to index content_a or content_b by an index either content addressable or name spaced key
#[derive(Debug, Clone, Encode, Decode)]
pub(crate) enum ContentEnum {
    ContentA(Vec<u8>),
    ContentB(Vec<u8>),
}

struct ContentEnumFeedProcessor;

impl FeedProcessor<FeedId> for ContentEnumFeedProcessor {
    fn object_mappings(&self, _feed_id: FeedId, object: &[u8]) -> Vec<FeedObjectMapping> {
        let content =
            ContentEnum::decode(&mut object.to_vec().as_slice()).expect("must decode to content");

        match content {
            ContentEnum::ContentA(_) | ContentEnum::ContentB(_) => {
                vec![FeedObjectMapping::Content {
                    // also need to consider the encoded length of the object
                    // encoded content_a or content_b starts at offset 1 due to enum variant
                    offset: 1 + Compact::<u32>::compact_len(&(object.len() as u32)) as u32,
                }]
            }
        }
    }
}
