use crate::feed_processor::{FeedObjectMapping, FeedProcessor};
use crate::{self as pallet_feeds, feed_processor::FeedProcessor as FeedProcessorT};
use codec::{Decode, Encode};
use frame_support::{
    parameter_types,
    traits::{ConstU16, ConstU32, ConstU64},
};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
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
    pub const MaxFeeds: u32 = 1;
}

#[derive(Debug, Clone, Encode, Decode, TypeInfo, Eq, PartialEq)]
pub enum FeedProcessorKind {
    FullObject(Option<Vec<u8>>),
    Content(Option<Vec<u8>>),
    ContentEnum(Option<Vec<u8>>),
}

impl Default for FeedProcessorKind {
    fn default() -> Self {
        FeedProcessorKind::FullObject(None)
    }
}

impl pallet_feeds::Config for Test {
    type Event = Event;
    type FeedId = FeedId;
    type FeedProcessorKind = FeedProcessorKind;
    type MaxFeeds = MaxFeeds;

    fn feed_processor(
        feed_processor_kind: Self::FeedProcessorKind,
    ) -> Box<dyn FeedProcessorT<Self::FeedId>> {
        match feed_processor_kind {
            FeedProcessorKind::FullObject(maybe_key) => Box::new(FullObject(maybe_key)),
            FeedProcessorKind::Content(maybe_key) => Box::new(ContentFeedProcessor(maybe_key)),
            FeedProcessorKind::ContentEnum(maybe_key) => {
                Box::new(ContentEnumFeedProcessor(maybe_key))
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

// Same as Default with flexible key override
struct FullObject(Option<Vec<u8>>);

impl FeedProcessor<FeedId> for FullObject {
    fn object_mappings(&self, _feed_id: FeedId, _object: &[u8]) -> Vec<FeedObjectMapping> {
        vec![FeedObjectMapping::Object {
            key: self.0.clone(),
        }]
    }
}

// this is the content encoded as object for the put call
// we want to index content_a and content_b by an index either content addressable or name spaced key
#[derive(Debug, Clone, Encode, Decode)]
pub(crate) struct Content {
    pub(crate) content_a: Vec<u8>,
    pub(crate) content_b: Vec<u8>,
}

struct ContentFeedProcessor(Option<Vec<u8>>);

impl FeedProcessor<FeedId> for ContentFeedProcessor {
    fn object_mappings(&self, _feed_id: FeedId, object: &[u8]) -> Vec<FeedObjectMapping> {
        let content =
            Content::decode(&mut object.to_vec().as_slice()).expect("must decode to content");

        let content_b_offset = content.content_a.encoded_size();
        vec![
            FeedObjectMapping::Content {
                key: self.0.clone(),
                offset: 0, // encoded content_a starts at offset 0
            },
            FeedObjectMapping::Content {
                key: self.0.clone(),
                offset: content_b_offset as u32, // encoded content_b starts at 0 + encoded(content_a)
            },
        ]
    }
}

// this is the content enum encoded as object for the put call
// we want to index content_a or content_b by an index either content addressable or name spaced key
#[derive(Debug, Clone, Encode, Decode)]
pub(crate) enum ContentEnum {
    ContentA(Vec<u8>),
    ContentB(Vec<u8>),
}

struct ContentEnumFeedProcessor(Option<Vec<u8>>);

impl FeedProcessor<FeedId> for ContentEnumFeedProcessor {
    fn object_mappings(&self, _feed_id: FeedId, object: &[u8]) -> Vec<FeedObjectMapping> {
        let content =
            ContentEnum::decode(&mut object.to_vec().as_slice()).expect("must decode to content");

        match content {
            ContentEnum::ContentA(_) | ContentEnum::ContentB(_) => {
                vec![FeedObjectMapping::Content {
                    key: self.0.clone(),
                    offset: 1, // encoded content_a starts at offset 1 due to enum variant
                }]
            }
        }
    }
}
