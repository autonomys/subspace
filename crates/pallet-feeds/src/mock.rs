// Silence a rust-analyzer warning in `construct_runtime!`. This warning isn't present in rustc output.
// TODO: remove when upstream issue is fixed: <https://github.com/rust-lang/rust-analyzer/issues/16514>
#![allow(non_camel_case_types)]

use crate::feed_processor::{FeedObjectMapping, FeedProcessor, FeedProcessor as FeedProcessorT};
use crate::{self as pallet_feeds};
use codec::{Compact, CompactLen, Decode, Encode};
use frame_support::{derive_impl, parameter_types};
use scale_info::TypeInfo;
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;
type FeedId = u64;

frame_support::construct_runtime!(
    pub struct Test {
        System: frame_system,
        Feeds: pallet_feeds,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
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
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
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
