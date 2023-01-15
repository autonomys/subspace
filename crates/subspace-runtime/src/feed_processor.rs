use crate::{FeedId, Runtime};
use codec::{Decode, Encode};
use pallet_feeds::feed_processor::{FeedMetadata, FeedObjectMapping, FeedProcessor};
use pallet_grandpa_finality_verifier::chain::Chain;
use scale_info::TypeInfo;
use sp_api::HeaderT;
use sp_core::Hasher;
use sp_runtime::traits::BlakeTwo256;
use sp_runtime::{generic, DispatchError};
use sp_std::prelude::*;

/// Polkadot-like chain.
struct PolkadotLike;
impl Chain for PolkadotLike {
    type BlockNumber = u32;
    type Hash = <BlakeTwo256 as Hasher>::Out;
    type Header = generic::Header<u32, BlakeTwo256>;
    type Hasher = BlakeTwo256;
}

/// Type used to represent a FeedId or ChainId
struct GrandpaValidator<C>(C);

impl<C: Chain> FeedProcessor<FeedId> for GrandpaValidator<C> {
    fn init(&self, feed_id: FeedId, data: &[u8]) -> sp_runtime::DispatchResult {
        pallet_grandpa_finality_verifier::initialize::<Runtime, C>(feed_id, data)
    }

    fn put(&self, feed_id: FeedId, object: &[u8]) -> Result<Option<FeedMetadata>, DispatchError> {
        Ok(Some(
            pallet_grandpa_finality_verifier::validate_finalized_block::<Runtime, C>(
                feed_id, object,
            )?
            .encode(),
        ))
    }

    fn object_mappings(&self, _feed_id: FeedId, object: &[u8]) -> Vec<FeedObjectMapping> {
        extract_substrate_object_mapping::<C>(object)
    }

    fn delete(&self, feed_id: FeedId) -> sp_runtime::DispatchResult {
        pallet_grandpa_finality_verifier::purge::<Runtime>(feed_id)
    }
}

struct ParachainImporter<C>(C);

impl<C: Chain> FeedProcessor<FeedId> for ParachainImporter<C> {
    fn put(&self, _feed_id: FeedId, object: &[u8]) -> Result<Option<FeedMetadata>, DispatchError> {
        let block = C::decode_block::<Runtime>(object)?;
        Ok(Some(
            (block.block.header.hash(), *block.block.header.number()).encode(),
        ))
    }
    fn object_mappings(&self, _feed_id: FeedId, object: &[u8]) -> Vec<FeedObjectMapping> {
        extract_substrate_object_mapping::<C>(object)
    }
}

fn extract_substrate_object_mapping<C: Chain>(object: &[u8]) -> Vec<FeedObjectMapping> {
    let block = match C::decode_block::<Runtime>(object) {
        Ok(block) => block,
        // we just return empty if we failed to decode as this is not called in runtime
        Err(_) => return vec![],
    };

    // we send two mappings pointed to the same object
    // block height and block hash
    // this would be easier for sync client to crawl through the descendents by block height
    // if you already have a block hash, you can fetch the same block with it as well
    vec![
        FeedObjectMapping::Custom {
            key: block.block.header.number().encode(),
            offset: 0,
        },
        FeedObjectMapping::Custom {
            key: block.block.header.hash().as_ref().to_vec(),
            offset: 0,
        },
    ]
}

/// FeedProcessorId represents the available FeedProcessor impls
#[derive(Default, Debug, Clone, Copy, Encode, Decode, TypeInfo, Eq, PartialEq)]
pub enum FeedProcessorKind {
    /// Content addressable Feed processor,
    #[default]
    ContentAddressable,
    /// Polkadot like relay chain Feed processor that validates grandpa justifications and indexes the entire block
    PolkadotLike,
    /// Parachain Feed processor that just indexes the entire block
    ParachainLike,
}

pub(crate) fn feed_processor(
    feed_processor_kind: FeedProcessorKind,
) -> Box<dyn FeedProcessor<FeedId>> {
    match feed_processor_kind {
        FeedProcessorKind::PolkadotLike => Box::new(GrandpaValidator(PolkadotLike)),
        FeedProcessorKind::ContentAddressable => Box::new(()),
        FeedProcessorKind::ParachainLike => Box::new(ParachainImporter(PolkadotLike)),
    }
}
