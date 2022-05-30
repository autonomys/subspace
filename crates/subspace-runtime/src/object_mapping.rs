use crate::{Block, Call, Runtime};
use codec::{Compact, CompactLen, Encode};
use sp_api::HashT;
use sp_runtime::traits::BlakeTwo256;
use sp_std::iter::Peekable;
use sp_std::prelude::*;
use subspace_core_primitives::objects::{BlockObject, BlockObjectMapping};
use subspace_runtime_primitives::Hash;

const MAX_OBJECT_MAPPING_RECURSION_DEPTH: u16 = 5;

pub(crate) fn extract_feeds_block_object_mapping<I: Iterator<Item = Hash>>(
    base_offset: u32,
    objects: &mut Vec<BlockObject>,
    call: &pallet_feeds::Call<Runtime>,
    successful_calls: &mut Peekable<I>,
) {
    let call_hash = successful_calls.peek();
    match call_hash {
        Some(hash) => {
            if <BlakeTwo256 as HashT>::hash(call.encode().as_slice()) != *hash {
                return;
            }

            // remove the hash and fetch the object mapping for this call
            successful_calls.next();
        }
        None => return,
    }

    call.extract_call_objects()
        .into_iter()
        .for_each(|object_map| {
            objects.push(BlockObject::V0 {
                hash: object_map.key,
                offset: base_offset + object_map.offset,
            })
        })
}

pub(crate) fn extract_object_store_block_object_mapping(
    base_offset: u32,
    objects: &mut Vec<BlockObject>,
    call: &pallet_object_store::Call<Runtime>,
) {
    if let Some(call_object) = call.extract_call_object() {
        objects.push(BlockObject::V0 {
            hash: call_object.hash,
            offset: base_offset + call_object.offset,
        });
    }
}

pub(crate) fn extract_utility_block_object_mapping<I: Iterator<Item = Hash>>(
    mut base_offset: u32,
    objects: &mut Vec<BlockObject>,
    call: &pallet_utility::Call<Runtime>,
    mut recursion_depth_left: u16,
    successful_calls: &mut Peekable<I>,
) {
    if recursion_depth_left == 0 {
        return;
    }

    recursion_depth_left -= 1;

    // Add enum variant to the base offset.
    base_offset += 1;

    match call {
        pallet_utility::Call::batch { calls }
        | pallet_utility::Call::batch_all { calls }
        | pallet_utility::Call::force_batch { calls } => {
            base_offset += Compact::compact_len(&(calls.len() as u32)) as u32;

            for call in calls {
                extract_call_block_object_mapping(
                    base_offset,
                    objects,
                    call,
                    recursion_depth_left,
                    successful_calls,
                );

                base_offset += call.encoded_size() as u32;
            }
        }
        pallet_utility::Call::as_derivative { index, call } => {
            base_offset += index.encoded_size() as u32;

            extract_call_block_object_mapping(
                base_offset,
                objects,
                call.as_ref(),
                recursion_depth_left,
                successful_calls,
            );
        }
        pallet_utility::Call::dispatch_as { as_origin, call } => {
            base_offset += as_origin.encoded_size() as u32;

            extract_call_block_object_mapping(
                base_offset,
                objects,
                call.as_ref(),
                recursion_depth_left,
                successful_calls,
            );
        }
        pallet_utility::Call::__Ignore(_, _) => {
            // Ignore.
        }
    }
}

pub(crate) fn extract_call_block_object_mapping<I: Iterator<Item = Hash>>(
    mut base_offset: u32,
    objects: &mut Vec<BlockObject>,
    call: &Call,
    recursion_depth_left: u16,
    successful_calls: &mut Peekable<I>,
) {
    // Add enum variant to the base offset.
    base_offset += 1;

    match call {
        Call::Feeds(call) => {
            extract_feeds_block_object_mapping(base_offset, objects, call, successful_calls);
        }
        Call::ObjectStore(call) => {
            extract_object_store_block_object_mapping(base_offset, objects, call);
        }
        Call::Utility(call) => {
            extract_utility_block_object_mapping(
                base_offset,
                objects,
                call,
                recursion_depth_left,
                successful_calls,
            );
        }
        _ => {}
    }
}

pub(crate) fn extract_block_object_mapping(
    block: Block,
    successful_calls: Vec<Hash>,
) -> BlockObjectMapping {
    let mut block_object_mapping = BlockObjectMapping::default();
    let mut successful_calls = successful_calls.into_iter().peekable();
    let mut base_offset =
        block.header.encoded_size() + Compact::compact_len(&(block.extrinsics.len() as u32));
    for extrinsic in block.extrinsics {
        let signature_size = extrinsic
            .signature
            .as_ref()
            .map(|s| s.encoded_size())
            .unwrap_or_default();
        // Extrinsic starts with vector length and version byte, followed by optional signature and
        // `function` encoding.
        let base_extrinsic_offset = base_offset
            + Compact::compact_len(
                &((1 + signature_size + extrinsic.function.encoded_size()) as u32),
            )
            + 1
            + signature_size;

        extract_call_block_object_mapping(
            base_extrinsic_offset as u32,
            &mut block_object_mapping.objects,
            &extrinsic.function,
            MAX_OBJECT_MAPPING_RECURSION_DEPTH,
            &mut successful_calls,
        );

        base_offset += extrinsic.encoded_size();
    }

    block_object_mapping
}
