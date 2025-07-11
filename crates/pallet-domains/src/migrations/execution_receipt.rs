#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::pallet::BlockTreeNodes;
use crate::{
    BalanceOf, BlockTreeNodeFor, Config, DomainBlockNumberFor, DomainGenesisBlockExecutionReceipt,
    ExecutionReceiptOf, LatestConfirmedDomainExecutionReceipt, ReceiptHashFor,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use frame_support::pallet_prelude::{Encode, TypeInfo};
use frame_support::storage::generator::StorageMap;
use frame_system::pallet_prelude::BlockNumberFor;
use parity_scale_codec::Decode;
use sp_domains::execution_receipt::execution_receipt_v0::ExecutionReceiptV0;
use sp_domains::{DomainId, OperatorId};

pub(crate) type ExecutionReceiptV0Of<T> = ExecutionReceiptV0<
    BlockNumberFor<T>,
    <T as frame_system::Config>::Hash,
    DomainBlockNumberFor<T>,
    <T as Config>::DomainHash,
    BalanceOf<T>,
>;

pub fn latest_confirmed_domain_execution_receipt<T: Config>(
    domain_id: DomainId,
) -> Option<ExecutionReceiptOf<T>> {
    let key = LatestConfirmedDomainExecutionReceipt::<T>::storage_map_final_key(domain_id);
    decode_execution_receipt::<T>(key)
}

fn decode_execution_receipt<T: Config>(key: Vec<u8>) -> Option<ExecutionReceiptOf<T>> {
    let raw_value = sp_io::storage::get(key.as_slice())?;
    match ExecutionReceiptOf::<T>::decode(&mut &raw_value[..]) {
        Ok(er) => Some(er),
        Err(_) => ExecutionReceiptV0Of::<T>::decode(&mut &raw_value[..])
            .ok()
            .map(ExecutionReceiptOf::<T>::V0),
    }
}

pub fn domain_genesis_block_execution_receipt<T: Config>(
    domain_id: DomainId,
) -> Option<ExecutionReceiptOf<T>> {
    let key = DomainGenesisBlockExecutionReceipt::<T>::storage_map_final_key(domain_id);
    decode_execution_receipt::<T>(key)
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
struct BlockTreeNodeV0<Number, Hash, DomainNumber, DomainHash, Balance> {
    /// The full ER for this block.
    execution_receipt: ExecutionReceiptV0<Number, Hash, DomainNumber, DomainHash, Balance>,
    /// A set of all operators who have committed to this ER within a bundle. Used to determine who to
    /// slash if a fraudulent branch of the `block_tree` is pruned.
    ///
    /// NOTE: there may be duplicated operator id as an operator can submit multiple bundles with the
    /// same head receipt to a consensus block.
    operator_ids: Vec<OperatorId>,
}

type BlockTreeNodeV0For<T> = BlockTreeNodeV0<
    BlockNumberFor<T>,
    <T as frame_system::Config>::Hash,
    DomainBlockNumberFor<T>,
    <T as Config>::DomainHash,
    BalanceOf<T>,
>;

fn decode_block_tree_node<T: Config>(raw_value: Vec<u8>) -> Option<BlockTreeNodeFor<T>> {
    match BlockTreeNodeFor::<T>::decode(&mut &raw_value[..]) {
        Ok(er) => Some(er),
        Err(_) => BlockTreeNodeV0For::<T>::decode(&mut &raw_value[..])
            .ok()
            .map(|node| {
                let BlockTreeNodeV0 {
                    execution_receipt,
                    operator_ids,
                } = node;
                BlockTreeNodeFor::<T> {
                    execution_receipt: ExecutionReceiptOf::<T>::V0(execution_receipt),
                    operator_ids,
                }
            }),
    }
}

pub(crate) fn get_block_tree_node<T: Config>(
    receipt_hash: ReceiptHashFor<T>,
) -> Option<BlockTreeNodeFor<T>> {
    let key = BlockTreeNodes::<T>::storage_map_final_key(receipt_hash);
    let raw_value = sp_io::storage::get(key.as_slice())?;
    decode_block_tree_node::<T>(raw_value.to_vec())
}

pub(crate) fn take_block_tree_node<T: Config>(
    receipt_hash: ReceiptHashFor<T>,
) -> Option<BlockTreeNodeFor<T>> {
    let key = BlockTreeNodes::<T>::storage_map_final_key(receipt_hash);
    let raw_value = sp_io::storage::get(key.as_slice())?;
    sp_io::storage::clear(key.as_slice());
    decode_block_tree_node::<T>(raw_value.to_vec())
}
