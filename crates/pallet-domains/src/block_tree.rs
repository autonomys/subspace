//! Domain block tree

use crate::{
    BlockTree, Config, DomainBlocks, ExecutionInbox, ExecutionReceiptOf, HeadReceiptNumber,
};
use codec::{Decode, Encode};
use frame_support::{ensure, PalletError};
use scale_info::TypeInfo;
use sp_core::Get;
use sp_domains::v2::ExecutionReceipt;
use sp_domains::{DomainId, OperatorId};
use sp_runtime::traits::{CheckedSub, One, Saturating, Zero};
use sp_std::cmp::Ordering;
use sp_std::vec::Vec;

/// Block tree specific errors
#[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
pub enum Error {
    InvalidExtrinsicsRoots,
    UnknownParentBlockReceipt,
    BuiltOnUnknownConsensusBlock,
    InFutureReceipt,
    PrunedReceipt,
    ChallengeGenesisReceipt,
    ExceedMaxBlockTreeFork,
    UnexpectedReceiptType,
    MaxHeadDomainNumber,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct DomainBlock<Number, Hash, DomainNumber, DomainHash, Balance> {
    /// The full ER for this block.
    pub execution_receipt: ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance>,
    /// A set of all operators who have committed to this ER within a bundle. Used to determine who to
    /// slash if a fraudulent branch of the `block_tree` is pruned.
    ///
    /// NOTE: there may be duplicated operator id as an operator can submit multiple bundles with the
    /// same head receipt to a consensus block.
    pub operator_ids: Vec<OperatorId>,
}

/// The type of receipt regarding to its freshness
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReceiptType {
    // New head receipt that extend the longest branch
    NewHead,
    // Receipt that comfirms the current head receipt
    CurrentHead,
    // Receipt that creates a new branch of the block tree
    NewBranch,
    // Receipt that is newer than the head receipt but does not extend the head receipt
    InFuture,
    // Receipt that comfirm a non-head receipt
    Stale,
    // Receipt that already been pruned
    Pruned,
}

/// Get the receipt type of the given receipt based on the current block tree state
pub(crate) fn execution_receipt_type<T: Config>(
    domain_id: DomainId,
    execution_receipt: &ExecutionReceiptOf<T>,
) -> ReceiptType {
    let receipt_number = execution_receipt.domain_block_number;
    let head_receipt_number = HeadReceiptNumber::<T>::get(domain_id);

    match receipt_number.cmp(&head_receipt_number.saturating_add(One::one())) {
        Ordering::Greater => ReceiptType::InFuture,
        Ordering::Equal => ReceiptType::NewHead,
        Ordering::Less => {
            let oldest_receipt_number =
                head_receipt_number.saturating_sub(T::BlockTreePruningDepth::get());
            let already_exist =
                BlockTree::<T>::get(domain_id, receipt_number).contains(&execution_receipt.hash());

            if receipt_number < oldest_receipt_number {
                // Receipt already pruned
                ReceiptType::Pruned
            } else if !already_exist {
                // Create new branch
                ReceiptType::NewBranch
            } else if receipt_number == head_receipt_number {
                // Add comfirm to the current head receipt
                ReceiptType::CurrentHead
            } else {
                // Add comfirm to a non-head receipt
                ReceiptType::Stale
            }
        }
    }
}

/// Verify the execution receipt
pub(crate) fn verify_execution_receipt<T: Config>(
    domain_id: DomainId,
    execution_receipt: &ExecutionReceiptOf<T>,
) -> Result<(), Error> {
    let ExecutionReceipt {
        consensus_block_number,
        consensus_block_hash,
        domain_block_number,
        block_extrinsics_roots,
        parent_domain_block_receipt_hash,
        ..
    } = execution_receipt;

    if !domain_block_number.is_zero() {
        let execution_inbox = ExecutionInbox::<T>::get(domain_id, domain_block_number);
        ensure!(
            !block_extrinsics_roots.is_empty() && *block_extrinsics_roots == execution_inbox,
            Error::InvalidExtrinsicsRoots
        );
    }

    let excepted_consensus_block_hash =
        frame_system::Pallet::<T>::block_hash(consensus_block_number);
    ensure!(
        *consensus_block_hash == excepted_consensus_block_hash,
        Error::BuiltOnUnknownConsensusBlock
    );

    if let Some(parent_block_number) = domain_block_number.checked_sub(&One::one()) {
        let parent_block_exist = BlockTree::<T>::get(domain_id, parent_block_number)
            .contains(parent_domain_block_receipt_hash);
        ensure!(parent_block_exist, Error::UnknownParentBlockReceipt);
    }

    match execution_receipt_type::<T>(domain_id, execution_receipt) {
        ReceiptType::InFuture => {
            log::error!(
                "Unexpected in future receipt {execution_receipt:?}, which should result in \
                `UnknownParentBlockReceipt` error as it parent receipt is missing"
            );
            Err(Error::InFutureReceipt)
        }
        ReceiptType::Pruned => {
            log::error!(
                "Unexpected pruned receipt {execution_receipt:?}, which should result in \
                `InvalidExtrinsicsRoots` error as its `ExecutionInbox` is pruned at the same time"
            );
            Err(Error::PrunedReceipt)
        }
        // The genesis receipt is generated and added to the block tree by the runtime upon domain
        // instantiation, thus it is unchallengeable and must always be the same.
        ReceiptType::NewBranch if domain_block_number.is_zero() => {
            Err(Error::ChallengeGenesisReceipt)
        }
        ReceiptType::NewHead
        | ReceiptType::NewBranch
        | ReceiptType::CurrentHead
        | ReceiptType::Stale => Ok(()),
    }
}

/// Process the execution receipt to add it to the block tree
///
/// NOTE: only `NewHead`, `NewBranch` and `CurrentHead` type of receipt is expected
/// for this function, passing other type of receipt will result in an `UnexpectedReceiptType`
/// error.
pub(crate) fn process_execution_receipt<T: Config>(
    domain_id: DomainId,
    submitter: OperatorId,
    execution_receipt: ExecutionReceiptOf<T>,
    receipt_type: ReceiptType,
) -> Result<(), Error> {
    let er_hash = execution_receipt.hash();
    match receipt_type {
        er_type @ ReceiptType::NewHead | er_type @ ReceiptType::NewBranch => {
            // Construct and add a new domain block to the block tree
            let domain_block_number = execution_receipt.domain_block_number;
            let domain_block = DomainBlock {
                execution_receipt,
                operator_ids: sp_std::vec![submitter],
            };
            BlockTree::<T>::mutate(domain_id, domain_block_number, |er_hashes| {
                er_hashes
                    .try_insert(er_hash)
                    .map_err(|_| Error::ExceedMaxBlockTreeFork)?;
                Ok(())
            })?;
            DomainBlocks::<T>::insert(er_hash, domain_block);

            if er_type == ReceiptType::NewHead {
                // Update the head receipt number
                HeadReceiptNumber::<T>::insert(domain_id, domain_block_number);

                // Prune expired domain block
                if let Some(to_prune) =
                    domain_block_number.checked_sub(&T::BlockTreePruningDepth::get())
                {
                    for block in BlockTree::<T>::take(domain_id, to_prune) {
                        DomainBlocks::<T>::remove(block);
                    }
                    // Remove the block's `ExecutionInbox` as the block is pruned and does not need
                    // to verify its receipt's `extrinsics_root` anymore
                    ExecutionInbox::<T>::remove(domain_id, to_prune);
                }
            }
        }
        ReceiptType::CurrentHead => {
            // Add confirmation to the current head receipt
            DomainBlocks::<T>::mutate(er_hash, |maybe_domain_block| {
                let domain_block = maybe_domain_block.as_mut().expect(
                    "The domain block of `CurrentHead` receipt is checked to be exist in `execution_receipt_type`; qed"
                );
                domain_block.operator_ids.push(submitter);
            });
        }
        // Other types of receipt is unexpected for this function
        _ => return Err(Error::UnexpectedReceiptType),
    }
    Ok(())
}

/// Import the genesis receipt to the block tree
pub(crate) fn import_genesis_receipt<T: Config>(
    domain_id: DomainId,
    genesis_receipt: ExecutionReceiptOf<T>,
) {
    let er_hash = genesis_receipt.hash();
    let domain_block_number = genesis_receipt.domain_block_number;
    let domain_block = DomainBlock {
        execution_receipt: genesis_receipt,
        operator_ids: sp_std::vec![],
    };
    // NOTE: no need to upate the head receipt number as we are using `ValueQuery`
    BlockTree::<T>::mutate(domain_id, domain_block_number, |er_hashes| {
        er_hashes.try_insert(er_hash)
            .expect(
                "Must not exceed MaxBlockTreeFork as the genesis receipt is the first and only receipt at block #0; qed"
            );
    });
    DomainBlocks::<T>::insert(er_hash, domain_block);
}
