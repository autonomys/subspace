//! Domain block tree

use crate::pallet::StateRoots;
use crate::{
    BalanceOf, BlockTree, BlockTreeNodes, Config, ConsensusBlockHash, DomainBlockDescendants,
    DomainBlockNumberFor, ExecutionInbox, ExecutionReceiptOf, HeadReceiptNumber,
    InboxedBundleAuthor,
};
use codec::{Decode, Encode};
use frame_support::{ensure, PalletError};
use scale_info::TypeInfo;
use sp_core::Get;
use sp_domains::merkle_tree::MerkleTree;
use sp_domains::{DomainId, ExecutionReceipt, OperatorId};
use sp_runtime::traits::{BlockNumberProvider, CheckedSub, One, Saturating, Zero};
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
    BadGenesisReceipt,
    UnexpectedReceiptType,
    MaxHeadDomainNumber,
    MultipleERsAfterChallengePeriod,
    MissingDomainBlock,
    InvalidTraceRoot,
    UnavailableConsensusBlockHash,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct BlockTreeNode<Number, Hash, DomainNumber, DomainHash, Balance> {
    /// The full ER for this block.
    pub execution_receipt: ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance>,
    /// A set of all operators who have committed to this ER within a bundle. Used to determine who to
    /// slash if a fraudulent branch of the `block_tree` is pruned.
    ///
    /// NOTE: there may be duplicated operator id as an operator can submit multiple bundles with the
    /// same head receipt to a consensus block.
    pub operator_ids: Vec<OperatorId>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AcceptedReceiptType {
    // New head receipt that extend the longest branch
    NewHead,
    // Receipt that creates a new branch of the block tree
    NewBranch,
    // Receipt that comfirms the current head receipt
    CurrentHead,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RejectedReceiptType {
    // Receipt that is newer than the head receipt but does not extend the head receipt
    InFuture,
    // Receipt that already been pruned
    Pruned,
}

impl From<RejectedReceiptType> for Error {
    fn from(rejected_receipt: RejectedReceiptType) -> Error {
        match rejected_receipt {
            RejectedReceiptType::InFuture => Error::InFutureReceipt,
            RejectedReceiptType::Pruned => Error::PrunedReceipt,
        }
    }
}

/// The type of receipt regarding to its freshness
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReceiptType {
    Accepted(AcceptedReceiptType),
    Rejected(RejectedReceiptType),
    // Receipt that comfirm a non-head receipt
    Stale,
}

/// Get the receipt type of the given receipt based on the current block tree state
pub(crate) fn execution_receipt_type<T: Config>(
    domain_id: DomainId,
    execution_receipt: &ExecutionReceiptOf<T>,
) -> ReceiptType {
    let receipt_number = execution_receipt.domain_block_number;
    let head_receipt_number = HeadReceiptNumber::<T>::get(domain_id);

    match receipt_number.cmp(&head_receipt_number.saturating_add(One::one())) {
        Ordering::Greater => ReceiptType::Rejected(RejectedReceiptType::InFuture),
        Ordering::Equal => ReceiptType::Accepted(AcceptedReceiptType::NewHead),
        Ordering::Less => {
            let oldest_receipt_number =
                head_receipt_number.saturating_sub(T::BlockTreePruningDepth::get());
            let already_exist =
                BlockTree::<T>::get(domain_id, receipt_number).contains(&execution_receipt.hash());

            if receipt_number < oldest_receipt_number {
                // Receipt already pruned
                ReceiptType::Rejected(RejectedReceiptType::Pruned)
            } else if !already_exist {
                // Create new branch
                ReceiptType::Accepted(AcceptedReceiptType::NewBranch)
            } else if receipt_number == head_receipt_number {
                // Add comfirm to the current head receipt
                ReceiptType::Accepted(AcceptedReceiptType::CurrentHead)
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
        inboxed_bundles,
        parent_domain_block_receipt_hash,
        execution_trace,
        execution_trace_root,
        ..
    } = execution_receipt;

    if domain_block_number.is_zero() {
        // The genesis receipt is generated and added to the block tree by the runtime upon domain
        // instantiation, thus it is unchallengeable and must always be the same.
        ensure!(
            BlockTree::<T>::get(domain_id, domain_block_number).contains(&execution_receipt.hash()),
            Error::BadGenesisReceipt
        );
    } else {
        let bundles_extrinsics_roots: Vec<_> =
            inboxed_bundles.iter().map(|b| b.extrinsics_root).collect();
        let execution_inbox =
            ExecutionInbox::<T>::get((domain_id, domain_block_number, consensus_block_number));
        let expected_extrinsics_roots: Vec<_> =
            execution_inbox.iter().map(|b| b.extrinsics_root).collect();
        ensure!(
            !bundles_extrinsics_roots.is_empty()
                && bundles_extrinsics_roots == expected_extrinsics_roots,
            Error::InvalidExtrinsicsRoots
        );

        let mut trace = Vec::with_capacity(execution_trace.len());
        for root in execution_trace {
            trace.push(
                root.encode()
                    .try_into()
                    .map_err(|_| Error::InvalidTraceRoot)?,
            );
        }
        let expected_execution_trace_root: sp_core::H256 =
            MerkleTree::from_leaves(trace.as_slice())
                .root()
                .ok_or(Error::InvalidTraceRoot)?
                .into();
        ensure!(
            expected_execution_trace_root == *execution_trace_root,
            Error::InvalidTraceRoot
        );

        let excepted_consensus_block_hash =
            match ConsensusBlockHash::<T>::get(domain_id, consensus_block_number) {
                Some(hash) => hash,
                // The `initialize_block` of non-system pallets is skipped in the `validate_transaction`,
                // thus the hash of best block, which is recorded in the this pallet's `on_initialize` hook,
                // is unavailable at this point.
                None => {
                    let parent_block_number =
                        frame_system::Pallet::<T>::current_block_number() - One::one();
                    if *consensus_block_number == parent_block_number {
                        frame_system::Pallet::<T>::parent_hash()
                    } else {
                        return Err(Error::UnavailableConsensusBlockHash);
                    }
                }
            };
        ensure!(
            *consensus_block_hash == excepted_consensus_block_hash,
            Error::BuiltOnUnknownConsensusBlock
        );
    }

    if let Some(parent_block_number) = domain_block_number.checked_sub(&One::one()) {
        let parent_block_exist = BlockTree::<T>::get(domain_id, parent_block_number)
            .contains(parent_domain_block_receipt_hash);
        ensure!(parent_block_exist, Error::UnknownParentBlockReceipt);
    }

    match execution_receipt_type::<T>(domain_id, execution_receipt) {
        ReceiptType::Rejected(RejectedReceiptType::InFuture) => {
            log::error!(
                target: "runtime::domains",
                "Unexpected in future receipt {execution_receipt:?}, which should result in \
                `UnknownParentBlockReceipt` error as it parent receipt is missing"
            );
            Err(Error::InFutureReceipt)
        }
        ReceiptType::Rejected(RejectedReceiptType::Pruned) => {
            log::error!(
                target: "runtime::domains",
                "Unexpected pruned receipt {execution_receipt:?}, which should result in \
                `InvalidExtrinsicsRoots` error as its `ExecutionInbox` is pruned at the same time"
            );
            Err(Error::PrunedReceipt)
        }
        ReceiptType::Accepted(_) | ReceiptType::Stale => Ok(()),
    }
}

/// Details of the confirmed domain block such as operators, rewards they would receive.
#[derive(Debug, PartialEq)]
pub(crate) struct ConfirmedDomainBlockInfo<DomainNumber, Balance> {
    pub domain_block_number: DomainNumber,
    pub operator_ids: Vec<OperatorId>,
    pub rewards: Balance,
    pub invalid_bundle_authors: Vec<OperatorId>,
}

pub(crate) type ProcessExecutionReceiptResult<T> =
    Result<Option<ConfirmedDomainBlockInfo<DomainBlockNumberFor<T>, BalanceOf<T>>>, Error>;

/// Process the execution receipt to add it to the block tree
/// Returns the domain block number that was pruned, if any
pub(crate) fn process_execution_receipt<T: Config>(
    domain_id: DomainId,
    submitter: OperatorId,
    execution_receipt: ExecutionReceiptOf<T>,
    receipt_type: AcceptedReceiptType,
) -> ProcessExecutionReceiptResult<T> {
    match receipt_type {
        AcceptedReceiptType::NewBranch => {
            add_new_receipt_to_block_tree::<T>(domain_id, submitter, execution_receipt);
        }
        AcceptedReceiptType::NewHead => {
            let domain_block_number = execution_receipt.domain_block_number;

            add_new_receipt_to_block_tree::<T>(domain_id, submitter, execution_receipt);

            // Update the head receipt number
            HeadReceiptNumber::<T>::insert(domain_id, domain_block_number);

            // Prune expired domain block
            if let Some(to_prune) =
                domain_block_number.checked_sub(&T::BlockTreePruningDepth::get())
            {
                let receipts_at_number = BlockTree::<T>::take(domain_id, to_prune);

                // The receipt at `to_prune` may already been pruned if there is fraud proof being
                // processed and the `HeadReceiptNumber` is reverted.
                if receipts_at_number.is_empty() {
                    return Ok(None);
                }

                // FIXME: the following check is wrong because the ER at `to_prune` may not necessarily go through
                // the whole challenge period since the malicious operator can submit `NewBranch` ER any time, thus
                // the ER may just submitted a few blocks ago and `receipts_at_number` may contains more than one block.
                //
                // In current implementatiomn, the correct finalized ER should be the one that has `BlockTreePruningDepth`
                // length of descendants which is non-trival to find, but once https://github.com/subspace/subspace/issues/1731
                // is implemented this issue should be fixed automatically.
                if receipts_at_number.len() != 1 {
                    return Err(Error::MultipleERsAfterChallengePeriod);
                }

                let receipt_hash = receipts_at_number
                    .first()
                    .cloned()
                    .expect("should always have a value due to check above");

                let BlockTreeNode {
                    execution_receipt,
                    operator_ids,
                } = BlockTreeNodes::<T>::take(receipt_hash).ok_or(Error::MissingDomainBlock)?;

                _ = StateRoots::<T>::take((
                    domain_id,
                    to_prune,
                    execution_receipt.domain_block_hash,
                ));
                _ = DomainBlockDescendants::<T>::take(receipt_hash);

                // Collect the invalid bundle author
                let mut invalid_bundle_authors = Vec::new();
                let bundle_digests = ExecutionInbox::<T>::get((
                    domain_id,
                    to_prune,
                    execution_receipt.consensus_block_number,
                ));
                for (index, bd) in bundle_digests.into_iter().enumerate() {
                    if let Some(bundle_author) = InboxedBundleAuthor::<T>::take(bd.header_hash) {
                        // It is okay to index `ER::bundles` here since `verify_execution_receipt` have checked
                        // the `ER::bundles` have the same length of `ExecutionInbox`
                        if execution_receipt.inboxed_bundles[index].is_invalid() {
                            invalid_bundle_authors.push(bundle_author);
                        }
                    }
                }

                // Remove the block's `ExecutionInbox` as the domain block is confirmed and no need to verify
                // its receipt's `extrinsics_root` anymore.
                let _ = ExecutionInbox::<T>::clear_prefix((domain_id, to_prune), u32::MAX, None);

                ConsensusBlockHash::<T>::remove(
                    domain_id,
                    execution_receipt.consensus_block_number,
                );

                return Ok(Some(ConfirmedDomainBlockInfo {
                    domain_block_number: to_prune,
                    operator_ids,
                    rewards: execution_receipt.total_rewards,
                    invalid_bundle_authors,
                }));
            }
        }
        AcceptedReceiptType::CurrentHead => {
            // Add confirmation to the current head receipt
            let er_hash = execution_receipt.hash();
            BlockTreeNodes::<T>::mutate(er_hash, |maybe_node| {
                let node = maybe_node.as_mut().expect(
                    "The domain block of `CurrentHead` receipt is checked to be exist in `execution_receipt_type`; qed"
                );
                node.operator_ids.push(submitter);
            });
        }
    }
    Ok(None)
}

fn add_new_receipt_to_block_tree<T: Config>(
    domain_id: DomainId,
    submitter: OperatorId,
    execution_receipt: ExecutionReceiptOf<T>,
) {
    // Construct and add a new domain block to the block tree
    let er_hash = execution_receipt.hash();
    let domain_block_number = execution_receipt.domain_block_number;
    StateRoots::<T>::insert(
        (
            domain_id,
            domain_block_number,
            execution_receipt.domain_block_hash,
        ),
        execution_receipt.final_state_root,
    );

    BlockTree::<T>::mutate(domain_id, domain_block_number, |er_hashes| {
        er_hashes.insert(er_hash);
    });
    DomainBlockDescendants::<T>::mutate(
        execution_receipt.parent_domain_block_receipt_hash,
        |er_hashes| {
            er_hashes.insert(er_hash);
        },
    );
    let block_tree_node = BlockTreeNode {
        execution_receipt,
        operator_ids: sp_std::vec![submitter],
    };
    BlockTreeNodes::<T>::insert(er_hash, block_tree_node);
}

/// Import the genesis receipt to the block tree
pub(crate) fn import_genesis_receipt<T: Config>(
    domain_id: DomainId,
    genesis_receipt: ExecutionReceiptOf<T>,
) {
    let er_hash = genesis_receipt.hash();
    let domain_block_number = genesis_receipt.domain_block_number;
    let block_tree_node = BlockTreeNode {
        execution_receipt: genesis_receipt,
        operator_ids: sp_std::vec![],
    };
    // NOTE: no need to update the head receipt number as we are using `ValueQuery`
    BlockTree::<T>::mutate(domain_id, domain_block_number, |er_hashes| {
        er_hashes.insert(er_hash);
    });
    StateRoots::<T>::insert(
        (
            domain_id,
            domain_block_number,
            block_tree_node.execution_receipt.domain_block_hash,
        ),
        block_tree_node.execution_receipt.final_state_root,
    );
    BlockTreeNodes::<T>::insert(er_hash, block_tree_node);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{
        create_dummy_bundle_with_receipts, create_dummy_receipt, extend_block_tree,
        get_block_tree_node_at, new_test_ext_with_extensions, register_genesis_domain,
        run_to_block, BlockTreePruningDepth, Test,
    };
    use frame_support::dispatch::RawOrigin;
    use frame_support::{assert_err, assert_ok};
    use sp_core::H256;
    use sp_domains::{BundleDigest, InboxedBundle, InvalidBundleType};
    use sp_runtime::traits::BlockNumberProvider;

    #[test]
    fn test_genesis_receipt() {
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(0u64, vec![0u64]);

            // The genesis receipt should be added to the block tree
            let block_tree_node_at_0 = BlockTree::<Test>::get(domain_id, 0);
            assert_eq!(block_tree_node_at_0.len(), 1);

            let genesis_node =
                BlockTreeNodes::<Test>::get(block_tree_node_at_0.first().unwrap()).unwrap();
            assert!(genesis_node.operator_ids.is_empty());
            assert_eq!(HeadReceiptNumber::<Test>::get(domain_id), 0);

            // The genesis receipt should be able pass the verification and is unchallengeable
            let genesis_receipt = genesis_node.execution_receipt;
            let invalid_genesis_receipt = {
                let mut receipt = genesis_receipt.clone();
                receipt.final_state_root = H256::random();
                receipt
            };
            assert_ok!(verify_execution_receipt::<Test>(
                domain_id,
                &genesis_receipt
            ));
            assert_err!(
                verify_execution_receipt::<Test>(domain_id, &invalid_genesis_receipt),
                Error::BadGenesisReceipt
            );
        });
    }

    #[test]
    fn test_new_head_receipt() {
        let creator = 0u64;
        let operator_id = 1u64;
        let block_tree_pruning_depth = <Test as Config>::BlockTreePruningDepth::get();

        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, vec![operator_id]);

            // The genesis node of the block tree
            let genesis_node = get_block_tree_node_at::<Test>(domain_id, 0).unwrap();
            let mut receipt = genesis_node.execution_receipt;
            assert_eq!(
                receipt.consensus_block_number,
                frame_system::Pallet::<Test>::current_block_number()
            );
            let mut receipt_of_block_1 = None;
            let mut bundle_header_hash_of_block_1 = None;
            for block_number in 1..=(block_tree_pruning_depth as u64 + 3) {
                // Finilize parent block and initialize block at `block_number`
                run_to_block::<Test>(block_number, receipt.consensus_block_hash);

                if block_number != 1 {
                    // `ConsensusBlockHash` should be set to `Some` since last consensus block contains bundle
                    assert_eq!(
                        ConsensusBlockHash::<Test>::get(domain_id, block_number - 1),
                        Some(frame_system::Pallet::<Test>::block_hash(block_number - 1))
                    );
                    // ER point to last consensus block should have `NewHead` type
                    assert_eq!(
                        execution_receipt_type::<Test>(domain_id, &receipt),
                        ReceiptType::Accepted(AcceptedReceiptType::NewHead)
                    );
                    assert_ok!(verify_execution_receipt::<Test>(domain_id, &receipt));
                }

                // Submit a bundle with the receipt of the last block
                let bundle_extrinsics_root = H256::random();
                let bundle = create_dummy_bundle_with_receipts(
                    domain_id,
                    operator_id,
                    bundle_extrinsics_root,
                    receipt,
                );
                let bundle_header_hash = bundle.sealed_header.pre_hash();
                assert_ok!(crate::Pallet::<Test>::submit_bundle(
                    RawOrigin::None.into(),
                    bundle,
                ));
                // `bundle_extrinsics_root` should be tracked in `ExecutionInbox`
                assert_eq!(
                    ExecutionInbox::<Test>::get((domain_id, block_number as u32, block_number)),
                    vec![BundleDigest {
                        header_hash: bundle_header_hash,
                        extrinsics_root: bundle_extrinsics_root,
                    }]
                );
                assert!(InboxedBundleAuthor::<Test>::contains_key(
                    bundle_header_hash
                ));

                // Head receipt number should be updated
                let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);
                assert_eq!(head_receipt_number, block_number as u32 - 1);

                // As we only extending the block tree there should be no fork
                let parent_block_tree_nodes =
                    BlockTree::<Test>::get(domain_id, head_receipt_number);
                assert_eq!(parent_block_tree_nodes.len(), 1);

                // The submitter should be added to `operator_ids`
                let parent_domain_block_receipt = parent_block_tree_nodes.first().unwrap();
                let parent_node = BlockTreeNodes::<Test>::get(parent_domain_block_receipt).unwrap();
                assert_eq!(parent_node.operator_ids.len(), 1);
                assert_eq!(parent_node.operator_ids[0], operator_id);

                // Construct a `NewHead` receipt of the just submitted bundle, which will be included
                // in the next bundle
                receipt = create_dummy_receipt(
                    block_number,
                    H256::random(),
                    *parent_domain_block_receipt,
                    vec![bundle_extrinsics_root],
                );

                // Record receipt of block #1 for later use
                if block_number == 1 {
                    receipt_of_block_1.replace(receipt.clone());
                    bundle_header_hash_of_block_1.replace(bundle_header_hash);
                }
            }

            // The receipt of the block 1 is pruned at the last iteration, verify it will result in
            // `InvalidExtrinsicsRoots` error as `ExecutionInbox` of block 1 is pruned
            let pruned_receipt = receipt_of_block_1.unwrap();
            let pruned_bundle = bundle_header_hash_of_block_1.unwrap();
            assert!(BlockTree::<Test>::get(domain_id, 1).is_empty());
            assert!(ExecutionInbox::<Test>::get((domain_id, 1, 1)).is_empty());
            assert!(!InboxedBundleAuthor::<Test>::contains_key(pruned_bundle));
            assert_eq!(
                execution_receipt_type::<Test>(domain_id, &pruned_receipt),
                ReceiptType::Rejected(RejectedReceiptType::Pruned)
            );
            assert_err!(
                verify_execution_receipt::<Test>(domain_id, &pruned_receipt),
                Error::InvalidExtrinsicsRoots
            );
            assert!(ConsensusBlockHash::<Test>::get(
                domain_id,
                pruned_receipt.consensus_block_number,
            )
            .is_none());
            assert!(DomainBlockDescendants::<Test>::get(pruned_receipt.hash()).is_empty());
        });
    }

    #[test]
    fn test_confirm_head_receipt() {
        let creator = 0u64;
        let operator_id1 = 1u64;
        let operator_id2 = 2u64;
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, vec![operator_id1, operator_id2]);
            extend_block_tree(domain_id, operator_id1, 3);

            let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);

            // Get the head receipt
            let current_head_receipt =
                get_block_tree_node_at::<Test>(domain_id, head_receipt_number)
                    .unwrap()
                    .execution_receipt;

            // Receipt should be valid
            assert_eq!(
                execution_receipt_type::<Test>(domain_id, &current_head_receipt),
                ReceiptType::Accepted(AcceptedReceiptType::CurrentHead)
            );
            assert_ok!(verify_execution_receipt::<Test>(
                domain_id,
                &current_head_receipt
            ));

            // Re-submit the receipt will add confirm to the head receipt
            let bundle = create_dummy_bundle_with_receipts(
                domain_id,
                operator_id2,
                H256::random(),
                current_head_receipt,
            );
            assert_ok!(crate::Pallet::<Test>::submit_bundle(
                RawOrigin::None.into(),
                bundle,
            ));
            let head_node = get_block_tree_node_at::<Test>(domain_id, head_receipt_number).unwrap();
            assert_eq!(head_node.operator_ids, vec![operator_id1, operator_id2]);
        });
    }

    #[test]
    fn test_stale_receipt() {
        let creator = 0u64;
        let operator_id1 = 1u64;
        let operator_id2 = 2u64;
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, vec![operator_id1, operator_id2]);
            extend_block_tree(domain_id, operator_id1, 3);

            // Receipt that comfirm a non-head receipt is stale receipt
            let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);
            let stale_receipt = get_block_tree_node_at::<Test>(domain_id, head_receipt_number - 1)
                .unwrap()
                .execution_receipt;
            let stale_receipt_hash = stale_receipt.hash();

            // Stale receipt can pass the verification
            assert_eq!(
                execution_receipt_type::<Test>(domain_id, &stale_receipt),
                ReceiptType::Stale
            );
            assert_ok!(verify_execution_receipt::<Test>(domain_id, &stale_receipt));

            // Stale receipt can be submitted but won't be added to the block tree
            let bundle = create_dummy_bundle_with_receipts(
                domain_id,
                operator_id2,
                H256::random(),
                stale_receipt,
            );
            assert_ok!(crate::Pallet::<Test>::submit_bundle(
                RawOrigin::None.into(),
                bundle,
            ));

            assert_eq!(
                BlockTreeNodes::<Test>::get(stale_receipt_hash)
                    .unwrap()
                    .operator_ids,
                vec![operator_id1]
            );
        });
    }

    #[test]
    fn test_new_branch_receipt() {
        let creator = 0u64;
        let operator_id1 = 1u64;
        let operator_id2 = 2u64;
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, vec![operator_id1, operator_id2]);
            extend_block_tree(domain_id, operator_id1, 3);

            let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);
            assert_eq!(
                BlockTree::<Test>::get(domain_id, head_receipt_number).len(),
                1
            );

            // Construct new branch receipt that fork away from an existing node of
            // the block tree
            let new_branch_receipt = {
                let mut head_receipt =
                    get_block_tree_node_at::<Test>(domain_id, head_receipt_number)
                        .unwrap()
                        .execution_receipt;
                head_receipt.final_state_root = H256::random();
                head_receipt
            };
            let new_branch_receipt_hash = new_branch_receipt.hash();

            // New branch receipt can pass the verification
            assert_eq!(
                execution_receipt_type::<Test>(domain_id, &new_branch_receipt),
                ReceiptType::Accepted(AcceptedReceiptType::NewBranch)
            );
            assert_ok!(verify_execution_receipt::<Test>(
                domain_id,
                &new_branch_receipt
            ));

            // Submit the new branch receipt will create fork in the block tree
            let bundle = create_dummy_bundle_with_receipts(
                domain_id,
                operator_id2,
                H256::random(),
                new_branch_receipt,
            );
            assert_ok!(crate::Pallet::<Test>::submit_bundle(
                RawOrigin::None.into(),
                bundle,
            ));

            let nodes = BlockTree::<Test>::get(domain_id, head_receipt_number);
            assert_eq!(nodes.len(), 2);
            for n in nodes.iter() {
                let node = BlockTreeNodes::<Test>::get(n).unwrap();
                if *n == new_branch_receipt_hash {
                    assert_eq!(node.operator_ids, vec![operator_id2]);
                } else {
                    assert_eq!(node.operator_ids, vec![operator_id1]);
                }
            }
        });
    }

    #[test]
    fn test_invalid_receipt() {
        let creator = 0u64;
        let operator_id = 1u64;
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, vec![operator_id]);
            extend_block_tree(domain_id, operator_id, 3);

            let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);
            let current_head_receipt =
                get_block_tree_node_at::<Test>(domain_id, head_receipt_number)
                    .unwrap()
                    .execution_receipt;

            // Construct a future receipt
            let mut future_receipt = current_head_receipt.clone();
            future_receipt.domain_block_number = head_receipt_number + 2;
            future_receipt.consensus_block_number = head_receipt_number as u64 + 2;
            ExecutionInbox::<Test>::insert(
                (
                    domain_id,
                    future_receipt.domain_block_number,
                    future_receipt.consensus_block_number,
                ),
                future_receipt
                    .inboxed_bundles
                    .clone()
                    .into_iter()
                    .map(|b| BundleDigest {
                        header_hash: H256::random(),
                        extrinsics_root: b.extrinsics_root,
                    })
                    .collect::<Vec<_>>(),
            );
            assert_eq!(
                execution_receipt_type::<Test>(domain_id, &future_receipt),
                ReceiptType::Rejected(RejectedReceiptType::InFuture)
            );

            // Return `UnavailableConsensusBlockHash` error since ER point to a future consensus block
            assert_err!(
                verify_execution_receipt::<Test>(domain_id, &future_receipt),
                Error::UnavailableConsensusBlockHash
            );
            ConsensusBlockHash::<Test>::insert(
                domain_id,
                future_receipt.consensus_block_number,
                future_receipt.consensus_block_hash,
            );

            // Return `UnknownParentBlockReceipt` error as its parent receipt is missing from the block tree
            assert_err!(
                verify_execution_receipt::<Test>(domain_id, &future_receipt),
                Error::UnknownParentBlockReceipt
            );

            // Receipt with unknown extrinsics roots
            let mut unknown_extrinsics_roots_receipt = current_head_receipt.clone();
            unknown_extrinsics_roots_receipt.inboxed_bundles =
                vec![InboxedBundle::valid(H256::random(), H256::random())];
            assert_err!(
                verify_execution_receipt::<Test>(domain_id, &unknown_extrinsics_roots_receipt),
                Error::InvalidExtrinsicsRoots
            );

            // Receipt with unknown consensus block hash
            let mut unknown_consensus_block_receipt = current_head_receipt.clone();
            unknown_consensus_block_receipt.consensus_block_hash = H256::random();
            assert_err!(
                verify_execution_receipt::<Test>(domain_id, &unknown_consensus_block_receipt),
                Error::BuiltOnUnknownConsensusBlock
            );

            // Receipt with unknown parent receipt
            let mut unknown_parent_receipt = current_head_receipt;
            unknown_parent_receipt.parent_domain_block_receipt_hash = H256::random();
            assert_err!(
                verify_execution_receipt::<Test>(domain_id, &unknown_parent_receipt),
                Error::UnknownParentBlockReceipt
            );
        });
    }

    #[test]
    fn test_invalid_trace_root_receipt() {
        let creator = 0u64;
        let operator_id1 = 1u64;
        let operator_id2 = 2u64;
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, vec![operator_id1, operator_id2]);
            extend_block_tree(domain_id, operator_id1, 3);

            let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);

            // Get the head receipt
            let current_head_receipt =
                get_block_tree_node_at::<Test>(domain_id, head_receipt_number)
                    .unwrap()
                    .execution_receipt;

            // Receipt with wrong value of `execution_trace_root`
            let mut invalid_receipt = current_head_receipt.clone();
            invalid_receipt.execution_trace_root = H256::random();
            assert_err!(
                verify_execution_receipt::<Test>(domain_id, &invalid_receipt),
                Error::InvalidTraceRoot
            );

            // Receipt with wrong value of trace
            let mut invalid_receipt = current_head_receipt.clone();
            invalid_receipt.execution_trace[0] = H256::random();
            assert_err!(
                verify_execution_receipt::<Test>(domain_id, &invalid_receipt),
                Error::InvalidTraceRoot
            );

            // Receipt with addtional trace
            let mut invalid_receipt = current_head_receipt.clone();
            invalid_receipt.execution_trace.push(H256::random());
            assert_err!(
                verify_execution_receipt::<Test>(domain_id, &invalid_receipt),
                Error::InvalidTraceRoot
            );

            // Receipt with missing trace
            let mut invalid_receipt = current_head_receipt;
            invalid_receipt.execution_trace.pop();
            assert_err!(
                verify_execution_receipt::<Test>(domain_id, &invalid_receipt),
                Error::InvalidTraceRoot
            );
        });
    }

    #[test]
    fn test_collect_invalid_bundle_author() {
        let creator = 0u64;
        let challenge_period = BlockTreePruningDepth::get() as u64;
        let operator_set: Vec<_> = (1..15).collect();
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, operator_set.clone());
            let mut target_receipt = extend_block_tree(domain_id, operator_set[0], 3);

            // Submit bundle for every operator except operator 1 since it already submit one
            let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);
            let current_head_receipt =
                get_block_tree_node_at::<Test>(domain_id, head_receipt_number)
                    .unwrap()
                    .execution_receipt;
            for operator_id in operator_set.iter().skip(1) {
                let bundle = create_dummy_bundle_with_receipts(
                    domain_id,
                    *operator_id,
                    H256::random(),
                    current_head_receipt.clone(),
                );
                assert_ok!(crate::Pallet::<Test>::submit_bundle(
                    RawOrigin::None.into(),
                    bundle,
                ));
            }
            let head_node = get_block_tree_node_at::<Test>(domain_id, head_receipt_number).unwrap();
            assert_eq!(head_node.operator_ids, operator_set);

            // Get the `bundles_extrinsics_roots` that contains all the submitted bundles
            let current_block_number = frame_system::Pallet::<Test>::current_block_number();
            let execution_inbox = ExecutionInbox::<Test>::get((
                domain_id,
                current_block_number as u32,
                current_block_number,
            ));
            let bundles_extrinsics_roots: Vec<_> = execution_inbox
                .into_iter()
                .map(|b| b.extrinsics_root)
                .collect();
            assert_eq!(bundles_extrinsics_roots.len(), operator_set.len());

            // Prepare the invalid bundles and invalid bundle authors
            let mut bundles = vec![];
            let mut invalid_bundle_authors = vec![];
            for (i, (operator, extrinsics_root)) in operator_set
                .iter()
                .zip(bundles_extrinsics_roots)
                .enumerate()
            {
                if i % 2 == 0 {
                    invalid_bundle_authors.push(*operator);
                    bundles.push(InboxedBundle::invalid(
                        InvalidBundleType::OutOfRangeTx(0),
                        extrinsics_root,
                    ));
                } else {
                    bundles.push(InboxedBundle::valid(H256::random(), extrinsics_root));
                }
            }
            target_receipt.inboxed_bundles = bundles;

            // Run into next block
            run_to_block::<Test>(
                current_block_number + 1,
                target_receipt.consensus_block_hash,
            );
            let current_block_number = current_block_number + 1;

            // Submit `target_receipt`
            assert_ok!(crate::Pallet::<Test>::submit_bundle(
                RawOrigin::None.into(),
                create_dummy_bundle_with_receipts(
                    domain_id,
                    operator_set[0],
                    H256::random(),
                    target_receipt,
                ),
            ));

            // Extend the block tree by `challenge_period - 1` blocks
            let next_receipt = extend_block_tree(
                domain_id,
                operator_set[0],
                (current_block_number + challenge_period) as u32 - 1,
            );
            // Confirm `target_receipt`
            let confirmed_domain_block = process_execution_receipt::<Test>(
                domain_id,
                operator_set[0],
                next_receipt,
                AcceptedReceiptType::NewHead,
            )
            .unwrap()
            .unwrap();

            // Invalid bundle authors should be collected correctly
            assert_eq!(
                confirmed_domain_block.invalid_bundle_authors,
                invalid_bundle_authors
            );
        });
    }
}
