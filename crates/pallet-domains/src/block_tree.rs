//! Domain block tree

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::{
    BalanceOf, BlockTree, BlockTreeNodeFor, BlockTreeNodes, Config, ConsensusBlockHash,
    DomainBlockNumberFor, DomainGenesisBlockExecutionReceipt, DomainHashingFor,
    DomainRuntimeUpgradeRecords, ExecutionInbox, ExecutionReceiptOf, ExecutionReceiptRefOf,
    HeadDomainNumber, HeadReceiptNumber, InboxedBundleAuthor,
    LatestConfirmedDomainExecutionReceipt, LatestSubmittedER, NewAddedHeadReceipt, Pallet,
    ReceiptHashFor,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use frame_support::{PalletError, ensure};
use frame_system::pallet_prelude::BlockNumberFor;
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode};
use scale_info::TypeInfo;
use sp_core::Get;
use sp_domains::execution_receipt::execution_receipt_v0::ExecutionReceiptV0;
use sp_domains::execution_receipt::{ExecutionReceipt, ExecutionReceiptRef, Transfers};
use sp_domains::merkle_tree::MerkleTree;
use sp_domains::{ChainId, DomainId, DomainsTransfersTracker, OnChainRewards, OperatorId};
use sp_runtime::traits::{BlockNumberProvider, CheckedSub, One, Saturating, Zero};
use sp_std::cmp::Ordering;
use sp_std::collections::btree_map::BTreeMap;

/// Block tree specific errors
#[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq, DecodeWithMemTracking)]
pub enum Error {
    InvalidExtrinsicsRoots,
    UnknownParentBlockReceipt,
    BuiltOnUnknownConsensusBlock,
    InFutureReceipt,
    PrunedReceipt,
    StaleReceipt,
    NewBranchReceipt,
    BadGenesisReceipt,
    UnexpectedReceiptType,
    MaxHeadDomainNumber,
    MissingDomainBlock,
    InvalidTraceRoot,
    InvalidExecutionTrace,
    UnavailableConsensusBlockHash,
    InvalidStateRoot,
    BalanceOverflow,
    DomainTransfersTracking,
    InvalidDomainTransfers,
    OverwritingER,
    RuntimeNotFound,
    LastBlockNotFound,
    UnmatchedNewHeadReceipt,
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
    // Receipt that confirms the head receipt that added in the current block
    CurrentHead,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RejectedReceiptType {
    // Receipt that is newer than the head receipt but does not extend the head receipt
    InFuture,
    // Receipt that already been pruned
    Pruned,
    // Receipt that confirm a non-head receipt or head receipt of the previous block
    Stale,
    // Receipt that tries to create a new branch of the block tree
    //
    // The honests operator must submit fraud proof to prune the bad receipt at the
    // same height before submitting the valid receipt.
    NewBranch,
}

impl From<RejectedReceiptType> for Error {
    fn from(rejected_receipt: RejectedReceiptType) -> Error {
        match rejected_receipt {
            RejectedReceiptType::InFuture => Error::InFutureReceipt,
            RejectedReceiptType::Pruned => Error::PrunedReceipt,
            RejectedReceiptType::Stale => Error::StaleReceipt,
            RejectedReceiptType::NewBranch => Error::NewBranchReceipt,
        }
    }
}

/// The type of receipt regarding to its freshness
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReceiptType {
    Accepted(AcceptedReceiptType),
    Rejected(RejectedReceiptType),
}

pub(crate) fn does_receipt_exists<T: Config>(
    domain_id: DomainId,
    domain_number: DomainBlockNumberFor<T>,
    receipt_hash: ReceiptHashFor<T>,
) -> bool {
    BlockTree::<T>::get(domain_id, domain_number)
        .map(|h| h == receipt_hash)
        .unwrap_or(false)
}

/// Get the receipt type of the given receipt based on the current block tree state
pub(crate) fn execution_receipt_type<T: Config>(
    domain_id: DomainId,
    execution_receipt: &ExecutionReceiptRefOf<T>,
) -> ReceiptType {
    let ExecutionReceiptRef::V0(ExecutionReceiptV0 {
        domain_block_number,
        ..
    }) = execution_receipt;
    let receipt_number = *domain_block_number;
    let head_receipt_number = HeadReceiptNumber::<T>::get(domain_id);
    let head_receipt_extended = NewAddedHeadReceipt::<T>::get(domain_id).is_some();
    let next_receipt_number = head_receipt_number.saturating_add(One::one());
    let latest_confirmed_domain_block_number =
        Pallet::<T>::latest_confirmed_domain_block_number(domain_id);

    match receipt_number.cmp(&next_receipt_number) {
        Ordering::Greater => ReceiptType::Rejected(RejectedReceiptType::InFuture),
        Ordering::Equal => {
            // we do not allow consecutive ER in a single consensus block
            // if the head receipt is already extended, then reject this ER
            // as it is a Future ER
            if head_receipt_extended {
                ReceiptType::Rejected(RejectedReceiptType::InFuture)
            } else {
                ReceiptType::Accepted(AcceptedReceiptType::NewHead)
            }
        }
        Ordering::Less => {
            // Reject receipt that already confirmed
            if !latest_confirmed_domain_block_number.is_zero()
                && receipt_number <= latest_confirmed_domain_block_number
            {
                return ReceiptType::Rejected(RejectedReceiptType::Pruned);
            }

            // Reject receipt that try to create new branch in the block tree
            let already_exist = does_receipt_exists::<T>(
                domain_id,
                receipt_number,
                execution_receipt.hash::<DomainHashingFor<T>>(),
            );
            if !already_exist {
                return ReceiptType::Rejected(RejectedReceiptType::NewBranch);
            }

            // Add confirm to the head receipt that added in the current block or it is
            // the first genesis receipt
            let is_first_genesis_receipt =
                receipt_number.is_zero() && HeadDomainNumber::<T>::get(domain_id).is_zero();
            if receipt_number == head_receipt_number
                && (head_receipt_extended || is_first_genesis_receipt)
            {
                return ReceiptType::Accepted(AcceptedReceiptType::CurrentHead);
            }

            // Add confirm to a non-head receipt or head receipt of the previous block
            ReceiptType::Rejected(RejectedReceiptType::Stale)
        }
    }
}

/// Verify the execution receipt
pub(crate) fn verify_execution_receipt<T: Config>(
    domain_id: DomainId,
    execution_receipt: &ExecutionReceiptRefOf<T>,
) -> Result<(), Error> {
    let ExecutionReceiptRef::V0(ExecutionReceiptV0 {
        consensus_block_number,
        consensus_block_hash,
        domain_block_number,
        inboxed_bundles,
        parent_domain_block_receipt_hash,
        execution_trace,
        execution_trace_root,
        final_state_root,
        ..
    }) = execution_receipt;

    // Checking if the incoming ER is expected regarding to its `domain_block_number` or freshness
    if let ReceiptType::Rejected(rejected_receipt_type) =
        execution_receipt_type::<T>(domain_id, execution_receipt)
    {
        return Err(rejected_receipt_type.into());
    }

    // If there is new head receipt added in the current block, as long as the incoming
    // receipt is the same as the new head receipt we can safely skip the following checks,
    // if they are not the same, we just reject the incoming receipt and expecting a fraud
    // proof will be submit if the new head receipt is fraudulent and then the incoming
    // receipt will be re-submit.
    if let Some(new_added_head_receipt) = NewAddedHeadReceipt::<T>::get(domain_id) {
        ensure!(
            new_added_head_receipt == execution_receipt.hash::<DomainHashingFor<T>>(),
            Error::UnmatchedNewHeadReceipt,
        );
        return Ok(());
    }

    // The genesis receipt is generated and added to the block tree by the runtime upon domain
    // instantiation thus it is unchallengeable, we can safely skip other checks as long as we
    // can ensure it is always be the same.
    if domain_block_number.is_zero() {
        ensure!(
            does_receipt_exists::<T>(
                domain_id,
                *domain_block_number,
                execution_receipt.hash::<DomainHashingFor<T>>(),
            ),
            Error::BadGenesisReceipt
        );
        return Ok(());
    }

    // Check if the ER has at least 2 trace root (for Initialization and Finalization of block at least)
    if execution_trace.len() < 2 {
        return Err(Error::InvalidExecutionTrace);
    }

    let maybe_domain_runtime_upgraded_at = {
        let runtime_id = Pallet::<T>::runtime_id(domain_id).ok_or(Error::RuntimeNotFound)?;
        DomainRuntimeUpgradeRecords::<T>::get(runtime_id).remove(consensus_block_number)
    };

    // Check if the ER is derived from the correct consensus block in the current chain
    let excepted_consensus_block_hash =
        match ConsensusBlockHash::<T>::get(domain_id, consensus_block_number) {
            Some(hash) => hash,
            None => {
                // The `initialize_block` of non-system pallets is skipped in the `validate_transaction`,
                // thus the hash of best block, which is recorded in the this pallet's `on_initialize` hook,
                // is unavailable at this point.
                let parent_block_number =
                    frame_system::Pallet::<T>::current_block_number() - One::one();
                if *consensus_block_number == parent_block_number {
                    frame_system::Pallet::<T>::parent_hash()

                // The domain runtime upgrade is forced to happen even if there is no bundle, in this case,
                // the `ConsensusBlockHash` will be empty so we need to get the consensus block hash from
                // `DomainRuntimeUpgradeRecords`
                } else if let Some(ref upgrade_entry) = maybe_domain_runtime_upgraded_at {
                    upgrade_entry.at_hash
                } else {
                    return Err(Error::UnavailableConsensusBlockHash);
                }
            }
        };
    ensure!(
        *consensus_block_hash == excepted_consensus_block_hash,
        Error::BuiltOnUnknownConsensusBlock
    );

    // Check if the ER is derived from the expected inboxed bundles of the consensus block
    let bundles_extrinsics_roots: Vec<_> =
        inboxed_bundles.iter().map(|b| b.extrinsics_root).collect();
    let execution_inbox =
        ExecutionInbox::<T>::get((domain_id, domain_block_number, consensus_block_number));
    let expected_extrinsics_roots: Vec<_> =
        execution_inbox.iter().map(|b| b.extrinsics_root).collect();
    ensure!(
        (!bundles_extrinsics_roots.is_empty() || maybe_domain_runtime_upgraded_at.is_some())
            && bundles_extrinsics_roots == expected_extrinsics_roots,
        Error::InvalidExtrinsicsRoots
    );

    // Check if the `execution_trace_root` is well-format
    let mut trace = Vec::with_capacity(execution_trace.len());
    for root in execution_trace {
        trace.push(
            root.encode()
                .try_into()
                .map_err(|_| Error::InvalidTraceRoot)?,
        );
    }
    let expected_execution_trace_root: sp_core::H256 = MerkleTree::from_leaves(trace.as_slice())
        .root()
        .ok_or(Error::InvalidTraceRoot)?
        .into();
    ensure!(
        expected_execution_trace_root == *execution_trace_root,
        Error::InvalidTraceRoot
    );

    // check state root on ER and in the Execution trace
    if let Some(expected_final_state_root) = execution_trace.last() {
        ensure!(
            final_state_root == expected_final_state_root,
            Error::InvalidStateRoot
        );
    }

    // Check if the ER is extending an existing parent ER
    if let Some(parent_block_number) = domain_block_number.checked_sub(&One::one()) {
        let parent_block_exist = does_receipt_exists::<T>(
            domain_id,
            parent_block_number,
            *parent_domain_block_receipt_hash,
        );
        ensure!(parent_block_exist, Error::UnknownParentBlockReceipt);
    }

    Ok(())
}

/// Details of the confirmed domain block such as operators, rewards they would receive.
#[derive(Debug, PartialEq)]
pub(crate) struct ConfirmedDomainBlockInfo<ConsensusNumber, DomainNumber, Balance> {
    pub consensus_block_number: ConsensusNumber,
    pub domain_block_number: DomainNumber,
    pub operator_ids: Vec<OperatorId>,
    pub rewards: Balance,
    pub invalid_bundle_authors: Vec<OperatorId>,
    pub total_storage_fee: Balance,
    pub paid_bundle_storage_fees: BTreeMap<OperatorId, u32>,
}

pub(crate) type ProcessExecutionReceiptResult<T> = Result<
    Option<ConfirmedDomainBlockInfo<BlockNumberFor<T>, DomainBlockNumberFor<T>, BalanceOf<T>>>,
    Error,
>;

/// Process the execution receipt to add it to the block tree
/// Returns the domain block number that was pruned, if any
pub(crate) fn process_execution_receipt<T: Config>(
    domain_id: DomainId,
    submitter: OperatorId,
    execution_receipt: ExecutionReceiptOf<T>,
    receipt_type: AcceptedReceiptType,
) -> ProcessExecutionReceiptResult<T> {
    let er_hash = execution_receipt.hash::<DomainHashingFor<T>>();
    let receipt_block_number = *execution_receipt.domain_block_number();
    match receipt_type {
        AcceptedReceiptType::NewHead => {
            add_new_receipt_to_block_tree::<T>(domain_id, submitter, execution_receipt)?;

            // Update the head receipt number
            HeadReceiptNumber::<T>::insert(domain_id, receipt_block_number);
            NewAddedHeadReceipt::<T>::insert(domain_id, er_hash);

            // Prune expired domain block
            if let Some(to_prune) =
                receipt_block_number.checked_sub(&T::BlockTreePruningDepth::get())
            {
                let BlockTreeNode {
                    execution_receipt,
                    operator_ids,
                } = match prune_receipt::<T>(domain_id, to_prune)? {
                    Some(n) => n,
                    // The receipt at `to_prune` may already been pruned if there is fraud proof being
                    // processed previously and the `HeadReceiptNumber` is reverted.
                    None => return Ok(None),
                };

                // Collect the paid bundle storage fees and the invalid bundle author
                let mut paid_bundle_storage_fees = BTreeMap::new();
                let mut invalid_bundle_authors = Vec::new();
                let consensus_block_number = *execution_receipt.consensus_block_number();
                let bundle_digests =
                    ExecutionInbox::<T>::get((domain_id, to_prune, consensus_block_number));
                let inboxed_bundles = execution_receipt.inboxed_bundles();
                for (index, bd) in bundle_digests.into_iter().enumerate() {
                    if let Some(bundle_author) = InboxedBundleAuthor::<T>::take(bd.header_hash) {
                        // It is okay to index `ER::bundles` here since `verify_execution_receipt` have checked
                        // the `ER::bundles` have the same length of `ExecutionInbox`
                        if inboxed_bundles[index].is_invalid() {
                            invalid_bundle_authors.push(bundle_author);
                        } else {
                            paid_bundle_storage_fees
                                .entry(bundle_author)
                                .and_modify(|s| *s += bd.size)
                                .or_insert(bd.size);
                        }
                    }
                }

                // Remove the block's `ExecutionInbox` as the domain block is confirmed and no need to verify
                // its receipt's `extrinsics_root` anymore.
                let _ = ExecutionInbox::<T>::clear_prefix((domain_id, to_prune), u32::MAX, None);

                LatestConfirmedDomainExecutionReceipt::<T>::insert(
                    domain_id,
                    execution_receipt.clone(),
                );

                ConsensusBlockHash::<T>::remove(domain_id, consensus_block_number);

                let block_fees = execution_receipt
                    .block_fees()
                    .total_fees()
                    .ok_or(Error::BalanceOverflow)?;

                ensure!(
                    execution_receipt
                        .transfers()
                        .is_valid(ChainId::Domain(domain_id)),
                    Error::InvalidDomainTransfers
                );

                update_domain_transfers::<T>(domain_id, execution_receipt.transfers(), block_fees)
                    .map_err(|_| Error::DomainTransfersTracking)?;

                update_domain_runtime_upgrade_records::<T>(domain_id, consensus_block_number)?;

                // handle chain rewards from the domain
                execution_receipt
                    .block_fees()
                    .chain_rewards
                    .iter()
                    .for_each(|(chain_id, reward)| {
                        T::OnChainRewards::on_chain_rewards(*chain_id, *reward)
                    });

                return Ok(Some(ConfirmedDomainBlockInfo {
                    consensus_block_number,
                    domain_block_number: to_prune,
                    operator_ids,
                    rewards: execution_receipt.block_fees().domain_execution_fee,
                    invalid_bundle_authors,
                    total_storage_fee: execution_receipt.block_fees().consensus_storage_fee,
                    paid_bundle_storage_fees,
                }));
            }
        }
        AcceptedReceiptType::CurrentHead => {
            // Add confirmation to the current head receipt
            BlockTreeNodes::<T>::mutate(er_hash, |maybe_node| {
                let node = maybe_node.as_mut().expect(
                    "The domain block of `CurrentHead` receipt is checked to be exist in `execution_receipt_type`; qed"
                );
                node.operator_ids.push(submitter);
            });
        }
    }

    // Update the `LatestSubmittedER` for the operator
    let key = (domain_id, submitter);
    if receipt_block_number > Pallet::<T>::latest_submitted_er(key) {
        LatestSubmittedER::<T>::insert(key, receipt_block_number)
    }

    Ok(None)
}

type TransferTrackerError<T> =
    <<T as Config>::DomainsTransfersTracker as DomainsTransfersTracker<BalanceOf<T>>>::Error;

/// Updates domain transfers for following scenarios
/// 1. Block fees are burned on domain
/// 2. Confirming incoming XDM transfers to the Domain
/// 3. Noting outgoing transfers from the domain
/// 4. Cancelling outgoing transfers from the domain.
fn update_domain_transfers<T: Config>(
    domain_id: DomainId,
    transfers: &Transfers<BalanceOf<T>>,
    block_fees: BalanceOf<T>,
) -> Result<(), TransferTrackerError<T>> {
    let Transfers {
        transfers_in,
        transfers_out,
        transfers_rejected,
        rejected_transfers_claimed,
    } = transfers;

    // confirm incoming transfers
    let er_chain_id = ChainId::Domain(domain_id);
    transfers_in
        .iter()
        .try_for_each(|(from_chain_id, amount)| {
            T::DomainsTransfersTracker::confirm_transfer(*from_chain_id, er_chain_id, *amount)
        })?;

    // note outgoing transfers
    transfers_out.iter().try_for_each(|(to_chain_id, amount)| {
        T::DomainsTransfersTracker::note_transfer(er_chain_id, *to_chain_id, *amount)
    })?;

    // note rejected transfers
    transfers_rejected
        .iter()
        .try_for_each(|(from_chain_id, amount)| {
            T::DomainsTransfersTracker::reject_transfer(*from_chain_id, er_chain_id, *amount)
        })?;

    // claim rejected transfers
    rejected_transfers_claimed
        .iter()
        .try_for_each(|(to_chain_id, amount)| {
            T::DomainsTransfersTracker::claim_rejected_transfer(er_chain_id, *to_chain_id, *amount)
        })?;

    // deduct execution fees from domain
    T::DomainsTransfersTracker::reduce_domain_balance(domain_id, block_fees)?;

    Ok(())
}

// Update the domain runtime upgrade record at `consensus_number` if there is one
fn update_domain_runtime_upgrade_records<T: Config>(
    domain_id: DomainId,
    consensus_number: BlockNumberFor<T>,
) -> Result<(), Error> {
    let runtime_id = Pallet::<T>::runtime_id(domain_id).ok_or(Error::RuntimeNotFound)?;
    let mut domain_runtime_upgrade_records = DomainRuntimeUpgradeRecords::<T>::get(runtime_id);

    if let Some(upgrade_entry) = domain_runtime_upgrade_records.get_mut(&consensus_number) {
        // Decrease the `reference_count` by one and remove the whole entry if it drop to zero
        if upgrade_entry.reference_count > One::one() {
            upgrade_entry.reference_count =
                upgrade_entry.reference_count.saturating_sub(One::one());
        } else {
            domain_runtime_upgrade_records.remove(&consensus_number);
        }

        if !domain_runtime_upgrade_records.is_empty() {
            DomainRuntimeUpgradeRecords::<T>::set(runtime_id, domain_runtime_upgrade_records);
        } else {
            DomainRuntimeUpgradeRecords::<T>::remove(runtime_id);
        }
    }
    Ok(())
}

fn add_new_receipt_to_block_tree<T: Config>(
    domain_id: DomainId,
    submitter: OperatorId,
    execution_receipt: ExecutionReceiptOf<T>,
) -> Result<(), Error> {
    // Construct and add a new domain block to the block tree
    let er_hash = execution_receipt.hash::<DomainHashingFor<T>>();
    let domain_block_number = execution_receipt.domain_block_number();

    ensure!(
        !BlockTree::<T>::contains_key(domain_id, domain_block_number),
        Error::OverwritingER,
    );

    BlockTree::<T>::insert(domain_id, domain_block_number, er_hash);
    let block_tree_node = BlockTreeNode {
        execution_receipt,
        operator_ids: sp_std::vec![submitter],
    };
    BlockTreeNodes::<T>::insert(er_hash, block_tree_node);

    Ok(())
}

/// Import the genesis receipt to the block tree
pub(crate) fn import_genesis_receipt<T: Config>(
    domain_id: DomainId,
    genesis_receipt: ExecutionReceiptOf<T>,
) {
    let er_hash = genesis_receipt.hash::<DomainHashingFor<T>>();
    let domain_block_number = *genesis_receipt.domain_block_number();

    LatestConfirmedDomainExecutionReceipt::<T>::insert(domain_id, genesis_receipt.clone());
    DomainGenesisBlockExecutionReceipt::<T>::insert(domain_id, genesis_receipt.clone());

    let block_tree_node = BlockTreeNode {
        execution_receipt: genesis_receipt,
        operator_ids: sp_std::vec![],
    };
    // NOTE: no need to update the head receipt number as `HeadReceiptNumber` is using `ValueQuery`
    BlockTree::<T>::insert(domain_id, domain_block_number, er_hash);
    BlockTreeNodes::<T>::insert(er_hash, block_tree_node);
}

pub(crate) fn prune_receipt<T: Config>(
    domain_id: DomainId,
    receipt_number: DomainBlockNumberFor<T>,
) -> Result<Option<BlockTreeNodeFor<T>>, Error> {
    let receipt_hash = match BlockTree::<T>::take(domain_id, receipt_number) {
        Some(er_hash) => er_hash,
        None => return Ok(None),
    };
    let block_tree_node =
        BlockTreeNodes::<T>::take(receipt_hash).ok_or(Error::MissingDomainBlock)?;

    // If the pruned ER is the operator's `latest_submitted_er` for this domain, it means either:
    //
    // - All the ER the operator submitted for this domain are confirmed and pruned, so the operator
    //   can't be targeted by fraud proof later unless it submit other new ERs.
    //
    // - All the bad ER the operator submitted for this domain are pruned and the operator is already
    //   slashed, so wwe don't need `LatestSubmittedER` to determine if the operator is pending slash.
    //
    // In both cases, it is safe to remove the `LatestSubmittedER` for the operator in this domain
    for operator_id in block_tree_node.operator_ids.iter() {
        let key = (domain_id, operator_id);
        let latest_submitted_er = Pallet::<T>::latest_submitted_er(key);
        if *block_tree_node.execution_receipt.domain_block_number() == latest_submitted_er {
            LatestSubmittedER::<T>::remove(key);
        }
    }

    Ok(Some(block_tree_node))
}

pub(crate) fn invalid_bundle_authors_for_receipt<T: Config>(
    domain_id: DomainId,
    er: &ExecutionReceiptOf<T>,
) -> Vec<OperatorId> {
    let bundle_digests = ExecutionInbox::<T>::get((
        domain_id,
        er.domain_block_number(),
        er.consensus_block_number(),
    ));
    bundle_digests
        .into_iter()
        .enumerate()
        .filter_map(|(index, digest)| {
            let bundle_author = InboxedBundleAuthor::<T>::get(digest.header_hash)?;
            if er.inboxed_bundles()[index].is_invalid() {
                Some(bundle_author)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{BlockTreePruningDepth, Domains, Test};
    use crate::tests::{
        create_dummy_bundle_with_receipts, create_dummy_receipt, extend_block_tree,
        extend_block_tree_from_zero, get_block_tree_node_at, new_test_ext_with_extensions,
        register_genesis_domain, run_to_block,
    };
    use crate::{FrozenDomains, RawOrigin as DomainOrigin};
    use frame_support::dispatch::RawOrigin;
    use frame_support::{assert_err, assert_ok};
    use frame_system::Origin;
    use sp_core::H256;
    use sp_domains::bundle::{BundleDigest, InboxedBundle, InvalidBundleType};

    #[test]
    fn test_genesis_receipt() {
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(0u128, 1);

            // The genesis receipt should be added to the block tree
            let block_tree_node_at_0 = BlockTree::<Test>::get(domain_id, 0).unwrap();

            let genesis_node = BlockTreeNodes::<Test>::get(block_tree_node_at_0).unwrap();
            assert!(genesis_node.operator_ids.is_empty());
            assert_eq!(HeadReceiptNumber::<Test>::get(domain_id), 0);

            // The genesis receipt should be able pass the verification and is unchallengeable
            let genesis_receipt = genesis_node.execution_receipt;
            let invalid_genesis_receipt = {
                let mut receipt = genesis_receipt.clone();
                receipt.set_final_state_root(H256::random());
                receipt
            };
            assert_ok!(verify_execution_receipt::<Test>(
                domain_id,
                &genesis_receipt.as_execution_receipt_ref()
            ));
            // Submitting an invalid genesis ER will result in `NewBranchReceipt` because the operator
            // need to submit fraud proof to pruned a ER first before submitting an ER at the same height
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &invalid_genesis_receipt.as_execution_receipt_ref()
                ),
                Error::NewBranchReceipt
            );
        });
    }

    #[test]
    fn test_new_head_receipt() {
        let creator = 0u128;
        let operator_id = 0u64;
        let block_tree_pruning_depth = <Test as Config>::BlockTreePruningDepth::get();

        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, 1);

            // The genesis node of the block tree
            let genesis_node = get_block_tree_node_at::<Test>(domain_id, 0).unwrap();
            let mut receipt = genesis_node.execution_receipt;
            assert_eq!(
                *receipt.consensus_block_number(),
                frame_system::Pallet::<Test>::current_block_number()
            );
            let mut receipt_of_block_1 = None;
            let mut bundle_header_hash_of_block_1 = None;
            for block_number in 1..=(block_tree_pruning_depth + 3) {
                // Finalize parent block and initialize block at `block_number`
                run_to_block::<Test>(block_number, *receipt.consensus_block_hash());

                if block_number != 1 {
                    // `ConsensusBlockHash` should be set to `Some` since last consensus block contains bundle
                    assert_eq!(
                        ConsensusBlockHash::<Test>::get(domain_id, block_number - 1),
                        Some(frame_system::Pallet::<Test>::block_hash(block_number - 1))
                    );
                    // ER point to last consensus block should have `NewHead` type
                    assert_eq!(
                        execution_receipt_type::<Test>(
                            domain_id,
                            &receipt.as_execution_receipt_ref()
                        ),
                        ReceiptType::Accepted(AcceptedReceiptType::NewHead)
                    );
                    assert_ok!(verify_execution_receipt::<Test>(
                        domain_id,
                        &receipt.as_execution_receipt_ref()
                    ));
                }

                // Submit a bundle with the receipt of the last block
                let bundle_extrinsics_root = H256::random();
                let bundle = create_dummy_bundle_with_receipts(
                    domain_id,
                    operator_id,
                    bundle_extrinsics_root,
                    receipt,
                );
                let bundle_header_hash = bundle.sealed_header().pre_hash();
                let bundle_size = bundle.size();
                assert_ok!(crate::Pallet::<Test>::submit_bundle(
                    DomainOrigin::ValidatedUnsigned.into(),
                    bundle,
                ));
                // `bundle_extrinsics_root` should be tracked in `ExecutionInbox`
                assert_eq!(
                    ExecutionInbox::<Test>::get((domain_id, block_number, block_number)),
                    vec![BundleDigest {
                        header_hash: bundle_header_hash,
                        extrinsics_root: bundle_extrinsics_root,
                        size: bundle_size,
                    }]
                );
                assert!(InboxedBundleAuthor::<Test>::contains_key(
                    bundle_header_hash
                ));

                // Head receipt number should be updated
                let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);
                assert_eq!(head_receipt_number, block_number - 1);

                // As we only extending the block tree there should be no fork
                let parent_domain_block_receipt =
                    BlockTree::<Test>::get(domain_id, head_receipt_number).unwrap();

                // The submitter should be added to `operator_ids`
                let parent_node = BlockTreeNodes::<Test>::get(parent_domain_block_receipt).unwrap();
                assert_eq!(parent_node.operator_ids.len(), 1);
                assert_eq!(parent_node.operator_ids[0], operator_id);

                // Construct a `NewHead` receipt of the just submitted bundle, which will be included
                // in the next bundle
                receipt = create_dummy_receipt(
                    block_number,
                    H256::random(),
                    parent_domain_block_receipt,
                    vec![bundle_extrinsics_root],
                );

                // Record receipt of block #1 for later use
                if block_number == 1 {
                    receipt_of_block_1.replace(receipt.clone());
                    bundle_header_hash_of_block_1.replace(bundle_header_hash);
                }
            }

            // The receipt of the block 1 is pruned at the last iteration, verify it will result in
            // `PrunedReceipt` error
            let pruned_receipt = receipt_of_block_1.unwrap();
            let pruned_bundle = bundle_header_hash_of_block_1.unwrap();
            assert!(BlockTree::<Test>::get(domain_id, 1).is_none());
            assert!(ExecutionInbox::<Test>::get((domain_id, 1, 1)).is_empty());
            assert!(!InboxedBundleAuthor::<Test>::contains_key(pruned_bundle));
            assert_eq!(
                execution_receipt_type::<Test>(
                    domain_id,
                    &pruned_receipt.as_execution_receipt_ref()
                ),
                ReceiptType::Rejected(RejectedReceiptType::Pruned)
            );
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &pruned_receipt.as_execution_receipt_ref()
                ),
                Error::PrunedReceipt
            );
            assert!(
                ConsensusBlockHash::<Test>::get(domain_id, pruned_receipt.consensus_block_number(),)
                    .is_none()
            );
        });
    }

    #[test]
    fn test_confirm_current_head_receipt() {
        let creator = 0u128;
        let operator_id1 = 0u64;
        let operator_id2 = 1u64;
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, 2);
            let next_head_receipt = extend_block_tree_from_zero(domain_id, operator_id1, 3);

            // Submit the new head receipt
            assert_eq!(
                execution_receipt_type::<Test>(
                    domain_id,
                    &next_head_receipt.as_execution_receipt_ref()
                ),
                ReceiptType::Accepted(AcceptedReceiptType::NewHead)
            );
            assert_ok!(verify_execution_receipt::<Test>(
                domain_id,
                &next_head_receipt.as_execution_receipt_ref()
            ));
            let bundle = create_dummy_bundle_with_receipts(
                domain_id,
                operator_id1,
                H256::random(),
                next_head_receipt.clone(),
            );
            assert_ok!(crate::Pallet::<Test>::submit_bundle(
                DomainOrigin::ValidatedUnsigned.into(),
                bundle,
            ));

            let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);
            let current_head_receipt =
                get_block_tree_node_at::<Test>(domain_id, head_receipt_number)
                    .unwrap()
                    .execution_receipt;

            // Now `next_head_receipt` become the head receipt
            assert_eq!(next_head_receipt, current_head_receipt);

            // Head receipt added in the current block is consider valid
            assert_eq!(
                execution_receipt_type::<Test>(
                    domain_id,
                    &current_head_receipt.as_execution_receipt_ref()
                ),
                ReceiptType::Accepted(AcceptedReceiptType::CurrentHead)
            );
            assert_ok!(verify_execution_receipt::<Test>(
                domain_id,
                &current_head_receipt.as_execution_receipt_ref()
            ));

            // Re-submit the head receipt by a different operator is okay
            let bundle = create_dummy_bundle_with_receipts(
                domain_id,
                operator_id2,
                H256::random(),
                current_head_receipt,
            );
            assert_ok!(crate::Pallet::<Test>::submit_bundle(
                DomainOrigin::ValidatedUnsigned.into(),
                bundle,
            ));

            let head_node = get_block_tree_node_at::<Test>(domain_id, head_receipt_number).unwrap();
            assert_eq!(head_node.operator_ids, vec![operator_id1, operator_id2]);
        });
    }

    #[test]
    fn test_non_head_receipt() {
        let creator = 0u128;
        let operator_id1 = 0u64;
        let operator_id2 = 1u64;
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, 2);
            extend_block_tree_from_zero(domain_id, operator_id1, 3);

            // Receipt that confirm a non-head receipt is stale receipt
            let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);
            let stale_receipt = get_block_tree_node_at::<Test>(domain_id, head_receipt_number - 1)
                .unwrap()
                .execution_receipt;
            let stale_receipt_hash = stale_receipt.hash::<DomainHashingFor<Test>>();

            // Stale receipt can pass the verification
            assert_eq!(
                execution_receipt_type::<Test>(
                    domain_id,
                    &stale_receipt.as_execution_receipt_ref()
                ),
                ReceiptType::Rejected(RejectedReceiptType::Stale)
            );
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &stale_receipt.as_execution_receipt_ref()
                ),
                Error::StaleReceipt
            );

            // Stale receipt will be rejected and won't be added to the block tree
            let bundle = create_dummy_bundle_with_receipts(
                domain_id,
                operator_id2,
                H256::random(),
                stale_receipt,
            );
            assert!(crate::Pallet::<Test>::submit_bundle(RawOrigin::None.into(), bundle).is_err());

            assert_eq!(
                BlockTreeNodes::<Test>::get(stale_receipt_hash)
                    .unwrap()
                    .operator_ids,
                vec![operator_id1]
            );
        });
    }

    #[test]
    fn test_previous_head_receipt() {
        let creator = 0u128;
        let operator_id1 = 0u64;
        let operator_id2 = 1u64;
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, 2);
            extend_block_tree_from_zero(domain_id, operator_id1, 3);

            // No new receipt submitted in current block
            assert!(NewAddedHeadReceipt::<Test>::get(domain_id).is_none());

            // Receipt that confirm a head receipt of the previous block is stale receipt
            let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);
            let previous_head_receipt =
                get_block_tree_node_at::<Test>(domain_id, head_receipt_number)
                    .unwrap()
                    .execution_receipt;

            // Stale receipt can not pass the verification
            assert_eq!(
                execution_receipt_type::<Test>(
                    domain_id,
                    &previous_head_receipt.as_execution_receipt_ref()
                ),
                ReceiptType::Rejected(RejectedReceiptType::Stale)
            );
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &previous_head_receipt.as_execution_receipt_ref()
                ),
                Error::StaleReceipt
            );

            // Stale receipt will be rejected and won't be added to the block tree
            let bundle = create_dummy_bundle_with_receipts(
                domain_id,
                operator_id2,
                H256::random(),
                previous_head_receipt,
            );
            assert!(crate::Pallet::<Test>::submit_bundle(RawOrigin::None.into(), bundle).is_err());
        });
    }

    #[test]
    fn test_new_branch_receipt() {
        let creator = 0u128;
        let operator_id1 = 0u64;
        let operator_id2 = 1u64;
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, 2);
            extend_block_tree_from_zero(domain_id, operator_id1, 3);

            let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);
            assert!(BlockTree::<Test>::get(domain_id, head_receipt_number).is_some());

            // Construct new branch receipt that fork away from an existing node of
            // the block tree
            let new_branch_receipt = {
                let mut head_receipt =
                    get_block_tree_node_at::<Test>(domain_id, head_receipt_number)
                        .unwrap()
                        .execution_receipt;
                head_receipt.set_final_state_root(H256::random());
                head_receipt
            };
            let new_branch_receipt_hash = new_branch_receipt.hash::<DomainHashingFor<Test>>();

            // New branch receipt can pass the verification
            assert_eq!(
                execution_receipt_type::<Test>(
                    domain_id,
                    &new_branch_receipt.as_execution_receipt_ref()
                ),
                ReceiptType::Rejected(RejectedReceiptType::NewBranch)
            );
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &new_branch_receipt.as_execution_receipt_ref()
                ),
                Error::NewBranchReceipt
            );

            // Submit the new branch receipt will be rejected
            let bundle = create_dummy_bundle_with_receipts(
                domain_id,
                operator_id2,
                H256::random(),
                new_branch_receipt,
            );
            assert!(crate::Pallet::<Test>::submit_bundle(RawOrigin::None.into(), bundle).is_err());
            assert!(BlockTreeNodes::<Test>::get(new_branch_receipt_hash).is_none());
        });
    }

    #[test]
    fn test_prune_domain_execution_receipt() {
        let creator = 0u128;
        let operator_id = 0u64;
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, 1);
            let _next_receipt = extend_block_tree_from_zero(domain_id, operator_id, 3);
            let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);

            // freeze domain
            assert!(!FrozenDomains::<Test>::get().contains(&domain_id));
            Domains::freeze_domain(Origin::<Test>::Root.into(), domain_id).unwrap();
            assert!(FrozenDomains::<Test>::get().contains(&domain_id));

            // prune execution recept
            let head_receipt_hash = BlockTree::<Test>::get(domain_id, head_receipt_number).unwrap();
            Domains::prune_domain_execution_receipt(
                Origin::<Test>::Root.into(),
                domain_id,
                head_receipt_hash,
            )
            .unwrap();
            assert_eq!(
                HeadReceiptNumber::<Test>::get(domain_id),
                head_receipt_number - 1
            );

            // unfreeze domain
            Domains::unfreeze_domain(Origin::<Test>::Root.into(), domain_id).unwrap();
            assert!(!FrozenDomains::<Test>::get().contains(&domain_id));
        })
    }

    #[test]
    fn test_invalid_receipt() {
        let creator = 0u128;
        let operator_id = 0u64;
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, 1);
            let next_receipt = extend_block_tree_from_zero(domain_id, operator_id, 3);
            let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);

            // Construct a future receipt
            let mut future_receipt = next_receipt.clone();
            future_receipt.set_domain_block_number(head_receipt_number + 2);
            future_receipt.set_consensus_block_number(head_receipt_number as u32 + 2);
            ExecutionInbox::<Test>::insert(
                (
                    domain_id,
                    future_receipt.domain_block_number(),
                    future_receipt.consensus_block_number(),
                ),
                future_receipt
                    .inboxed_bundles()
                    .iter()
                    .map(|b| BundleDigest {
                        header_hash: H256::random(),
                        extrinsics_root: b.extrinsics_root,
                        size: 0,
                    })
                    .collect::<Vec<_>>(),
            );
            assert_eq!(
                execution_receipt_type::<Test>(
                    domain_id,
                    &future_receipt.as_execution_receipt_ref()
                ),
                ReceiptType::Rejected(RejectedReceiptType::InFuture)
            );
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &future_receipt.as_execution_receipt_ref()
                ),
                Error::InFutureReceipt
            );

            // Receipt with unknown extrinsics roots
            let mut unknown_extrinsics_roots_receipt = next_receipt.clone();
            unknown_extrinsics_roots_receipt
                .set_inboxed_bundles(vec![InboxedBundle::valid(H256::random(), H256::random())]);
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &unknown_extrinsics_roots_receipt.as_execution_receipt_ref()
                ),
                Error::InvalidExtrinsicsRoots
            );

            // Receipt with unknown consensus block hash
            let mut unknown_consensus_block_receipt = next_receipt.clone();
            unknown_consensus_block_receipt.set_consensus_block_hash(H256::random());
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &unknown_consensus_block_receipt.as_execution_receipt_ref()
                ),
                Error::BuiltOnUnknownConsensusBlock
            );

            // Receipt with unknown parent receipt
            let mut unknown_parent_receipt = next_receipt.clone();
            unknown_parent_receipt.set_parent_receipt_hash(H256::random());
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &unknown_parent_receipt.as_execution_receipt_ref()
                ),
                Error::UnknownParentBlockReceipt
            );

            // Receipt with execution_trace length less than two
            let mut invalid_execution_trace_receipt = next_receipt;

            // Receipt with only one element in execution trace vector
            invalid_execution_trace_receipt.set_execution_traces(vec![
                invalid_execution_trace_receipt
                    .execution_traces()
                    .first()
                    .cloned()
                    .expect("First element should be there; qed"),
            ]);
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &invalid_execution_trace_receipt.as_execution_receipt_ref()
                ),
                Error::InvalidExecutionTrace
            );

            // Receipt with zero element in execution trace vector
            invalid_execution_trace_receipt.set_execution_traces(vec![]);
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &invalid_execution_trace_receipt.as_execution_receipt_ref()
                ),
                Error::InvalidExecutionTrace
            );
        });
    }

    #[test]
    fn test_invalid_receipt_with_head_receipt_already_extended() {
        let creator = 0u128;
        let operator_id = 0u64;
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, 1);
            let next_receipt = extend_block_tree_from_zero(domain_id, operator_id, 3);
            let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);

            // reject extending receipt if the HeadReceiptNumber is already extended
            assert!(NewAddedHeadReceipt::<Test>::get(domain_id).is_none());
            NewAddedHeadReceipt::<Test>::set(domain_id, Some(H256::random()));

            // Construct a future receipt
            let mut future_receipt = next_receipt.clone();
            future_receipt.set_domain_block_number(head_receipt_number + 1);
            future_receipt.set_consensus_block_number(head_receipt_number as u32 + 1);

            ExecutionInbox::<Test>::insert(
                (
                    domain_id,
                    future_receipt.domain_block_number(),
                    future_receipt.consensus_block_number(),
                ),
                future_receipt
                    .inboxed_bundles()
                    .iter()
                    .map(|b| BundleDigest {
                        header_hash: H256::random(),
                        extrinsics_root: b.extrinsics_root,
                        size: 0,
                    })
                    .collect::<Vec<_>>(),
            );
            assert_eq!(
                execution_receipt_type::<Test>(
                    domain_id,
                    &future_receipt.as_execution_receipt_ref()
                ),
                ReceiptType::Rejected(RejectedReceiptType::InFuture)
            );
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &future_receipt.as_execution_receipt_ref()
                ),
                Error::InFutureReceipt
            );
        });
    }

    #[test]
    fn test_invalid_trace_root_receipt() {
        let creator = 0u128;
        let operator_id1 = 0u64;
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, 2);
            let mut next_receipt = extend_block_tree_from_zero(domain_id, operator_id1, 3);
            let mut traces = next_receipt.execution_traces().to_vec();
            traces.push(H256::random());
            next_receipt.set_execution_traces(traces);
            next_receipt.set_final_state_root(*next_receipt.execution_traces().last().unwrap());

            let mut trace = Vec::with_capacity(next_receipt.execution_traces().len());
            for root in next_receipt.execution_traces() {
                trace.push(
                    root.encode()
                        .try_into()
                        .map_err(|_| Error::InvalidTraceRoot)
                        .expect("H256 to Blake3Hash should be successful; qed"),
                );
            }
            let new_execution_trace_root = MerkleTree::from_leaves(trace.as_slice())
                .root()
                .expect("Compute merkle root of trace should success")
                .into();
            next_receipt.set_execution_trace_root(new_execution_trace_root);
            assert_ok!(verify_execution_receipt::<Test>(
                domain_id,
                &next_receipt.as_execution_receipt_ref()
            ));

            // Receipt with wrong value of `execution_trace_root`
            let mut invalid_receipt = next_receipt.clone();
            invalid_receipt.set_execution_trace_root(H256::random());
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &invalid_receipt.as_execution_receipt_ref()
                ),
                Error::InvalidTraceRoot
            );

            // Receipt with wrong value of trace
            let mut invalid_receipt = next_receipt.clone();
            let mut traces = invalid_receipt.execution_traces().to_vec();
            traces[0] = H256::random();
            invalid_receipt.set_execution_traces(traces);
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &invalid_receipt.as_execution_receipt_ref()
                ),
                Error::InvalidTraceRoot
            );

            // Receipt with additional trace
            let mut invalid_receipt = next_receipt.clone();
            let mut traces = invalid_receipt.execution_traces().to_vec();
            traces.push(H256::random());
            invalid_receipt.set_execution_traces(traces);
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &invalid_receipt.as_execution_receipt_ref()
                ),
                Error::InvalidTraceRoot
            );

            // Receipt with missing trace
            let mut invalid_receipt = next_receipt;
            let mut traces = invalid_receipt.execution_traces().to_vec();
            traces.pop();
            invalid_receipt.set_execution_traces(traces);
            assert_err!(
                verify_execution_receipt::<Test>(
                    domain_id,
                    &invalid_receipt.as_execution_receipt_ref()
                ),
                Error::InvalidTraceRoot
            );
        });
    }

    #[test]
    fn test_collect_invalid_bundle_author() {
        let creator = 0u128;
        let challenge_period = BlockTreePruningDepth::get();
        let operator_set: Vec<_> = (0..14).collect();
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id = register_genesis_domain(creator, operator_set.len());
            let next_receipt = extend_block_tree_from_zero(domain_id, operator_set[0], 3);

            // Submit bundle for every operator
            for operator_id in operator_set.iter() {
                let bundle = create_dummy_bundle_with_receipts(
                    domain_id,
                    *operator_id,
                    H256::random(),
                    next_receipt.clone(),
                );
                assert_ok!(crate::Pallet::<Test>::submit_bundle(
                    DomainOrigin::ValidatedUnsigned.into(),
                    bundle,
                ));
            }
            let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);
            let head_node = get_block_tree_node_at::<Test>(domain_id, head_receipt_number).unwrap();
            assert_eq!(head_node.operator_ids, operator_set);

            // Get the `bundles_extrinsics_roots` that contains all the submitted bundles
            let current_block_number = frame_system::Pallet::<Test>::current_block_number();
            let execution_inbox = ExecutionInbox::<Test>::get((
                domain_id,
                current_block_number,
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
            let mut target_receipt = create_dummy_receipt(
                current_block_number,
                H256::random(),
                next_receipt.hash::<DomainHashingFor<Test>>(),
                vec![],
            );
            target_receipt.set_inboxed_bundles(bundles);

            // Extend the block tree by `challenge_period + 1` blocks
            let next_receipt = extend_block_tree(
                domain_id,
                operator_set[0],
                current_block_number + challenge_period + 1u32,
                target_receipt,
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
