//! Schema for executor in the aux-db.

use crate::ExecutionReceiptFor;
use codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sp_blockchain::{Error as ClientError, Result as ClientResult};
use sp_domains::InvalidBundleType;
use sp_runtime::traits::{Block as BlockT, NumberFor, One, SaturatedConversion};
use subspace_core_primitives::BlockNumber;

const EXECUTION_RECEIPT: &[u8] = b"execution_receipt";
const EXECUTION_RECEIPT_START: &[u8] = b"execution_receipt_start";
const EXECUTION_RECEIPT_BLOCK_NUMBER: &[u8] = b"execution_receipt_block_number";

/// domain_block_hash => latest_consensus_block_hash
///
/// It's important to note that a consensus block could possibly contain no bundles for a specific domain,
/// leading to the situation where multiple consensus blocks could correspond to the same domain block.
///
/// ConsensusBlock10 --> DomainBlock5
/// ConsensusBlock11 --> DomainBlock5
/// ConsensusBlock12 --> DomainBlock5
///
/// This mapping is designed to track the most recent consensus block that derives the domain block
/// identified by `domain_block_hash`, e.g., Hash(DomainBlock5) => Hash(ConsensusBlock12).
const LATEST_CONSENSUS_HASH: &[u8] = b"latest_consensus_hash";

/// consensus_block_hash => best_domain_block_hash
///
/// This mapping tracks the mapping of a consensus block and the corresponding domain block derived
/// until this consensus block:
/// - Hash(ConsensusBlock10) => Hash(DomainBlock5)
/// - Hash(ConsensusBlock11) => Hash(DomainBlock5)
/// - Hash(ConsensusBlock12) => Hash(DomainBlock5)
const BEST_DOMAIN_HASH: &[u8] = b"best_domain_hash";

/// Prune the execution receipts when they reach this number.
const PRUNING_DEPTH: BlockNumber = 1000;

fn execution_receipt_key(block_hash: impl Encode) -> Vec<u8> {
    (EXECUTION_RECEIPT, block_hash).encode()
}

fn load_decode<Backend: AuxStore, T: Decode>(
    backend: &Backend,
    key: &[u8],
) -> ClientResult<Option<T>> {
    match backend.get_aux(key)? {
        None => Ok(None),
        Some(t) => T::decode(&mut &t[..])
            .map_err(|e| {
                ClientError::Backend(format!("Operator DB is corrupted. Decode error: {e}"))
            })
            .map(Some),
    }
}

/// Write an execution receipt to aux storage, optionally prune the receipts that are
/// too old.
pub(super) fn write_execution_receipt<Backend, Block, CBlock>(
    backend: &Backend,
    head_receipt_number: NumberFor<Block>,
    execution_receipt: &ExecutionReceiptFor<Block, CBlock>,
) -> Result<(), sp_blockchain::Error>
where
    Backend: AuxStore,
    Block: BlockT,
    CBlock: BlockT,
{
    let block_number = execution_receipt.consensus_block_number;
    let consensus_hash = execution_receipt.consensus_block_hash;

    let block_number_key = (EXECUTION_RECEIPT_BLOCK_NUMBER, block_number).encode();
    let mut hashes_at_block_number =
        load_decode::<_, Vec<CBlock::Hash>>(backend, block_number_key.as_slice())?
            .unwrap_or_default();
    hashes_at_block_number.push(consensus_hash);

    let first_saved_receipt =
        load_decode::<_, NumberFor<CBlock>>(backend, EXECUTION_RECEIPT_START)?
            .unwrap_or(block_number);

    let mut new_first_saved_receipt = first_saved_receipt;

    let mut keys_to_delete = vec![];

    if let Some(delete_receipts_to) = head_receipt_number
        .saturated_into::<BlockNumber>()
        .checked_sub(PRUNING_DEPTH)
    {
        new_first_saved_receipt = Into::<NumberFor<CBlock>>::into(delete_receipts_to) + One::one();
        for receipt_to_delete in first_saved_receipt.saturated_into()..=delete_receipts_to {
            let delete_block_number_key =
                (EXECUTION_RECEIPT_BLOCK_NUMBER, receipt_to_delete).encode();

            if let Some(hashes_to_delete) =
                load_decode::<_, Vec<CBlock::Hash>>(backend, delete_block_number_key.as_slice())?
            {
                keys_to_delete.extend(
                    hashes_to_delete
                        .into_iter()
                        .map(|h| (EXECUTION_RECEIPT, h).encode()),
                );
                keys_to_delete.push(delete_block_number_key);
            }
        }
    }

    backend.insert_aux(
        &[
            (
                execution_receipt_key(consensus_hash).as_slice(),
                execution_receipt.encode().as_slice(),
            ),
            (
                block_number_key.as_slice(),
                hashes_at_block_number.encode().as_slice(),
            ),
            (
                EXECUTION_RECEIPT_START,
                new_first_saved_receipt.encode().as_slice(),
            ),
        ],
        &keys_to_delete
            .iter()
            .map(|k| &k[..])
            .collect::<Vec<&[u8]>>()[..],
    )
}

/// Load the execution receipt for given consensus block hash.
pub fn load_execution_receipt<Backend, Block, CBlock>(
    backend: &Backend,
    consensus_block_hash: CBlock::Hash,
) -> ClientResult<Option<ExecutionReceiptFor<Block, CBlock>>>
where
    Backend: AuxStore,
    Block: BlockT,
    CBlock: BlockT,
{
    load_decode(
        backend,
        execution_receipt_key(consensus_block_hash).as_slice(),
    )
}

pub(super) fn track_domain_hash_and_consensus_hash<Backend, Hash, CHash>(
    backend: &Backend,
    best_domain_hash: Hash,
    latest_consensus_hash: CHash,
) -> ClientResult<()>
where
    Backend: AuxStore,
    Hash: Clone + Encode,
    CHash: Encode,
{
    // TODO: prune the stale mappings.

    backend.insert_aux(
        &[
            (
                (LATEST_CONSENSUS_HASH, best_domain_hash.clone())
                    .encode()
                    .as_slice(),
                latest_consensus_hash.encode().as_slice(),
            ),
            (
                (BEST_DOMAIN_HASH, latest_consensus_hash)
                    .encode()
                    .as_slice(),
                best_domain_hash.encode().as_slice(),
            ),
        ],
        vec![],
    )
}

pub(super) fn best_domain_hash_for<Backend, Hash, CHash>(
    backend: &Backend,
    consensus_hash: &CHash,
) -> ClientResult<Option<Hash>>
where
    Backend: AuxStore,
    Hash: Decode,
    CHash: Encode,
{
    load_decode(
        backend,
        (BEST_DOMAIN_HASH, consensus_hash).encode().as_slice(),
    )
}

pub(super) fn latest_consensus_block_hash_for<Backend, Hash, CHash>(
    backend: &Backend,
    domain_hash: &Hash,
) -> ClientResult<Option<CHash>>
where
    Backend: AuxStore,
    Hash: Encode,
    CHash: Decode,
{
    load_decode(
        backend,
        (LATEST_CONSENSUS_HASH, domain_hash).encode().as_slice(),
    )
}

// TODO: Unlock once domain test infra is workable again.
#[allow(dead_code)]
pub(super) fn target_receipt_is_pruned(
    head_receipt_number: BlockNumber,
    target_block: BlockNumber,
) -> bool {
    head_receipt_number.saturating_sub(target_block) >= PRUNING_DEPTH
}

#[derive(Encode, Decode, Debug, PartialEq)]
pub(super) enum BundleMismatchType {
    // The invalid bundle is mismatch
    // For `TrueInvalid`, the fraud proof need to prove the bundle is indeed invalid due to `InvalidBundleType`
    // For `FalseInvalid`, the fraud proof need to prove the bundle is not invalid due to `InvalidBundleType`
    TrueInvalid(InvalidBundleType),
    FalseInvalid(InvalidBundleType),
    // The valid bundle is mismatch
    Valid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain_test_service::evm_domain_test_runtime::Block;
    use sp_core::hash::H256;
    use subspace_runtime_primitives::{Balance, BlockNumber, Hash};
    use subspace_test_runtime::Block as CBlock;

    type ExecutionReceipt =
        sp_domains::ExecutionReceipt<BlockNumber, Hash, BlockNumber, Hash, Balance>;

    fn create_execution_receipt(consensus_block_number: BlockNumber) -> ExecutionReceipt {
        ExecutionReceipt {
            domain_block_number: consensus_block_number,
            domain_block_hash: H256::random(),
            domain_block_extrinsic_root: H256::random(),
            parent_domain_block_receipt_hash: H256::random(),
            consensus_block_number,
            consensus_block_hash: H256::random(),
            inboxed_bundles: Vec::new(),
            final_state_root: Default::default(),
            execution_trace: Default::default(),
            execution_trace_root: Default::default(),
            total_rewards: Default::default(),
        }
    }

    // TODO: Remove `substrate_test_runtime_client` dependency for faster build time
    // TODO: Un-ignore once test client is fixed and working again on Windows
    #[test]
    #[ignore]
    fn normal_prune_execution_receipt_works() {
        let client = substrate_test_runtime_client::new();

        let receipt_start = || {
            load_decode::<_, BlockNumber>(&client, EXECUTION_RECEIPT_START.to_vec().as_slice())
                .unwrap()
        };

        let hashes_at = |number: BlockNumber| {
            load_decode::<_, Vec<Hash>>(
                &client,
                (EXECUTION_RECEIPT_BLOCK_NUMBER, number).encode().as_slice(),
            )
            .unwrap()
        };

        let receipt_at = |consensus_block_hash: Hash| {
            load_execution_receipt::<_, Block, CBlock>(&client, consensus_block_hash).unwrap()
        };

        let write_receipt_at = |number: BlockNumber, receipt: &ExecutionReceipt| {
            write_execution_receipt::<_, Block, CBlock>(
                &client,
                number - 1, // Ideally, the receipt of previous block has been included when writing the receipt of current block.
                receipt,
            )
            .unwrap()
        };

        assert_eq!(receipt_start(), None);

        // Create PRUNING_DEPTH receipts.
        let block_hash_list = (1..=PRUNING_DEPTH)
            .map(|block_number| {
                let receipt = create_execution_receipt(block_number);
                let consensus_block_hash = receipt.consensus_block_hash;
                write_receipt_at(block_number, &receipt);
                assert_eq!(receipt_at(consensus_block_hash), Some(receipt));
                assert_eq!(hashes_at(block_number), Some(vec![consensus_block_hash]));
                assert_eq!(receipt_start(), Some(1));
                consensus_block_hash
            })
            .collect::<Vec<_>>();

        assert!(!target_receipt_is_pruned(PRUNING_DEPTH, 1));

        // Create PRUNING_DEPTH + 1 receipt, head_receipt_number is PRUNING_DEPTH.
        let receipt = create_execution_receipt(PRUNING_DEPTH + 1);
        assert!(receipt_at(receipt.consensus_block_hash).is_none());
        write_receipt_at(PRUNING_DEPTH + 1, &receipt);
        assert!(receipt_at(receipt.consensus_block_hash).is_some());

        // Create PRUNING_DEPTH + 2 receipt, head_receipt_number is PRUNING_DEPTH + 1.
        let receipt = create_execution_receipt(PRUNING_DEPTH + 2);
        write_receipt_at(PRUNING_DEPTH + 2, &receipt);
        assert!(receipt_at(receipt.consensus_block_hash).is_some());

        // ER of block #1 should be pruned.
        assert!(receipt_at(block_hash_list[0]).is_none());
        // block number mapping should be pruned as well.
        assert!(hashes_at(1).is_none());
        assert!(target_receipt_is_pruned(PRUNING_DEPTH + 1, 1));
        assert_eq!(receipt_start(), Some(2));

        // Create PRUNING_DEPTH + 3 receipt, head_receipt_number is PRUNING_DEPTH + 2.
        let receipt = create_execution_receipt(PRUNING_DEPTH + 3);
        let consensus_block_hash1 = receipt.consensus_block_hash;
        write_receipt_at(PRUNING_DEPTH + 3, &receipt);
        assert!(receipt_at(consensus_block_hash1).is_some());
        // ER of block #2 should be pruned.
        assert!(receipt_at(block_hash_list[1]).is_none());
        assert!(target_receipt_is_pruned(PRUNING_DEPTH + 2, 2));
        assert!(!target_receipt_is_pruned(PRUNING_DEPTH + 2, 3));
        assert_eq!(receipt_start(), Some(3));

        // Multiple hashes attached to the block #(PRUNING_DEPTH + 3)
        let receipt = create_execution_receipt(PRUNING_DEPTH + 3);
        let consensus_block_hash2 = receipt.consensus_block_hash;
        write_receipt_at(PRUNING_DEPTH + 3, &receipt);
        assert!(receipt_at(consensus_block_hash2).is_some());
        assert_eq!(
            hashes_at(PRUNING_DEPTH + 3),
            Some(vec![consensus_block_hash1, consensus_block_hash2])
        );
    }

    // TODO: Un-ignore once test client is fixed and working again on Windows
    #[test]
    #[ignore]
    fn execution_receipts_should_be_kept_against_head_receipt_number() {
        let client = substrate_test_runtime_client::new();

        let receipt_start = || {
            load_decode::<_, BlockNumber>(&client, EXECUTION_RECEIPT_START.to_vec().as_slice())
                .unwrap()
        };

        let hashes_at = |number: BlockNumber| {
            load_decode::<_, Vec<Hash>>(
                &client,
                (EXECUTION_RECEIPT_BLOCK_NUMBER, number).encode().as_slice(),
            )
            .unwrap()
        };

        let receipt_at = |consensus_block_hash: Hash| {
            load_execution_receipt::<_, Block, CBlock>(&client, consensus_block_hash).unwrap()
        };

        let write_receipt_at = |head_receipt_number: BlockNumber, receipt: &ExecutionReceipt| {
            write_execution_receipt::<_, Block, CBlock>(&client, head_receipt_number, receipt)
                .unwrap()
        };

        assert_eq!(receipt_start(), None);

        // Create PRUNING_DEPTH receipts, head_receipt_number is 0, i.e., no receipt
        // has ever been included on consensus chain.
        let block_hash_list = (1..=PRUNING_DEPTH)
            .map(|block_number| {
                let receipt = create_execution_receipt(block_number);
                let consensus_block_hash = receipt.consensus_block_hash;
                write_receipt_at(0, &receipt);
                assert_eq!(receipt_at(consensus_block_hash), Some(receipt));
                assert_eq!(hashes_at(block_number), Some(vec![consensus_block_hash]));
                assert_eq!(receipt_start(), Some(1));
                consensus_block_hash
            })
            .collect::<Vec<_>>();

        assert!(!target_receipt_is_pruned(PRUNING_DEPTH, 1));

        // Create PRUNING_DEPTH + 1 receipt, head_receipt_number is 0.
        let receipt = create_execution_receipt(PRUNING_DEPTH + 1);
        assert!(receipt_at(receipt.consensus_block_hash).is_none());
        write_receipt_at(0, &receipt);

        // Create PRUNING_DEPTH + 2 receipt, head_receipt_number is 0.
        let receipt = create_execution_receipt(PRUNING_DEPTH + 2);
        write_receipt_at(0, &receipt);

        // ER of block #1 should not be pruned even the size of stored receipts exceeds the pruning depth.
        assert!(receipt_at(block_hash_list[0]).is_some());
        // block number mapping for #1 should not be pruned neither.
        assert!(hashes_at(1).is_some());
        assert!(!target_receipt_is_pruned(0, 1));
        assert_eq!(receipt_start(), Some(1));

        // Create PRUNING_DEPTH + 3 receipt, head_receipt_number is 0.
        let receipt = create_execution_receipt(PRUNING_DEPTH + 3);
        write_receipt_at(0, &receipt);

        // Create PRUNING_DEPTH + 4 receipt, head_receipt_number is PRUNING_DEPTH + 3.
        let receipt = create_execution_receipt(PRUNING_DEPTH + 4);
        write_receipt_at(
            PRUNING_DEPTH + 3, // Now assuming all the missing receipts are included.
            &receipt,
        );
        assert!(receipt_at(block_hash_list[0]).is_none());
        // receipt and block number mapping for [1, 2, 3] should be pruned.
        (1..=3).for_each(|pruned| {
            assert!(hashes_at(pruned).is_none());
            assert!(target_receipt_is_pruned(PRUNING_DEPTH + 3, pruned));
        });
        assert_eq!(receipt_start(), Some(4));
    }
}
