//! Schema for executor in the aux-db.

use crate::ExecutionReceiptFor;
use codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sc_client_api::HeaderBackend;
use sp_blockchain::{Error as ClientError, Result as ClientResult};
use sp_core::H256;
use sp_runtime::traits::{Block as BlockT, NumberFor, One, SaturatedConversion};
use subspace_core_primitives::BlockNumber;

const EXECUTION_RECEIPT: &[u8] = b"execution_receipt";
const EXECUTION_RECEIPT_START: &[u8] = b"execution_receipt_start";
const EXECUTION_RECEIPT_BLOCK_NUMBER: &[u8] = b"execution_receipt_block_number";

/// bad_receipt_block_number => all_bad_receipt_hashes_at_this_block
const BAD_RECEIPT_HASHES: &[u8] = b"bad_receipt_hashes";

/// bad_receipt_hash => (trace_mismatch_index, associated_local_block_hash)
const BAD_RECEIPT_MISMATCH_INFO: &[u8] = b"bad_receipt_mismatch_info";

/// Set of block numbers at which there is at least one bad receipt detected.
///
/// NOTE: Unbounded but the size is not expected to be large.
const BAD_RECEIPT_NUMBERS: &[u8] = b"bad_receipt_numbers";

/// domain_block_hash => consensus_block_hash
///
/// Updated only when there is a new domain block produced
const CONSENSUS_HASH: &[u8] = b"consensus_block_hash";

/// domain_block_hash => latest_primary_block_hash
///
/// It's important to note that a primary block could possibly contain no bundles for a specific domain,
/// leading to the situation where multiple primary blocks could correspond to the same domain block.
///
/// PrimaryBlock10 --> DomainBlock5
/// PrimaryBlock11 --> DomainBlock5
/// PrimaryBlock12 --> DomainBlock5
///
/// This mapping is designed to track the most recent primary block that derives the domain block
/// identified by `domain_block_hash`, e.g., Hash(DomainBlock5) => Hash(PrimaryBlock12).
const LATEST_PRIMARY_HASH: &[u8] = b"latest_primary_hash";

/// primary_block_hash => best_domain_block_hash
///
/// This mapping tracks the mapping of a primary block and the corresponding domain block derived
/// until this primary block:
/// - Hash(PrimaryBlock10) => Hash(DomainBlock5)
/// - Hash(PrimaryBlock11) => Hash(DomainBlock5)
/// - Hash(PrimaryBlock12) => Hash(DomainBlock5)
const BEST_DOMAIN_HASH: &[u8] = b"best_domain_hash";

/// Prune the execution receipts when they reach this number.
const PRUNING_DEPTH: BlockNumber = 1000;

fn execution_receipt_key(block_hash: impl Encode) -> Vec<u8> {
    (EXECUTION_RECEIPT, block_hash).encode()
}

fn bad_receipt_mismatch_info_key(bad_receipt_hash: impl Encode) -> Vec<u8> {
    (BAD_RECEIPT_MISMATCH_INFO, bad_receipt_hash).encode()
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
    let domain_hash = execution_receipt.domain_hash;

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
            // TODO: prune the stale mappings.
            (
                (CONSENSUS_HASH, domain_hash).encode().as_slice(),
                consensus_hash.encode().as_slice(),
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

/// Load the execution receipt for given domain block hash.
pub(super) fn load_execution_receipt_by_domain_hash<Backend, Block, CBlock>(
    backend: &Backend,
    domain_hash: Block::Hash,
) -> ClientResult<Option<ExecutionReceiptFor<Block, CBlock>>>
where
    Backend: AuxStore,
    Block: BlockT,
    CBlock: BlockT,
{
    match consensus_block_hash_for::<Backend, Block::Hash, CBlock::Hash>(backend, domain_hash)? {
        Some(primary_block_hash) => load_decode(
            backend,
            execution_receipt_key(primary_block_hash).as_slice(),
        ),
        None => Ok(None),
    }
}

/// Load the execution receipt for given consensus block hash.
pub(super) fn load_execution_receipt<Backend, Block, CBlock>(
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

pub(super) fn track_domain_hash_and_consensus_hash<Backend, Hash, PHash>(
    backend: &Backend,
    best_domain_hash: Hash,
    latest_primary_hash: PHash,
) -> ClientResult<()>
where
    Backend: AuxStore,
    Hash: Clone + Encode,
    PHash: Encode,
{
    // TODO: prune the stale mappings.

    backend.insert_aux(
        &[
            (
                (LATEST_PRIMARY_HASH, best_domain_hash.clone())
                    .encode()
                    .as_slice(),
                latest_primary_hash.encode().as_slice(),
            ),
            (
                (BEST_DOMAIN_HASH, latest_primary_hash).encode().as_slice(),
                best_domain_hash.encode().as_slice(),
            ),
        ],
        vec![],
    )
}

pub(super) fn best_domain_hash_for<Backend, Hash, PHash>(
    backend: &Backend,
    primary_hash: &PHash,
) -> ClientResult<Option<Hash>>
where
    Backend: AuxStore,
    Hash: Decode,
    PHash: Encode,
{
    load_decode(
        backend,
        (BEST_DOMAIN_HASH, primary_hash).encode().as_slice(),
    )
}

pub(super) fn latest_consensus_block_hash_for<Backend, Hash, PHash>(
    backend: &Backend,
    domain_hash: &Hash,
) -> ClientResult<Option<PHash>>
where
    Backend: AuxStore,
    Hash: Encode,
    PHash: Decode,
{
    load_decode(
        backend,
        (LATEST_PRIMARY_HASH, domain_hash).encode().as_slice(),
    )
}

pub(super) fn consensus_block_hash_for<Backend, Hash, PHash>(
    backend: &Backend,
    domain_hash: Hash,
) -> ClientResult<Option<PHash>>
where
    Backend: AuxStore,
    Hash: Encode,
    PHash: Decode,
{
    load_decode(backend, (CONSENSUS_HASH, domain_hash).encode().as_slice())
}

// TODO: Unlock once domain test infra is workable again.
#[allow(dead_code)]
pub(super) fn target_receipt_is_pruned(
    head_receipt_number: BlockNumber,
    target_block: BlockNumber,
) -> bool {
    head_receipt_number.saturating_sub(target_block) >= PRUNING_DEPTH
}

/// Writes a bad execution receipt to aux storage.
pub(super) fn write_bad_receipt<Backend, CBlock>(
    backend: &Backend,
    bad_receipt_number: NumberFor<CBlock>,
    bad_receipt_hash: H256,
    trace_mismatch_info: (u32, CBlock::Hash),
) -> Result<(), ClientError>
where
    Backend: AuxStore,
    CBlock: BlockT,
{
    let bad_receipt_hashes_key = (BAD_RECEIPT_HASHES, bad_receipt_number).encode();
    let mut bad_receipt_hashes: Vec<H256> =
        load_decode(backend, bad_receipt_hashes_key.as_slice())?.unwrap_or_default();
    bad_receipt_hashes.push(bad_receipt_hash);

    let mut to_insert = vec![
        (bad_receipt_hashes_key, bad_receipt_hashes.encode()),
        (
            bad_receipt_mismatch_info_key(bad_receipt_hash),
            trace_mismatch_info.encode(),
        ),
    ];

    let mut bad_receipt_numbers: Vec<NumberFor<CBlock>> =
        load_decode(backend, BAD_RECEIPT_NUMBERS.encode().as_slice())?.unwrap_or_default();

    // The first bad receipt detected at this block number.
    if !bad_receipt_numbers.contains(&bad_receipt_number) {
        bad_receipt_numbers.push(bad_receipt_number);
        bad_receipt_numbers.sort_unstable();
        to_insert.push((BAD_RECEIPT_NUMBERS.encode(), bad_receipt_numbers.encode()));
    }

    backend.insert_aux(
        &to_insert
            .iter()
            .map(|(k, v)| (&k[..], &v[..]))
            .collect::<Vec<_>>()[..],
        vec![],
    )
}

pub(super) fn delete_bad_receipt<Backend: AuxStore>(
    backend: &Backend,
    block_number: BlockNumber,
    bad_receipt_hash: H256,
) -> Result<(), ClientError> {
    let bad_receipt_hashes_key = (BAD_RECEIPT_HASHES, block_number).encode();
    let mut hashes_at_block_number: Vec<H256> =
        load_decode(backend, bad_receipt_hashes_key.as_slice())?.unwrap_or_default();

    if let Some(index) = hashes_at_block_number
        .iter()
        .position(|&x| x == bad_receipt_hash)
    {
        hashes_at_block_number.swap_remove(index);
    } else {
        return Err(ClientError::Backend(format!(
            "Deleting an inexistent bad receipt {bad_receipt_hash:?}, available: {hashes_at_block_number:?}",
        )));
    }

    let mut keys_to_delete = vec![bad_receipt_mismatch_info_key(bad_receipt_hash)];

    let to_insert = if hashes_at_block_number.is_empty() {
        keys_to_delete.push(bad_receipt_hashes_key);

        let mut bad_receipt_numbers: Vec<BlockNumber> =
            load_decode(backend, BAD_RECEIPT_NUMBERS.encode().as_slice())?.ok_or_else(|| {
                ClientError::Backend("Stored bad receipt numbers must exist".into())
            })?;
        bad_receipt_numbers.retain(|x| *x != block_number);

        if bad_receipt_numbers.is_empty() {
            keys_to_delete.push(BAD_RECEIPT_NUMBERS.encode());

            vec![]
        } else {
            vec![(BAD_RECEIPT_NUMBERS.encode(), bad_receipt_numbers.encode())]
        }
    } else {
        vec![(bad_receipt_hashes_key, hashes_at_block_number.encode())]
    };

    backend.insert_aux(
        &to_insert
            .iter()
            .map(|(k, v)| (&k[..], &v[..]))
            .collect::<Vec<_>>()[..],
        &keys_to_delete.iter().map(|k| &k[..]).collect::<Vec<_>>()[..],
    )
}

fn delete_expired_bad_receipt_info_at<Backend: AuxStore, Number: Encode>(
    backend: &Backend,
    block_number: Number,
) -> Result<(), sp_blockchain::Error> {
    let bad_receipt_hashes_key = (BAD_RECEIPT_HASHES, block_number).encode();

    let bad_receipt_hashes: Vec<H256> =
        load_decode(backend, bad_receipt_hashes_key.as_slice())?.unwrap_or_default();

    let keys_to_delete = bad_receipt_hashes
        .into_iter()
        .map(bad_receipt_mismatch_info_key)
        .chain(std::iter::once(bad_receipt_hashes_key))
        .collect::<Vec<_>>();

    backend.insert_aux(
        [],
        &keys_to_delete.iter().map(|k| &k[..]).collect::<Vec<_>>()[..],
    )
}

/// Bad receipts which are older than `oldest_receipt_number` are expired and will be pruned.
pub(super) fn prune_expired_bad_receipts<Backend, Number>(
    backend: &Backend,
    oldest_receipt_number: Number,
) -> Result<(), ClientError>
where
    Backend: AuxStore,
    Number: Encode + Decode + Copy + std::fmt::Debug + Copy + PartialOrd,
{
    let mut bad_receipt_numbers: Vec<Number> =
        load_decode(backend, BAD_RECEIPT_NUMBERS.encode().as_slice())?.unwrap_or_default();

    let expired_receipt_numbers = bad_receipt_numbers
        .drain_filter(|number| *number < oldest_receipt_number)
        .collect::<Vec<_>>();

    if !expired_receipt_numbers.is_empty() {
        // The bad receipt had been pruned on consensus chain, i.e., _finalized_.
        tracing::error!(
            ?oldest_receipt_number,
            ?expired_receipt_numbers,
            "Bad receipt(s) had been pruned on consensus chain"
        );

        for expired_receipt_number in expired_receipt_numbers {
            if let Err(e) = delete_expired_bad_receipt_info_at(backend, expired_receipt_number) {
                tracing::error!(error = ?e, "Failed to remove the expired bad receipt");
            }
        }

        if bad_receipt_numbers.is_empty() {
            backend.insert_aux(&[], &[BAD_RECEIPT_NUMBERS.encode().as_slice()])?;
        } else {
            backend.insert_aux(
                &[(
                    BAD_RECEIPT_NUMBERS.encode().as_slice(),
                    bad_receipt_numbers.encode().as_slice(),
                )],
                &[],
            )?;
        }
    }

    Ok(())
}

/// Returns the first unconfirmed bad receipt info necessary for building a fraud proof if any.
pub(super) fn find_first_unconfirmed_bad_receipt_info<Backend, Block, CBlock, F>(
    backend: &Backend,
    canonical_consensus_hash_at: F,
) -> Result<Option<(H256, u32, CBlock::Hash)>, ClientError>
where
    Backend: AuxStore + HeaderBackend<Block>,
    Block: BlockT,
    CBlock: BlockT,
    F: Fn(NumberFor<CBlock>) -> sp_blockchain::Result<CBlock::Hash>,
{
    let bad_receipt_numbers: Vec<NumberFor<CBlock>> =
        load_decode(backend, BAD_RECEIPT_NUMBERS.encode().as_slice())?.unwrap_or_default();

    for bad_receipt_number in bad_receipt_numbers {
        let bad_receipt_hashes_key = (BAD_RECEIPT_HASHES, bad_receipt_number).encode();
        let bad_receipt_hashes: Vec<H256> =
            load_decode(backend, bad_receipt_hashes_key.as_slice())?.unwrap_or_default();

        let canonical_consensus_hash = canonical_consensus_hash_at(bad_receipt_number)?;

        for bad_receipt_hash in bad_receipt_hashes.iter() {
            let (trace_mismatch_index, consensus_block_hash): (u32, CBlock::Hash) = load_decode(
                backend,
                bad_receipt_mismatch_info_key(bad_receipt_hash).as_slice(),
            )?
            .ok_or_else(|| {
                ClientError::Backend(format!(
                    "Trace mismatch info not found for `bad_receipt_hash`: {bad_receipt_hash:?}"
                ))
            })?;

            if consensus_block_hash == canonical_consensus_hash {
                return Ok(Some((
                    *bad_receipt_hash,
                    trace_mismatch_index,
                    consensus_block_hash,
                )));
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain_test_service::evm_domain_test_runtime::Block;
    use sc_client_api::backend::NewBlockState;
    use sc_client_api::{Backend, BlockImportOperation};
    use sp_core::hash::H256;
    use sp_runtime::traits::Header as HeaderT;
    use std::collections::HashSet;
    use std::sync::Mutex;
    use subspace_runtime_primitives::{BlockNumber, Hash};
    use subspace_test_runtime::Block as CBlock;
    // TODO: Remove `substrate_test_runtime_client` dependency for faster build time
    use substrate_test_runtime_client::{DefaultTestClientBuilderExt, TestClientBuilderExt};

    type ExecutionReceipt = sp_domains::ExecutionReceipt<BlockNumber, Hash, BlockNumber, Hash>;

    fn create_execution_receipt(consensus_block_number: BlockNumber) -> ExecutionReceipt {
        ExecutionReceipt {
            consensus_block_number,
            consensus_block_hash: H256::random(),
            domain_block_number: consensus_block_number,
            domain_hash: H256::random(),
            trace: Default::default(),
            trace_root: Default::default(),
        }
    }

    fn insert_header(
        backend: &substrate_test_runtime_client::Backend,
        number: u64,
        parent_hash: H256,
    ) -> H256 {
        let header = substrate_test_runtime_client::runtime::Header::new(
            number,
            Hash::random(),
            Hash::random(),
            parent_hash,
            Default::default(),
        );

        let header_hash = header.hash();
        let mut op = backend.begin_operation().unwrap();
        op.set_block_data(header, None, None, None, NewBlockState::Normal)
            .unwrap();
        backend.commit_operation(op).unwrap();
        header_hash
    }

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

    // TODO: Un-ignore once test client is fixed and working again on Windows
    #[test]
    #[ignore]
    fn write_delete_prune_bad_receipt_works() {
        struct ConsensusNumberHashMappings(Mutex<Vec<(u32, Hash)>>);

        impl ConsensusNumberHashMappings {
            fn insert_number_to_hash_mapping(&self, block_number: u32, block_hash: Hash) {
                let mut mappings = self.0.lock().unwrap();
                if !mappings.contains(&(block_number, block_hash)) {
                    mappings.push((block_number, block_hash));
                }
            }

            fn canonical_hash(&self, block_number: u32) -> Option<Hash> {
                self.0.lock().unwrap().iter().find_map(|(number, hash)| {
                    if *number == block_number {
                        Some(*hash)
                    } else {
                        None
                    }
                })
            }
        }

        let (client, backend) =
            substrate_test_runtime_client::TestClientBuilder::new().build_with_backend();

        let consensus_client = ConsensusNumberHashMappings(Mutex::new(Vec::new()));

        let bad_receipts_at = |number: BlockNumber| -> Option<HashSet<Hash>> {
            let bad_receipt_hashes_key = (BAD_RECEIPT_HASHES, number).encode();
            load_decode(&client, bad_receipt_hashes_key.as_slice())
                .unwrap()
                .map(|v: Vec<Hash>| v.into_iter().collect())
        };

        let trace_mismatch_info_for = |receipt_hash| -> Option<(u32, Hash)> {
            load_decode(
                &client,
                bad_receipt_mismatch_info_key(receipt_hash).as_slice(),
            )
            .unwrap()
        };

        let bad_receipt_numbers = || -> Option<Vec<BlockNumber>> {
            load_decode(&client, BAD_RECEIPT_NUMBERS.encode().as_slice()).unwrap()
        };

        let first_unconfirmed_bad_receipt_info =
            |oldest_receipt_number: BlockNumber| -> Option<(H256, u32, Hash)> {
                // Always check and prune the expired bad receipts before loading the first unconfirmed one.
                prune_expired_bad_receipts(&client, oldest_receipt_number).unwrap();
                find_first_unconfirmed_bad_receipt_info::<_, _, CBlock, _>(&client, |height| {
                    Ok(consensus_client.canonical_hash(height).unwrap())
                })
                .unwrap()
            };

        let (bad_receipt_hash1, block_hash1) = (
            Hash::random(),
            insert_header(backend.as_ref(), 1u64, client.info().genesis_hash),
        );
        let (bad_receipt_hash2, block_hash2) = (
            Hash::random(),
            insert_header(backend.as_ref(), 2u64, block_hash1),
        );
        let (bad_receipt_hash3, block_hash3) = (
            Hash::random(),
            insert_header(backend.as_ref(), 3u64, block_hash2),
        );

        consensus_client.insert_number_to_hash_mapping(10, block_hash1);
        write_bad_receipt::<_, CBlock>(&client, 10, bad_receipt_hash1, (1, block_hash1)).unwrap();
        assert_eq!(bad_receipt_numbers(), Some(vec![10]));
        consensus_client.insert_number_to_hash_mapping(10, block_hash2);
        write_bad_receipt::<_, CBlock>(&client, 10, bad_receipt_hash2, (2, block_hash2)).unwrap();
        assert_eq!(bad_receipt_numbers(), Some(vec![10]));
        consensus_client.insert_number_to_hash_mapping(10, block_hash3);
        write_bad_receipt::<_, CBlock>(&client, 10, bad_receipt_hash3, (3, block_hash3)).unwrap();
        assert_eq!(bad_receipt_numbers(), Some(vec![10]));

        let (bad_receipt_hash4, block_hash4) = (
            Hash::random(),
            insert_header(backend.as_ref(), 4u64, block_hash3),
        );
        consensus_client.insert_number_to_hash_mapping(20, block_hash4);
        write_bad_receipt::<_, CBlock>(&client, 20, bad_receipt_hash4, (1, block_hash4)).unwrap();
        assert_eq!(bad_receipt_numbers(), Some(vec![10, 20]));

        assert_eq!(
            trace_mismatch_info_for(bad_receipt_hash1).unwrap(),
            (1, block_hash1)
        );
        assert_eq!(
            trace_mismatch_info_for(bad_receipt_hash2).unwrap(),
            (2, block_hash2)
        );
        assert_eq!(
            trace_mismatch_info_for(bad_receipt_hash3).unwrap(),
            (3, block_hash3)
        );
        assert_eq!(
            first_unconfirmed_bad_receipt_info(1),
            Some((bad_receipt_hash1, 1, block_hash1))
        );

        assert_eq!(
            bad_receipts_at(10).unwrap(),
            [bad_receipt_hash1, bad_receipt_hash2, bad_receipt_hash3].into(),
        );
        assert_eq!(bad_receipts_at(20).unwrap(), [bad_receipt_hash4].into());

        assert!(delete_bad_receipt(&client, 10, bad_receipt_hash1).is_ok());
        assert_eq!(bad_receipt_numbers(), Some(vec![10, 20]));
        assert!(trace_mismatch_info_for(bad_receipt_hash1).is_none());
        assert_eq!(
            bad_receipts_at(10).unwrap(),
            [bad_receipt_hash2, bad_receipt_hash3].into()
        );

        assert!(delete_bad_receipt(&client, 10, bad_receipt_hash2).is_ok());
        assert_eq!(bad_receipt_numbers(), Some(vec![10, 20]));
        assert!(trace_mismatch_info_for(bad_receipt_hash2).is_none());
        assert_eq!(bad_receipts_at(10).unwrap(), [bad_receipt_hash3].into());

        assert!(delete_bad_receipt(&client, 10, bad_receipt_hash3).is_ok());
        assert_eq!(bad_receipt_numbers(), Some(vec![20]));
        assert!(trace_mismatch_info_for(bad_receipt_hash3).is_none());
        assert!(bad_receipts_at(10).is_none());
        assert_eq!(
            first_unconfirmed_bad_receipt_info(1),
            Some((bad_receipt_hash4, 1, block_hash4))
        );

        assert!(delete_bad_receipt(&client, 20, bad_receipt_hash4).is_ok());
        assert_eq!(first_unconfirmed_bad_receipt_info(20), None);

        let (bad_receipt_hash5, block_hash5) = (
            Hash::random(),
            insert_header(backend.as_ref(), 5u64, block_hash4),
        );
        consensus_client.insert_number_to_hash_mapping(30, block_hash5);
        write_bad_receipt::<_, CBlock>(&client, 30, bad_receipt_hash5, (1, block_hash5)).unwrap();
        assert_eq!(bad_receipt_numbers(), Some(vec![30]));
        assert_eq!(bad_receipts_at(30).unwrap(), [bad_receipt_hash5].into());
        // Expired bad receipts will be removed.
        assert_eq!(first_unconfirmed_bad_receipt_info(31), None);
        assert_eq!(bad_receipt_numbers(), None);
        assert!(bad_receipts_at(30).is_none());
    }
}
