//! Schema for executor in the aux-db.

use crate::ExecutionReceiptFor;
use parity_scale_codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sp_blockchain::{Error as ClientError, HeaderBackend, Result as ClientResult};
use sp_domains::bundle::InvalidBundleType;
use sp_runtime::Saturating;
use sp_runtime::traits::{
    Block as BlockT, CheckedMul, CheckedSub, NumberFor, One, SaturatedConversion, Zero,
};
use std::collections::BTreeSet;
use std::sync::Arc;
use subspace_core_primitives::BlockNumber;
use subspace_runtime_primitives::{BlockHashFor, DOMAINS_PRUNING_DEPTH_MULTIPLIER};

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

/// Tracks a domain block hash and consensus block hash from which domain block is derived from
/// at a given domain block height.
const BEST_DOMAIN_HASH_KEYS: &[u8] = b"best_domain_hash_keys";

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
    oldest_unconfirmed_receipt_number: Option<NumberFor<Block>>,
    execution_receipt: &ExecutionReceiptFor<Block, CBlock>,
    challenge_period: NumberFor<CBlock>,
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
            .unwrap_or(Zero::zero());

    let mut new_first_saved_receipt = first_saved_receipt;

    let mut keys_to_delete = vec![];

    if let Some(pruning_block_number) =
        challenge_period.checked_mul(&DOMAINS_PRUNING_DEPTH_MULTIPLIER.saturated_into())
    {
        // Delete ER that have confirmed long time ago
        if let Some(delete_receipts_to) = oldest_unconfirmed_receipt_number
            .map(|oldest_unconfirmed_receipt_number| {
                oldest_unconfirmed_receipt_number.saturating_sub(One::one())
            })
            .and_then(|latest_confirmed_receipt_number| {
                latest_confirmed_receipt_number
                    .saturated_into::<BlockNumber>()
                    .checked_sub(pruning_block_number.saturated_into())
            })
        {
            new_first_saved_receipt =
                Into::<NumberFor<CBlock>>::into(delete_receipts_to) + One::one();
            for receipt_to_delete in first_saved_receipt.saturated_into()..=delete_receipts_to {
                let delete_block_number_key =
                    (EXECUTION_RECEIPT_BLOCK_NUMBER, receipt_to_delete).encode();

                if let Some(hashes_to_delete) = load_decode::<_, Vec<CBlock::Hash>>(
                    backend,
                    delete_block_number_key.as_slice(),
                )? {
                    keys_to_delete.extend(
                        hashes_to_delete
                            .into_iter()
                            .map(|h| (EXECUTION_RECEIPT, h).encode()),
                    );
                    keys_to_delete.push(delete_block_number_key);
                }
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

type MaybeTrackedDomainHashes<Block, CBlock> =
    Option<BTreeSet<(BlockHashFor<Block>, BlockHashFor<CBlock>)>>;

fn get_tracked_domain_hash_keys<Backend, Block, CBlock>(
    backend: &Backend,
    domain_block_number: NumberFor<Block>,
) -> ClientResult<MaybeTrackedDomainHashes<Block, CBlock>>
where
    Backend: AuxStore,
    Block: BlockT,
    CBlock: BlockT,
{
    load_decode(
        backend,
        (BEST_DOMAIN_HASH_KEYS, domain_block_number)
            .encode()
            .as_slice(),
    )
}

pub(super) fn track_domain_hash_and_consensus_hash<Client, Block, CBlock>(
    domain_client: &Arc<Client>,
    best_domain_hash: Block::Hash,
    latest_consensus_hash: CBlock::Hash,
    cleanup: bool,
) -> ClientResult<()>
where
    Client: HeaderBackend<Block> + AuxStore,
    CBlock: BlockT,
    Block: BlockT,
{
    let best_domain_number =
        domain_client
            .number(best_domain_hash)?
            .ok_or(sp_blockchain::Error::MissingHeader(format!(
                "Block hash: {best_domain_hash:?}"
            )))?;
    let mut domain_hash_keys =
        get_tracked_domain_hash_keys::<_, Block, CBlock>(&**domain_client, best_domain_number)?
            .unwrap_or_default();

    domain_hash_keys.insert((best_domain_hash, latest_consensus_hash));

    domain_client.insert_aux(
        &[
            (
                (LATEST_CONSENSUS_HASH, best_domain_hash)
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
            (
                (BEST_DOMAIN_HASH_KEYS, best_domain_number)
                    .encode()
                    .as_slice(),
                domain_hash_keys.encode().as_slice(),
            ),
        ],
        vec![],
    )?;

    if cleanup {
        cleanup_domain_hash_and_consensus_hash::<_, Block, CBlock>(domain_client)?;
    }

    Ok(())
}

fn cleanup_domain_hash_and_consensus_hash<Client, Block, CBlock>(
    domain_client: &Arc<Client>,
) -> ClientResult<()>
where
    CBlock: BlockT,
    Block: BlockT,
    Client: HeaderBackend<Block> + AuxStore,
{
    let mut finalized_domain_number = domain_client.info().finalized_number;

    let mut deletions = vec![];
    while finalized_domain_number > Zero::zero()
        // exit early if there are not tracked hashes for this finalized block number.
        && let Some(domain_hash_keys) = &get_tracked_domain_hash_keys::<_, Block, CBlock>(
            &**domain_client,
            finalized_domain_number,
        )?
    {
        domain_hash_keys
            .iter()
            .for_each(|(domain_hash, consensus_hash)| {
                deletions.push((LATEST_CONSENSUS_HASH, domain_hash).encode());
                deletions.push((BEST_DOMAIN_HASH, consensus_hash).encode())
            });

        deletions.push((BEST_DOMAIN_HASH_KEYS, finalized_domain_number).encode());

        finalized_domain_number = match finalized_domain_number.checked_sub(&One::one()) {
            None => break,
            Some(number) => number,
        }
    }

    domain_client.insert_aux(
        [],
        &deletions
            .iter()
            .map(|key| key.as_slice())
            .collect::<Vec<_>>(),
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

/// Different kinds of bundle mismatches.
#[derive(Encode, Decode, Debug, PartialEq)]
pub(super) enum BundleMismatchType {
    /// The fraud proof needs to prove the bundle is invalid with `InvalidBundleType`,
    /// because the bundle is actually an invalid bundle, but it is either marked as valid,
    /// or as a lower priority invalid type.
    GoodInvalid(InvalidBundleType),
    /// The fraud proof needs to prove the `InvalidBundleType` is incorrect,
    /// because the bundle type is either valid, or a lower priority invalid type.
    BadInvalid(InvalidBundleType),
    /// The fraud proof needs to prove the valid bundle contents are incorrect,
    /// because the bundles are both valid, but their contents are different.
    ValidBundleContents,
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain_test_service::evm_domain_test_runtime::Block;
    use parking_lot::Mutex;
    use sp_core::hash::H256;
    use std::collections::HashMap;
    use subspace_runtime_primitives::{Balance, Hash};
    use subspace_test_runtime::Block as CBlock;

    const PRUNING_DEPTH: BlockNumber = 1000;

    type ExecutionReceipt = sp_domains::execution_receipt::ExecutionReceipt<
        BlockNumber,
        Hash,
        BlockNumber,
        Hash,
        Balance,
    >;

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
            block_fees: Default::default(),
            transfers: Default::default(),
        }
    }

    #[derive(Default)]
    struct TestClient(Mutex<HashMap<Vec<u8>, Vec<u8>>>);

    impl AuxStore for TestClient {
        fn insert_aux<
            'a,
            'b: 'a,
            'c: 'a,
            I: IntoIterator<Item = &'a (&'c [u8], &'c [u8])>,
            D: IntoIterator<Item = &'a &'b [u8]>,
        >(
            &self,
            insert: I,
            delete: D,
        ) -> sp_blockchain::Result<()> {
            let mut map = self.0.lock();
            for d in delete {
                map.remove(&d.to_vec());
            }
            for (k, v) in insert {
                map.insert(k.to_vec(), v.to_vec());
            }
            Ok(())
        }

        fn get_aux(&self, key: &[u8]) -> sp_blockchain::Result<Option<Vec<u8>>> {
            Ok(self.0.lock().get(key).cloned())
        }
    }

    #[test]
    fn normal_prune_execution_receipt_works() {
        let block_tree_pruning_depth = 256;
        let challenge_period = 500;
        let client = TestClient::default();

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

        let target_receipt_is_pruned = |number: BlockNumber| hashes_at(number).is_none();

        let receipt_at = |consensus_block_hash: Hash| {
            load_execution_receipt::<_, Block, CBlock>(&client, consensus_block_hash).unwrap()
        };

        let write_receipt_at = |oldest_unconfirmed_receipt_number: Option<BlockNumber>,
                                receipt: &ExecutionReceipt| {
            write_execution_receipt::<_, Block, CBlock>(
                &client,
                oldest_unconfirmed_receipt_number,
                receipt,
                challenge_period,
            )
            .unwrap()
        };

        assert_eq!(receipt_start(), None);

        // Create as many ER as before any ER being pruned yet
        let receipt_count = PRUNING_DEPTH + block_tree_pruning_depth - 1;
        let block_hash_list = (1..=receipt_count)
            .map(|block_number| {
                let receipt = create_execution_receipt(block_number);
                let consensus_block_hash = receipt.consensus_block_hash;
                let oldest_unconfirmed_receipt_number = block_number
                    .checked_sub(block_tree_pruning_depth)
                    .map(|n| n + 1);
                write_receipt_at(oldest_unconfirmed_receipt_number, &receipt);
                assert_eq!(receipt_at(consensus_block_hash), Some(receipt));
                assert_eq!(hashes_at(block_number), Some(vec![consensus_block_hash]));
                // No ER have been pruned yet
                assert_eq!(receipt_start(), Some(0));
                consensus_block_hash
            })
            .collect::<Vec<_>>();

        assert_eq!(receipt_start(), Some(0));
        assert!(!target_receipt_is_pruned(1));

        // Create `receipt_count + 1` receipt, `oldest_unconfirmed_receipt_number` is `PRUNING_DEPTH + 1`.
        let receipt = create_execution_receipt(receipt_count + 1);
        assert!(receipt_at(receipt.consensus_block_hash).is_none());
        write_receipt_at(Some(PRUNING_DEPTH + 1), &receipt);
        assert!(receipt_at(receipt.consensus_block_hash).is_some());
        assert_eq!(receipt_start(), Some(1));

        // Create `receipt_count + 2` receipt, `oldest_unconfirmed_receipt_number` is `PRUNING_DEPTH + 2`.
        let receipt = create_execution_receipt(receipt_count + 2);
        write_receipt_at(Some(PRUNING_DEPTH + 2), &receipt);
        assert!(receipt_at(receipt.consensus_block_hash).is_some());

        // ER of block #1 should be pruned, its block number mapping should be pruned as well.
        assert!(receipt_at(block_hash_list[0]).is_none());
        assert!(hashes_at(1).is_none());
        assert!(target_receipt_is_pruned(1));
        assert_eq!(receipt_start(), Some(2));

        // Create `receipt_count + 3` receipt, `oldest_unconfirmed_receipt_number` is `PRUNING_DEPTH + 3`.
        let receipt = create_execution_receipt(receipt_count + 3);
        let consensus_block_hash1 = receipt.consensus_block_hash;
        write_receipt_at(Some(PRUNING_DEPTH + 3), &receipt);
        assert!(receipt_at(consensus_block_hash1).is_some());
        // ER of block #2 should be pruned.
        assert!(receipt_at(block_hash_list[1]).is_none());
        assert!(target_receipt_is_pruned(2));
        assert!(!target_receipt_is_pruned(3));
        assert_eq!(receipt_start(), Some(3));

        // Multiple hashes attached to the block #`receipt_count + 3`
        let receipt = create_execution_receipt(receipt_count + 3);
        let consensus_block_hash2 = receipt.consensus_block_hash;
        write_receipt_at(Some(PRUNING_DEPTH + 3), &receipt);
        assert!(receipt_at(consensus_block_hash2).is_some());
        assert_eq!(
            hashes_at(receipt_count + 3),
            Some(vec![consensus_block_hash1, consensus_block_hash2])
        );
        // No ER pruned since the `oldest_unconfirmed_receipt_number` is the same
        assert!(!target_receipt_is_pruned(3));
        assert_eq!(receipt_start(), Some(3));
    }

    #[test]
    fn execution_receipts_should_be_kept_against_oldest_unconfirmed_receipt_number() {
        let block_tree_pruning_depth = 256;
        let challenge_period = 500;
        let client = TestClient::default();

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

        let write_receipt_at = |oldest_unconfirmed_receipt_number: Option<BlockNumber>,
                                receipt: &ExecutionReceipt| {
            write_execution_receipt::<_, Block, CBlock>(
                &client,
                oldest_unconfirmed_receipt_number,
                receipt,
                challenge_period,
            )
            .unwrap()
        };

        let target_receipt_is_pruned = |number: BlockNumber| hashes_at(number).is_none();

        assert_eq!(receipt_start(), None);

        // Create as many ER as before any ER being pruned yet, `oldest_unconfirmed_receipt_number` is `Some(1)`,
        // i.e., no receipt has ever been confirmed/pruned on consensus chain.
        let receipt_count = PRUNING_DEPTH + block_tree_pruning_depth - 1;

        let block_hash_list = (1..=receipt_count)
            .map(|block_number| {
                let receipt = create_execution_receipt(block_number);
                let consensus_block_hash = receipt.consensus_block_hash;
                write_receipt_at(Some(One::one()), &receipt);
                assert_eq!(receipt_at(consensus_block_hash), Some(receipt));
                assert_eq!(hashes_at(block_number), Some(vec![consensus_block_hash]));
                // No ER have been pruned yet
                assert_eq!(receipt_start(), Some(0));
                consensus_block_hash
            })
            .collect::<Vec<_>>();

        assert_eq!(receipt_start(), Some(0));
        assert!(!target_receipt_is_pruned(1));

        // Create `receipt_count + 1` receipt, `oldest_unconfirmed_receipt_number` is `Some(1)`.
        let receipt = create_execution_receipt(receipt_count + 1);
        assert!(receipt_at(receipt.consensus_block_hash).is_none());
        write_receipt_at(Some(One::one()), &receipt);

        // Create `receipt_count + 2` receipt, `oldest_unconfirmed_receipt_number` is `Some(1)`.
        let receipt = create_execution_receipt(receipt_count + 2);
        write_receipt_at(Some(One::one()), &receipt);

        // ER of block #1 and its block number mapping should not be pruned even the size of stored
        // receipts exceeds the pruning depth.
        assert!(receipt_at(block_hash_list[0]).is_some());
        assert!(hashes_at(1).is_some());
        assert!(!target_receipt_is_pruned(1));
        assert_eq!(receipt_start(), Some(0));

        // Create `receipt_count + 3` receipt, `oldest_unconfirmed_receipt_number` is `Some(1)`.
        let receipt = create_execution_receipt(receipt_count + 3);
        write_receipt_at(Some(One::one()), &receipt);

        // Create `receipt_count + 4` receipt, `oldest_unconfirmed_receipt_number` is `Some(PRUNING_DEPTH + 4)`.
        let receipt = create_execution_receipt(receipt_count + 4);
        write_receipt_at(
            Some(PRUNING_DEPTH + 4), // Now assuming all the missing receipts are confirmed.
            &receipt,
        );
        assert!(receipt_at(block_hash_list[0]).is_none());
        // receipt and block number mapping for [1, 2, 3] should be pruned.
        (1..=3).for_each(|pruned| {
            assert!(hashes_at(pruned).is_none());
            assert!(target_receipt_is_pruned(pruned));
        });
        assert_eq!(receipt_start(), Some(4));
    }
}
