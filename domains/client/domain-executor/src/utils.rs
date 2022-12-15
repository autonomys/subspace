use domain_runtime_primitives::AccountId;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sc_consensus::ForkChoiceStrategy;
use sc_executor_common::error::WasmError;
use sc_executor_common::runtime_blob::RuntimeBlob;
use sp_consensus_slots::Slot;
use sp_domains::{DomainId, OpaqueBundles, SignedOpaqueBundles};
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::collections::{BTreeMap, VecDeque};
use std::convert::TryInto;
use std::fmt::Debug;
use subspace_core_primitives::{Blake2b256Hash, BlockNumber, Randomness};

pub(super) enum DomainBundles<Block, PBlock>
where
    Block: BlockT,
    PBlock: BlockT,
{
    System(
        OpaqueBundles<PBlock, Block::Hash>,
        SignedOpaqueBundles<PBlock, Block::Hash>,
    ),
    Core(OpaqueBundles<PBlock, Block::Hash>),
}

/// Data required to produce bundles on executor node.
#[derive(PartialEq, Clone, Debug)]
pub(super) struct ExecutorSlotInfo {
    /// Slot
    pub(super) slot: Slot,
    /// Global challenge
    pub(super) global_challenge: Blake2b256Hash,
}

/// An event telling the `Overseer` on the particular block
/// that has been imported or finalized.
///
/// This structure exists solely for the purposes of decoupling
/// `Overseer` code from the client code and the necessity to call
/// `HeaderBackend::block_number_from_id()`.
#[derive(Debug, Clone)]
pub struct BlockInfo<Block>
where
    Block: BlockT,
{
    /// hash of the block.
    pub hash: Block::Hash,
    /// hash of the parent block.
    pub parent_hash: Block::Hash,
    /// block's number.
    pub number: NumberFor<Block>,
    /// Fork choice of the block.
    pub fork_choice: ForkChoiceStrategy,
}

/// Converts the block number from the generic type `N1` to `N2`.
pub(crate) fn translate_number_type<N1, N2>(block_number: N1) -> N2
where
    N1: TryInto<BlockNumber>,
    N2: From<BlockNumber>,
{
    N2::from(to_number_primitive(block_number))
}

/// Converts a generic block number to a concrete primitive block number.
pub(crate) fn to_number_primitive<N>(block_number: N) -> BlockNumber
where
    N: TryInto<BlockNumber>,
{
    block_number
        .try_into()
        .unwrap_or_else(|_| panic!("Block number must fit into u32; qed"))
}

/// Shuffles the extrinsics in a deterministic way.
///
/// The extrinsics are grouped by the signer. The extrinsics without a signer, i.e., unsigned
/// extrinsics, are considered as a special group. The items in different groups are cross shuffled,
/// while the order of items inside the same group is still maintained.
pub(crate) fn shuffle_extrinsics<Extrinsic: Debug>(
    extrinsics: Vec<(Option<AccountId>, Extrinsic)>,
    shuffling_seed: Randomness,
) -> Vec<Extrinsic> {
    let mut rng = ChaCha8Rng::from_seed(shuffling_seed);

    let mut positions = extrinsics
        .iter()
        .map(|(maybe_signer, _)| maybe_signer)
        .cloned()
        .collect::<Vec<_>>();

    // Shuffles the positions using Fisher–Yates algorithm.
    positions.shuffle(&mut rng);

    let mut grouped_extrinsics: BTreeMap<Option<AccountId>, VecDeque<_>> = extrinsics
        .into_iter()
        .fold(BTreeMap::new(), |mut groups, (maybe_signer, tx)| {
            groups
                .entry(maybe_signer)
                .or_insert_with(VecDeque::new)
                .push_back(tx);
            groups
        });

    // The relative ordering for the items in the same group does not change.
    let shuffled_extrinsics = positions
        .into_iter()
        .map(|maybe_signer| {
            grouped_extrinsics
                .get_mut(&maybe_signer)
                .expect("Extrinsics are grouped correctly; qed")
                .pop_front()
                .expect("Extrinsic definitely exists as it's correctly grouped above; qed")
        })
        .collect::<Vec<_>>();

    tracing::trace!(?shuffled_extrinsics, "Shuffled extrinsics");

    shuffled_extrinsics
}

pub(crate) fn read_core_domain_runtime_blob(
    system_domain_bundle: &[u8],
    core_domain_id: DomainId,
) -> Result<Vec<u8>, WasmError> {
    let system_runtime_blob = RuntimeBlob::new(system_domain_bundle)?;

    let section_contents_name = core_domain_id.link_section_name();
    let embedded_runtime_blob = system_runtime_blob
        .custom_section_contents(&section_contents_name)
        .ok_or_else(|| {
            WasmError::Other(format!("Custom section {section_contents_name} not found"))
        })?;

    Ok(embedded_runtime_blob.to_vec())
}

#[cfg(test)]
mod tests {
    use super::shuffle_extrinsics;
    use sp_keyring::sr25519::Keyring;
    use sp_runtime::traits::{BlakeTwo256, Hash as HashT};

    #[test]
    fn shuffle_extrinsics_should_work() {
        let alice = Keyring::Alice.to_account_id();
        let bob = Keyring::Bob.to_account_id();
        let charlie = Keyring::Charlie.to_account_id();

        let extrinsics = vec![
            (Some(alice.clone()), 10),
            (None, 100),
            (Some(bob.clone()), 1),
            (Some(bob), 2),
            (Some(charlie.clone()), 30),
            (Some(alice.clone()), 11),
            (Some(charlie), 31),
            (None, 101),
            (None, 102),
            (Some(alice), 12),
        ];

        let dummy_seed = BlakeTwo256::hash_of(&[1u8; 64]).into();
        let shuffled_extrinsics = shuffle_extrinsics(extrinsics, dummy_seed);

        assert_eq!(
            shuffled_extrinsics,
            vec![100, 30, 10, 1, 11, 101, 31, 12, 102, 2]
        );
    }
}
