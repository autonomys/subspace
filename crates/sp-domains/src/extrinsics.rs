#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use domain_runtime_primitives::opaque::AccountId;
use rand_chacha::ChaCha8Rng;
use rand_core::{Rng, SeedableRng};
use sp_state_machine::trace;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::collections::vec_deque::VecDeque;
use sp_std::fmt::Debug;
use subspace_core_primitives::Randomness;

pub fn deduplicate_and_shuffle_extrinsics<Extrinsic>(
    mut extrinsics: Vec<(Option<AccountId>, Extrinsic)>,
    shuffling_seed: Randomness,
) -> VecDeque<Extrinsic>
where
    Extrinsic: Debug + PartialEq + Clone,
{
    let mut seen = Vec::new();
    extrinsics.retain(|(_, uxt)| match seen.contains(uxt) {
        true => {
            trace!(extrinsic = ?uxt, "Duplicated extrinsic");
            false
        }
        false => {
            seen.push(uxt.clone());
            true
        }
    });
    drop(seen);
    trace!(?extrinsics, "Origin deduplicated extrinsics");
    shuffle_extrinsics::<Extrinsic, AccountId>(extrinsics, shuffling_seed)
}

/// Shuffles the extrinsics in a deterministic way.
///
/// The extrinsics are grouped by the signer. The extrinsics without a signer, i.e., unsigned
/// extrinsics, are considered as a special group. The items in different groups are cross shuffled,
/// while the order of items inside the same group is still maintained.
pub fn shuffle_extrinsics<Extrinsic: Debug, AccountId: Ord + Clone>(
    extrinsics: Vec<(Option<AccountId>, Extrinsic)>,
    shuffling_seed: Randomness,
) -> VecDeque<Extrinsic> {
    let mut rng = ChaCha8Rng::from_seed(*shuffling_seed);

    let mut positions = extrinsics
        .iter()
        .map(|(maybe_signer, _)| maybe_signer)
        .cloned()
        .collect::<Vec<_>>();

    shuffle(&mut positions, &mut rng);

    let mut grouped_extrinsics: BTreeMap<Option<AccountId>, VecDeque<_>> = extrinsics
        .into_iter()
        .fold(BTreeMap::new(), |mut groups, (maybe_signer, tx)| {
            groups.entry(maybe_signer).or_default().push_back(tx);
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
        .collect::<VecDeque<_>>();

    trace!(?shuffled_extrinsics, "Shuffled extrinsics");

    shuffled_extrinsics
}

/// Shuffles the slice using Fisher–Yates algorithm.
///
/// This is a consensus-critical function that must produce exactly the same output as
/// `SliceRandom::shuffle()` from `rand` 0.8 did, independently of the `rand` version in use.
fn shuffle<T>(slice: &mut [T], rng: &mut ChaCha8Rng) {
    for i in (1..slice.len()).rev() {
        // Invariant: elements with index > i have been locked in place
        slice.swap(i, gen_index(rng, i + 1));
    }
}

/// Uniformly samples an index in `0..ubound` using widening multiplication with rejection.
fn gen_index(rng: &mut ChaCha8Rng, ubound: usize) -> usize {
    if let Ok(ubound) = u32::try_from(ubound) {
        let zone = (ubound << ubound.leading_zeros()).wrapping_sub(1);
        loop {
            let product = u64::from(rng.next_u32()) * u64::from(ubound);
            if product as u32 <= zone {
                return (product >> u32::BITS) as usize;
            }
        }
    } else {
        let ubound = ubound as u64;
        let zone = (ubound << ubound.leading_zeros()).wrapping_sub(1);
        loop {
            let product = u128::from(rng.next_u64()) * u128::from(ubound);
            if product as u64 <= zone {
                return (product >> u64::BITS) as usize;
            }
        }
    }
}
