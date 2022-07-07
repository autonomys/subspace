use core::mem;
use schnorrkel::vrf::VRFOutput;
use schnorrkel::SignatureResult;
use sp_arithmetic::traits::SaturatedConversion;
use subspace_core_primitives::{
    crypto, Randomness, Salt, Tag, TagSignature, RANDOMNESS_CONTEXT, RANDOMNESS_LENGTH,
    SALT_HASHING_PREFIX, SALT_SIZE,
};
use subspace_solving::create_tag_signature_transcript;

/// Derive randomness from tag signature.
///
/// NOTE: If you are not the signer then you must verify the local challenge before calling this
/// function.
pub fn derive_randomness<PublicKey>(
    public_key: &PublicKey,
    tag: Tag,
    tag_signature: &TagSignature,
) -> SignatureResult<Randomness>
where
    PublicKey: AsRef<[u8]>,
{
    let in_out = VRFOutput(tag_signature.output).attach_input_hash(
        &schnorrkel::PublicKey::from_bytes(public_key.as_ref())?,
        create_tag_signature_transcript(tag),
    )?;

    Ok(in_out.make_bytes(RANDOMNESS_CONTEXT))
}

/// Derives next solution range based on the total era slots and slot probability
pub fn derive_next_solution_range(
    start_slot: u64,
    current_slot: u64,
    slot_probability: (u64, u64),
    current_solution_range: u64,
    era_duration: u64,
) -> u64 {
    // calculate total slots within this era
    let era_slot_count = current_slot - start_slot;

    // Now we need to re-calculate solution range. The idea here is to keep block production at
    // the same pace while space pledged on the network changes. For this we adjust previous
    // solution range according to actual and expected number of blocks per era.

    // Below is code analogous to the following, but without using floats:
    // ```rust
    // let actual_slots_per_block = era_slot_count as f64 / era_duration as f64;
    // let expected_slots_per_block =
    //     slot_probability.1 as f64 / slot_probability.0 as f64;
    // let adjustment_factor =
    //     (actual_slots_per_block / expected_slots_per_block).clamp(0.25, 4.0);
    //
    // next_solution_range =
    //     (solution_ranges.current as f64 * adjustment_factor).round() as u64;
    // ```
    u64::saturated_from(
        u128::from(current_solution_range)
            .saturating_mul(u128::from(era_slot_count))
            .saturating_mul(u128::from(slot_probability.0))
            / u128::from(era_duration)
            / u128::from(slot_probability.1),
    )
    .clamp(
        current_solution_range / 4,
        current_solution_range.saturating_mul(4),
    )
}

const SALT_HASHING_PREFIX_LEN: usize = SALT_HASHING_PREFIX.len();

/// Derives next salt value from the randomness provided.
pub fn derive_next_salt_from_randomness(eon_index: u64, randomness: &Randomness) -> Salt {
    let mut input = [0u8; SALT_HASHING_PREFIX_LEN + RANDOMNESS_LENGTH + mem::size_of::<u64>()];
    input[..SALT_HASHING_PREFIX_LEN].copy_from_slice(SALT_HASHING_PREFIX);
    input[SALT_HASHING_PREFIX_LEN..SALT_HASHING_PREFIX_LEN + RANDOMNESS_LENGTH]
        .copy_from_slice(randomness);
    input[SALT_HASHING_PREFIX_LEN + RANDOMNESS_LENGTH..].copy_from_slice(&eon_index.to_le_bytes());

    crypto::sha256_hash(&input)[..SALT_SIZE]
        .try_into()
        .expect("Slice has exactly the size needed; qed")
}
