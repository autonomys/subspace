use schnorrkel::vrf::VRFOutput;
use schnorrkel::SignatureResult;
use subspace_core_primitives::{Randomness, Tag, TagSignature, RANDOMNESS_CONTEXT};
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
