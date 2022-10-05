use crate::{
    is_equivocation_proof_valid, CompatibleDigestItem, EquivocationProof, FarmerPublicKey,
    FarmerSignature,
};
use schnorrkel::Keypair;
use sp_consensus_slots::Slot;
use sp_core::crypto::UncheckedFrom;
use sp_runtime::traits::BlakeTwo256;
use sp_runtime::{Digest, DigestItem};
use subspace_core_primitives::{ChunkSignature, Solution};
use subspace_solving::REWARD_SIGNING_CONTEXT;

type Header = sp_runtime::generic::Header<u32, BlakeTwo256>;
type PreDigest = crate::PreDigest<FarmerPublicKey, ()>;

#[test]
fn test_is_equivocation_proof_valid() {
    let keypair = Keypair::generate();
    let offender = FarmerPublicKey::unchecked_from(keypair.public.to_bytes());
    let slot = Slot::from(1);
    let solution = Solution {
        public_key: offender.clone(),
        reward_address: (),
        sector_index: 0,
        total_pieces: 1,
        piece_offset: 0,
        piece_record_hash: Default::default(),
        piece_witness: Default::default(),
        chunk: Default::default(),
        chunk_signature: ChunkSignature {
            output: Default::default(),
            proof: [0u8; 64],
        },
    };

    let mut first_header = Header {
        parent_hash: [0u8; 32].into(),
        number: 1,
        state_root: Default::default(),
        extrinsics_root: Default::default(),
        digest: Digest {
            logs: vec![DigestItem::subspace_pre_digest(&PreDigest {
                slot,
                solution: solution.clone(),
            })],
        },
    };
    first_header
        .digest
        .logs
        .push(DigestItem::subspace_seal(FarmerSignature::unchecked_from(
            keypair
                .sign(
                    schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT)
                        .bytes(first_header.hash().as_bytes()),
                )
                .to_bytes(),
        )));

    let mut second_header = Header {
        parent_hash: [1u8; 32].into(),
        number: 1,
        state_root: Default::default(),
        extrinsics_root: Default::default(),
        digest: Digest {
            logs: vec![DigestItem::subspace_pre_digest(&PreDigest {
                slot,
                solution,
            })],
        },
    };
    second_header
        .digest
        .logs
        .push(DigestItem::subspace_seal(FarmerSignature::unchecked_from(
            keypair
                .sign(
                    schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT)
                        .bytes(second_header.hash().as_bytes()),
                )
                .to_bytes(),
        )));

    let equivocation_proof = EquivocationProof {
        offender,
        slot,
        first_header,
        second_header,
    };

    assert!(is_equivocation_proof_valid::<_, ()>(equivocation_proof));
}
