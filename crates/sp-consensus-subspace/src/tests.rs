use crate::digests::PreDigestPotInfo;
use crate::{
    is_equivocation_proof_valid, CompatibleDigestItem, EquivocationProof, FarmerSignature,
};
use schnorrkel::Keypair;
use sp_consensus_slots::Slot;
use sp_core::crypto::UncheckedFrom;
use sp_runtime::traits::BlakeTwo256;
use sp_runtime::{Digest, DigestItem};
use std::num::NonZeroU64;
use subspace_core_primitives::{
    HistorySize, PieceOffset, PublicKey, Solution, REWARD_SIGNING_CONTEXT,
};

type Header = sp_runtime::generic::Header<u32, BlakeTwo256>;
type PreDigest = crate::PreDigest<()>;

#[test]
fn test_is_equivocation_proof_valid() {
    let keypair = Keypair::generate();
    let offender = PublicKey::from(keypair.public.to_bytes());
    let slot = Slot::from(1);
    let solution = Solution {
        public_key: offender,
        reward_address: (),
        sector_index: 0,
        history_size: HistorySize::from(NonZeroU64::new(1).unwrap()),
        piece_offset: PieceOffset::default(),
        record_commitment: Default::default(),
        record_witness: Default::default(),
        chunk: Default::default(),
        chunk_witness: Default::default(),
        proof_of_space: Default::default(),
    };

    let mut first_header = Header {
        parent_hash: [0u8; 32].into(),
        number: 1,
        state_root: Default::default(),
        extrinsics_root: Default::default(),
        digest: Digest {
            logs: vec![DigestItem::subspace_pre_digest(&PreDigest::V0 {
                slot,
                solution: solution.clone(),
                pot_info: PreDigestPotInfo::V0 {
                    proof_of_time: Default::default(),
                    future_proof_of_time: Default::default(),
                },
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
            logs: vec![DigestItem::subspace_pre_digest(&PreDigest::V0 {
                slot,
                solution,
                pot_info: PreDigestPotInfo::V0 {
                    proof_of_time: Default::default(),
                    future_proof_of_time: Default::default(),
                },
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

    assert!(is_equivocation_proof_valid::<_, ()>(&equivocation_proof));
}
