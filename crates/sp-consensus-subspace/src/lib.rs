// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Primitives for Subspace consensus.

#![forbid(unsafe_code, missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod digests;
pub mod inherents;
pub mod offence;
pub mod verification;

use crate::digests::{
    CompatibleDigestItem, GlobalRandomnessDescriptor, PreDigest, SaltDescriptor,
    SolutionRangeDescriptor,
};
use codec::{Decode, Encode, MaxEncodedLen};
use core::time::Duration;
use scale_info::TypeInfo;
use schnorrkel::vrf::VRFOutput;
use schnorrkel::{PublicKey, SignatureResult};
use sp_api::{BlockT, HeaderT};
use sp_consensus_slots::Slot;
use sp_core::crypto::KeyTypeId;
use sp_core::H256;
use sp_io::hashing;
use sp_runtime::{ConsensusEngineId, RuntimeAppPublic};
use sp_std::vec::Vec;
use subspace_core_primitives::{
    Randomness, RootBlock, Salt, Sha256Hash, Solution, Tag, TagSignature,
};
use subspace_solving::create_tag_signature_transcript;

/// Key type for Subspace pallet.
const KEY_TYPE: KeyTypeId = KeyTypeId(*b"sub_");

// TODO: Remove this and replace with simple encodable wrappers of Schnorrkel's types
mod app {
    use super::KEY_TYPE;
    use sp_application_crypto::{app_crypto, sr25519};

    app_crypto!(sr25519, KEY_TYPE);
}

/// A Subspace farmer signature.
pub type FarmerSignature = app::Signature;

/// A Subspace farmer identifier. Necessarily equivalent to the schnorrkel public key used in
/// the main Subspace module. If that ever changes, then this must, too.
pub type FarmerPublicKey = app::Public;

/// The `ConsensusEngineId` of Subspace.
const SUBSPACE_ENGINE_ID: ConsensusEngineId = *b"SUB_";

const RANDOMNESS_CONTEXT: &[u8] = b"subspace_randomness";

/// An equivocation proof for multiple block authorships on the same slot (i.e. double vote).
pub type EquivocationProof<Header> = sp_consensus_slots::EquivocationProof<Header, FarmerPublicKey>;

/// An consensus log item for Subspace.
#[derive(Debug, Decode, Encode, Clone, PartialEq, Eq)]
enum ConsensusLog {
    /// Global randomness for this block/interval.
    #[codec(index = 1)]
    GlobalRandomness(GlobalRandomnessDescriptor),
    /// Solution range for this block/era.
    #[codec(index = 2)]
    SolutionRange(SolutionRangeDescriptor),
    /// Salt for this block/eon.
    #[codec(index = 3)]
    Salt(SaltDescriptor),
}

/// Farmer vote.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode, TypeInfo)]
pub enum Vote<Number, Hash, RewardAddress> {
    /// V0 of the farmer vote.
    V0 {
        /// Height at which vote was created.
        ///
        /// Equivalent to block number, but this is not a block.
        height: Number,
        /// Hash of the block on top of which vote was created.
        parent_hash: Hash,
        /// Slot at which vote was created.
        slot: Slot,
        /// Solution (includes PoR).
        solution: Solution<FarmerPublicKey, RewardAddress>,
    },
}

impl<Number, Hash, RewardAddress> Vote<Number, Hash, RewardAddress>
where
    Number: Encode,
    Hash: Encode,
    RewardAddress: Encode,
{
    /// Farmer public key in the solution.
    pub fn public_key(&self) -> &FarmerPublicKey {
        let Self::V0 { solution, .. } = self;
        &solution.public_key
    }

    /// Hash of the vote, used for signing and verifying signature.
    pub fn hash(&self) -> H256 {
        hashing::blake2_256(&self.encode()).into()
    }
}

/// Signed farmer vote.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode, TypeInfo)]
pub struct SignedVote<Number, Hash, RewardAddress> {
    /// Farmer vote.
    pub vote: Vote<Number, Hash, RewardAddress>,
    /// Signature.
    pub signature: FarmerSignature,
}

fn find_pre_digest<Header, RewardAddress>(
    header: &Header,
) -> Option<PreDigest<FarmerPublicKey, RewardAddress>>
where
    Header: HeaderT,
    RewardAddress: Decode,
{
    header
        .digest()
        .logs()
        .iter()
        .find_map(|log| log.as_subspace_pre_digest())
}

fn is_seal_signature_valid<Header>(mut header: Header, offender: &FarmerPublicKey) -> bool
where
    Header: HeaderT,
{
    let seal = match header.digest_mut().pop() {
        Some(seal) => seal,
        None => {
            return false;
        }
    };
    let seal = match seal.as_subspace_seal() {
        Some(seal) => seal,
        None => {
            return false;
        }
    };
    let pre_hash = header.hash();

    offender.verify(&pre_hash, &seal)
}

/// Verifies the equivocation proof by making sure that: both headers have
/// different hashes, are targeting the same slot, and have valid signatures by
/// the same authority.
pub fn is_equivocation_proof_valid<Header, RewardAddress>(proof: EquivocationProof<Header>) -> bool
where
    Header: HeaderT,
    RewardAddress: Decode,
{
    // we must have different headers for the equivocation to be valid
    if proof.first_header.hash() == proof.second_header.hash() {
        return false;
    }

    let first_pre_digest = match find_pre_digest::<_, RewardAddress>(&proof.first_header) {
        Some(pre_digest) => pre_digest,
        None => {
            return false;
        }
    };
    let second_pre_digest = match find_pre_digest::<_, RewardAddress>(&proof.second_header) {
        Some(pre_digest) => pre_digest,
        None => {
            return false;
        }
    };

    // both headers must be targeting the same slot and it must
    // be the same as the one in the proof.
    if !(proof.slot == first_pre_digest.slot && proof.slot == second_pre_digest.slot) {
        return false;
    }

    // both headers must have been authored by the same farmer
    if first_pre_digest.solution.public_key != second_pre_digest.solution.public_key {
        return false;
    }

    // we finally verify that the expected farmer has signed both headers and
    // that the signature is valid.
    is_seal_signature_valid(proof.first_header, &proof.offender)
        && is_seal_signature_valid(proof.second_header, &proof.offender)
}

/// Subspace global randomnesses used for deriving global challenges.
#[derive(Default, Decode, Encode, MaxEncodedLen, PartialEq, Eq, Clone, Copy, Debug, TypeInfo)]
pub struct GlobalRandomnesses {
    /// Global randomness used for deriving global challenge in current block/interval.
    pub current: Randomness,
    /// Global randomness that will be used for deriving global challenge in the next
    /// block/interval.
    pub next: Option<Randomness>,
}

/// Subspace solution ranges used for challenges.
#[derive(Decode, Encode, MaxEncodedLen, PartialEq, Eq, Clone, Copy, Debug, TypeInfo)]
pub struct SolutionRanges {
    /// Solution range in current block/era.
    pub current: u64,
    /// Solution range that will be used in the next block/era.
    pub next: Option<u64>,
    /// Voting solution range in current block/era.
    pub voting_current: u64,
    /// Voting solution range that will be used in the next block/era.
    pub voting_next: Option<u64>,
}

impl Default for SolutionRanges {
    fn default() -> Self {
        Self {
            current: u64::MAX,
            next: None,
            voting_current: u64::MAX,
            voting_next: None,
        }
    }
}

/// Derive on-chain randomness from tag signature.
///
/// NOTE: If you are not the signer then you must verify the local challenge before calling this
/// function.
pub fn derive_randomness(
    public_key: &FarmerPublicKey,
    tag: Tag,
    tag_signature: &TagSignature,
) -> SignatureResult<Randomness> {
    let in_out = VRFOutput(tag_signature.output).attach_input_hash(
        &PublicKey::from_bytes(public_key.as_ref())?,
        create_tag_signature_transcript(tag),
    )?;

    Ok(in_out.make_bytes(RANDOMNESS_CONTEXT))
}

/// Subspace salts used for challenges.
#[derive(Default, Decode, Encode, MaxEncodedLen, PartialEq, Eq, Clone, Copy, Debug, TypeInfo)]
pub struct Salts {
    /// Salt used for challenges in current block/eon.
    pub current: Salt,
    /// Salt used for challenges after `salt` in the next eon.
    pub next: Option<Salt>,
    /// Whether salt should be updated in the next block (next salt is known upfront for some time
    /// and is not necessarily switching in the very next block).
    pub switch_next_block: bool,
}

sp_api::decl_runtime_apis! {
    /// API necessary for block authorship with Subspace.
    pub trait SubspaceApi<RewardAddress: Encode + Decode> {
        /// Depth `K` after which a block enters the recorded history (a global constant, as opposed
        /// to the client-dependent transaction confirmation depth `k`).
        fn confirmation_depth_k() -> <<Block as BlockT>::Header as HeaderT>::Number;

        /// The size of data in one piece (in bytes).
        fn record_size() -> u32;

        /// Recorded history is encoded and plotted in segments of this size (in bytes).
        fn recorded_history_segment_size() -> u32;

        /// Maximum number of pieces in each plot
        fn max_plot_size() -> u64;

        /// The slot duration in milliseconds for Subspace.
        fn slot_duration() -> Duration;

        /// Global randomnesses used for deriving global challenges.
        fn global_randomnesses() -> GlobalRandomnesses;

        /// Solution ranges.
        fn solution_ranges() -> SolutionRanges;

        /// Subspace salts used for challenges.
        fn salts() -> Salts;

        /// Submits an unsigned extrinsic to report an equivocation. The caller must provide the
        /// equivocation proof. The extrinsic will be unsigned and should only be accepted for local
        /// authorship (not to be broadcast to the network). This method returns `None` when
        /// creation of the extrinsic fails, e.g. if equivocation reporting is disabled for the
        /// given runtime (i.e. this method is hardcoded to return `None`). Only useful in an
        /// offchain context.
        fn submit_report_equivocation_extrinsic(
            equivocation_proof: EquivocationProof<Block::Header>,
        ) -> Option<()>;

        /// Submit farmer vote vote that is essentially a header with bigger solution range than
        /// acceptable for block authoring. Only useful in an offchain context.
        fn submit_vote_extrinsic(
            signed_vote: SignedVote<
                <<Block as BlockT>::Header as HeaderT>::Number,
                Block::Hash,
                RewardAddress,
            >,
        );

        /// Check if `farmer_public_key` is in block list (due to equivocation)
        fn is_in_block_list(farmer_public_key: &FarmerPublicKey) -> bool;

        /// Total number of pieces in a blockchain
        fn total_pieces() -> u64;

        /// Get the merkle tree root of records for specified segment index
        fn records_root(segment_index: u64) -> Option<Sha256Hash>;

        /// Returns `Vec<RootBlock>` if a given extrinsic has them.
        fn extract_root_blocks(ext: &Block::Extrinsic) -> Option<Vec<RootBlock>>;

        /// Returns root plot public key in case block authoring is restricted.
        fn root_plot_public_key() -> Option<FarmerPublicKey>;
    }
}
