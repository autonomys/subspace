// Copyright 2017-2020 Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! `V1` Primitives.

use bitvec::vec::BitVec;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_std::{collections::btree_map::BTreeMap, prelude::*};

use application_crypto::KeyTypeId;
use inherents::InherentIdentifier;
use primitives::RuntimeDebug;
use runtime_primitives::traits::{AppVerify, Header as HeaderT};
use sp_arithmetic::traits::{BaseArithmetic, Saturating};

pub use runtime_primitives::traits::{BlakeTwo256, Hash as HashT};

// Export some core primitives.
pub use polkadot_core_primitives::v1::{
	AccountId, AccountIndex, AccountPublic, Balance, Block, BlockId, BlockNumber, CandidateHash,
	ChainId, DownwardMessage, Hash, Header, InboundDownwardMessage, InboundHrmpMessage, Moment,
	Nonce, OutboundHrmpMessage, Remark, Signature, UncheckedExtrinsic,
};

// Export some polkadot-parachain primitives
// pub use polkadot_parachain::primitives::{
	// HeadData, HrmpChannelId, Id, UpwardMessage, ValidationCode, ValidationCodeHash,
	// LOWEST_PUBLIC_ID, LOWEST_USER_ID,
// };

#[cfg(feature = "std")]
use parity_util_mem::{MallocSizeOf, MallocSizeOfOps};

pub use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
pub use sp_consensus_slots::Slot;
pub use sp_staking::SessionIndex;

/// Signed data.
// mod signed;
// pub use signed::{EncodeAs, Signed, UncheckedSigned};

/// A declarations of storage keys where an external observer can find some interesting data.
pub mod well_known_keys {
	// use super::{HrmpChannelId, Id};
	use hex_literal::hex;
	use parity_scale_codec::Encode as _;
	use sp_io::hashing::twox_64;
	use sp_std::prelude::*;

	// A note on generating these magic values below:
	//
	// The `StorageValue`, such as `ACTIVE_CONFIG` was obtained by calling:
	//
	//     <Self as Store>::ActiveConfig::hashed_key()
	//
	// The `StorageMap` values require `prefix`, and for example for `hrmp_egress_channel_index`,
	// it could be obtained like:
	//
	//     <Hrmp as Store>::HrmpEgressChannelsIndex::prefix_hash();
	//

	/// The current slot number.
	///
	/// The storage entry should be accessed as a `Slot` encoded value.
	pub const CURRENT_SLOT: &[u8] =
		&hex!["1cb6f36e027abb2091cfb5110ab5087f06155b3cd9a8c9e5e9a23fd5dc13a5ed"];

	/// The currently active host configuration.
	///
	/// The storage entry should be accessed as an `AbridgedHostConfiguration` encoded value.
	pub const ACTIVE_CONFIG: &[u8] =
		&hex!["06de3d8a54d27e44a9d5ce189618f22db4b49d95320d9021994c850f25b8e385"];
}

/// Unique identifier for the Parachains Inherent
pub const PARACHAINS_INHERENT_IDENTIFIER: InherentIdentifier = *b"parachn0";

/// The key type ID for parachain assignment key.
pub const ASSIGNMENT_KEY_TYPE_ID: KeyTypeId = KeyTypeId(*b"asgn");

/// Maximum compressed code size we support right now.
/// At the moment we have runtime upgrade on chain, which restricts scalability severely. If we want
/// to have bigger values, we should fix that first.
///
/// Used for:
/// * initial genesis for the Parachains configuration
/// * checking updates to this stored runtime configuration do not exceed this limit
/// * when detecting a code decompression bomb in the client
pub const MAX_CODE_SIZE: u32 = 3 * 1024 * 1024;

/// Maximum head data size we support right now.
///
/// Used for:
/// * initial genesis for the Parachains configuration
/// * checking updates to this stored runtime configuration do not exceed this limit
pub const MAX_HEAD_DATA_SIZE: u32 = 1 * 1024 * 1024;

/// Maximum PoV size we support right now.
///
/// Used for:
/// * initial genesis for the Parachains configuration
/// * checking updates to this stored runtime configuration do not exceed this limit
/// * when detecting a PoV decompression bomb in the client
pub const MAX_POV_SIZE: u32 = 5 * 1024 * 1024;

// The public key of a keypair used by a validator for determining assignments
/// to approve included parachain candidates.
mod assignment_app {
	use application_crypto::{app_crypto, sr25519};
	app_crypto!(sr25519, super::ASSIGNMENT_KEY_TYPE_ID);
}

/// The public key of a keypair used by a validator for determining assignments
/// to approve included parachain candidates.
pub type AssignmentId = assignment_app::Public;

application_crypto::with_pair! {
	/// The full keypair used by a validator for determining assignments to approve included
	/// parachain candidates.
	pub type AssignmentPair = assignment_app::Pair;
}

#[cfg(feature = "std")]
impl MallocSizeOf for AssignmentId {
	fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize {
		0
	}
	fn constant_size() -> Option<usize> {
		Some(0)
	}
}

/// The index of the candidate in the list of candidates fully included as-of the block.
pub type CandidateIndex = u32;

/// A vote of approval on a candidate.
#[derive(Clone, RuntimeDebug)]
pub struct ApprovalVote(pub CandidateHash);

impl ApprovalVote {
	/// Yields the signing payload for this approval vote.
	pub fn signing_payload(&self, session_index: SessionIndex) -> Vec<u8> {
		const MAGIC: [u8; 4] = *b"APPR";

		(MAGIC, &self.0, session_index).encode()
	}
}

/// Custom validity errors used in Polkadot while validating transactions.
#[repr(u8)]
pub enum ValidityError {
	/// The Ethereum signature is invalid.
	InvalidEthereumSignature = 0,
	/// The signer has no claim.
	SignerHasNoClaim = 1,
	/// No permission to execute the call.
	NoPermission = 2,
	/// An invalid statement was made for a claim.
	InvalidStatement = 3,
}

impl From<ValidityError> for u8 {
	fn from(err: ValidityError) -> Self {
		err as u8
	}
}

/// Abridged version of `HostConfiguration` (from the `Configuration` parachains host runtime module)
/// meant to be used by a parachain or PDK such as cumulus.
#[derive(Clone, Encode, Decode, RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "std", derive(PartialEq))]
pub struct AbridgedHostConfiguration {
	/// The maximum validation code size, in bytes.
	pub max_code_size: u32,
	/// The maximum head-data size, in bytes.
	pub max_head_data_size: u32,
	/// Total number of individual messages allowed in the parachain -> relay-chain message queue.
	pub max_upward_queue_count: u32,
	/// Total size of messages allowed in the parachain -> relay-chain message queue before which
	/// no further messages may be added to it. If it exceeds this then the queue may contain only
	/// a single message.
	pub max_upward_queue_size: u32,
	/// The maximum size of an upward message that can be sent by a candidate.
	///
	/// This parameter affects the size upper bound of the `CandidateCommitments`.
	pub max_upward_message_size: u32,
	/// The maximum number of messages that a candidate can contain.
	///
	/// This parameter affects the size upper bound of the `CandidateCommitments`.
	pub max_upward_message_num_per_candidate: u32,
	/// The maximum number of outbound HRMP messages can be sent by a candidate.
	///
	/// This parameter affects the upper bound of size of `CandidateCommitments`.
	pub hrmp_max_message_num_per_candidate: u32,
	/// The minimum frequency at which parachains can update their validation code.
	pub validation_upgrade_frequency: BlockNumber,
	/// The delay, in blocks, before a validation upgrade is applied.
	pub validation_upgrade_delay: BlockNumber,
}

/// Abridged version of `HrmpChannel` (from the `Hrmp` parachains host runtime module) meant to be
/// used by a parachain or PDK such as cumulus.
#[derive(Clone, Encode, Decode, RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "std", derive(PartialEq))]
pub struct AbridgedHrmpChannel {
	/// The maximum number of messages that can be pending in the channel at once.
	pub max_capacity: u32,
	/// The maximum total size of the messages that can be pending in the channel at once.
	pub max_total_size: u32,
	/// The maximum message size that could be put into the channel.
	pub max_message_size: u32,
	/// The current number of messages pending in the channel.
	/// Invariant: should be less or equal to `max_capacity`.s`.
	pub msg_count: u32,
	/// The total size in bytes of all message payloads in the channel.
	/// Invariant: should be less or equal to `max_total_size`.
	pub total_size: u32,
	/// A head of the Message Queue Chain for this channel. Each link in this chain has a form:
	/// `(prev_head, B, H(M))`, where
	/// - `prev_head`: is the previous value of `mqc_head` or zero if none.
	/// - `B`: is the [relay-chain] block number in which a message was appended
	/// - `H(M)`: is the hash of the message being appended.
	/// This value is initialized to a special value that consists of all zeroes which indicates
	/// that no messages were previously added.
	pub mqc_head: Option<Hash>,
}

/// A possible upgrade restriction that prevents a parachain from performing an upgrade.
#[derive(Encode, Decode, PartialEq, RuntimeDebug, TypeInfo)]
pub enum UpgradeRestriction {
	/// There is an upgrade restriction and there are no details about its specifics nor how long
	/// it could last.
	#[codec(index = 0)]
	Present,
}

/// A struct that the relay-chain communicates to a parachain indicating what course of action the
/// parachain should take in the coordinated parachain validation code upgrade process.
///
/// This data type appears in the last step of the upgrade process. After the parachain observes it
/// and reacts to it the upgrade process concludes.
#[derive(Encode, Decode, PartialEq, RuntimeDebug, TypeInfo)]
pub enum UpgradeGoAhead {
	/// Abort the upgrade process. There is something wrong with the validation code previously
	/// submitted by the parachain. This variant can also be used to prevent upgrades by the governance
	/// should an emergency emerge.
	///
	/// The expected reaction on this variant is that the parachain will admit this message and
	/// remove all the data about the pending upgrade. Depending on the nature of the problem (to
	/// be examined offchain for now), it can try to send another validation code or just retry later.
	#[codec(index = 0)]
	Abort,
	/// Apply the pending code change. The parablock that is built on a relay-parent that is descendant
	/// of the relay-parent where the parachain observed this signal must use the upgraded validation
	/// code.
	#[codec(index = 1)]
	GoAhead,
}

/// Consensus engine id for polkadot v1 consensus engine.
pub const POLKADOT_ENGINE_ID: runtime_primitives::ConsensusEngineId = *b"POL1";

/// Different kinds of statements of validity on  a candidate.
#[derive(Encode, Decode, Clone, PartialEq, RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "std", derive(MallocSizeOf))]
pub enum ValidDisputeStatementKind {
	/// An explicit statement issued as part of a dispute.
	#[codec(index = 0)]
	Explicit,
	/// A seconded statement on a candidate from the backing phase.
	#[codec(index = 1)]
	BackingSeconded(Hash),
	/// A valid statement on a candidate from the backing phase.
	#[codec(index = 2)]
	BackingValid(Hash),
	/// An approval vote from the approval checking phase.
	#[codec(index = 3)]
	ApprovalChecking,
}

/// Different kinds of statements of invalidity on a candidate.
#[derive(Encode, Decode, Clone, PartialEq, RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "std", derive(MallocSizeOf))]
pub enum InvalidDisputeStatementKind {
	/// An explicit statement issued as part of a dispute.
	#[codec(index = 0)]
	Explicit,
}

/// An explicit statement on a candidate issued as part of a dispute.
#[derive(Clone, PartialEq, RuntimeDebug)]
pub struct ExplicitDisputeStatement {
	/// Whether the candidate is valid
	pub valid: bool,
	/// The candidate hash.
	pub candidate_hash: CandidateHash,
	/// The session index of the candidate.
	pub session: SessionIndex,
}

impl ExplicitDisputeStatement {
	/// Produce the payload used for signing this type of statement.
	pub fn signing_payload(&self) -> Vec<u8> {
		const MAGIC: [u8; 4] = *b"DISP";

		(MAGIC, self.valid, self.candidate_hash, self.session).encode()
	}
}

/// The entire state of a dispute.
#[derive(Encode, Decode, Clone, RuntimeDebug, PartialEq, TypeInfo)]
pub struct DisputeState<N = BlockNumber> {
	/// A bitfield indicating all validators for the candidate.
	pub validators_for: BitVec<bitvec::order::Lsb0, u8>, // one bit per validator.
	/// A bitfield indicating all validators against the candidate.
	pub validators_against: BitVec<bitvec::order::Lsb0, u8>, // one bit per validator.
	/// The block number at which the dispute started on-chain.
	pub start: N,
	/// The block number at which the dispute concluded on-chain.
	pub concluded_at: Option<N>,
}

/// The maximum number of validators `f` which may safely be faulty.
///
/// The total number of validators is `n = 3f + e` where `e in { 1, 2, 3 }`.
pub fn byzantine_threshold(n: usize) -> usize {
	n.saturating_sub(1) / 3
}

/// The supermajority threshold of validators which represents a subset
/// guaranteed to have at least f+1 honest validators.
pub fn supermajority_threshold(n: usize) -> usize {
	n - byzantine_threshold(n)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn group_rotation_info_calculations() {
		let info =
			GroupRotationInfo { session_start_block: 10u32, now: 15, group_rotation_frequency: 5 };

		assert_eq!(info.next_rotation_at(), 20);
		assert_eq!(info.last_rotation_at(), 15);
	}

	#[test]
	fn group_for_core_is_core_for_group() {
		for cores in 1..=256 {
			for rotations in 0..(cores * 2) {
				let info = GroupRotationInfo {
					session_start_block: 0u32,
					now: rotations,
					group_rotation_frequency: 1,
				};

				for core in 0..cores {
					let group = info.group_for_core(CoreIndex(core), cores as usize);
					assert_eq!(info.core_for_group(group, cores as usize).0, core);
				}
			}
		}
	}

	#[test]
	fn collator_signature_payload_is_valid() {
		// if this fails, collator signature verification code has to be updated.
		let h = Hash::default();
		assert_eq!(h.as_ref().len(), 32);

		let _payload = collator_signature_payload(
			&Hash::repeat_byte(1),
			&5u32.into(),
			&Hash::repeat_byte(2),
			&Hash::repeat_byte(3),
			&Hash::repeat_byte(4).into(),
		);
	}

	#[test]
	fn test_byzantine_threshold() {
		assert_eq!(byzantine_threshold(0), 0);
		assert_eq!(byzantine_threshold(1), 0);
		assert_eq!(byzantine_threshold(2), 0);
		assert_eq!(byzantine_threshold(3), 0);
		assert_eq!(byzantine_threshold(4), 1);
		assert_eq!(byzantine_threshold(5), 1);
		assert_eq!(byzantine_threshold(6), 1);
		assert_eq!(byzantine_threshold(7), 2);
	}

	#[test]
	fn test_supermajority_threshold() {
		assert_eq!(supermajority_threshold(0), 0);
		assert_eq!(supermajority_threshold(1), 1);
		assert_eq!(supermajority_threshold(2), 2);
		assert_eq!(supermajority_threshold(3), 3);
		assert_eq!(supermajority_threshold(4), 3);
		assert_eq!(supermajority_threshold(5), 4);
		assert_eq!(supermajority_threshold(6), 5);
		assert_eq!(supermajority_threshold(7), 5);
	}
}
