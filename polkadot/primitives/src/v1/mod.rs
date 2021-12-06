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

#[cfg(feature = "std")]
use parity_util_mem::{MallocSizeOf, MallocSizeOfOps};

pub use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
pub use sp_consensus_slots::Slot;
pub use sp_staking::SessionIndex;

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

/// Different kinds of statements of invalidity on a candidate.
#[derive(Encode, Decode, Clone, PartialEq, RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "std", derive(MallocSizeOf))]
pub enum InvalidDisputeStatementKind {
	/// An explicit statement issued as part of a dispute.
	#[codec(index = 0)]
	Explicit,
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
