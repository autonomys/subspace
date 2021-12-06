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

//! Primitive types used on the node-side.
//!
//! Unlike the `polkadot-primitives` crate, these primitives are only used on the node-side,
//! not shared between the node and the runtime. This crate builds on top of the primitives defined
//! there.

#![deny(missing_docs)]

use std::{convert::TryFrom, pin::Pin, time::Duration};

use bounded_vec::BoundedVec;
use futures::Future;
use parity_scale_codec::{Decode, Encode, Error as CodecError, Input};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

pub use sp_consensus_babe::{
	AllowedSlots as BabeAllowedSlots, BabeEpochConfiguration, Epoch as BabeEpoch,
};
pub use sp_core::traits::SpawnNamed;

// use polkadot_primitives::v1::{
	// BlakeTwo256, CandidateCommitments, CandidateHash, CollatorPair, CommittedCandidateReceipt,
	// CompactStatement, EncodeAs, Hash, HashT, HeadData, Id as ParaId, OutboundHrmpMessage,
	// PersistedValidationData, SessionIndex, Signed, UncheckedSigned, UpwardMessage, ValidationCode,
	// ValidatorIndex, MAX_CODE_SIZE, MAX_POV_SIZE,
// };

// pub use polkadot_parachain::primitives::BlockData;

// pub mod approval;

/// Disputes related types.
// pub mod disputes;
// pub use disputes::{
	// CandidateVotes, DisputeMessage, DisputeMessageCheckError, InvalidDisputeVote,
	// SignedDisputeStatement, UncheckedDisputeMessage, ValidDisputeVote,
// };

// For a 16-ary Merkle Prefix Trie, we can expect at most 16 32-byte hashes per node
// plus some overhead:
// header 1 + bitmap 2 + max partial_key 8 + children 16 * (32 + len 1) + value 32 + value len 1
const MERKLE_NODE_MAX_SIZE: usize = 512 + 100;
// 16-ary Merkle Prefix Trie for 32-bit ValidatorIndex has depth at most 8.
const MERKLE_PROOF_MAX_DEPTH: usize = 8;

/// The bomb limit for decompressing code blobs.
// pub const VALIDATION_CODE_BOMB_LIMIT: usize = (MAX_CODE_SIZE * 4u32) as usize;

/// The bomb limit for decompressing PoV blobs.
// pub const POV_BOMB_LIMIT: usize = (MAX_POV_SIZE * 4u32) as usize;

/// The amount of time to spend on execution during backing.
pub const BACKING_EXECUTION_TIMEOUT: Duration = Duration::from_secs(2);

/// The amount of time to spend on execution during approval or disputes.
///
/// This is deliberately much longer than the backing execution timeout to
/// ensure that in the absence of extremely large disparities between hardware,
/// blocks that pass backing are considerd executable by approval checkers or
/// dispute participants.
pub const APPROVAL_EXECUTION_TIMEOUT: Duration = Duration::from_secs(6);

/// The cumulative weight of a block in a fork-choice rule.
pub type BlockWeight = u32;

/// Candidate invalidity details
#[derive(Debug)]
pub enum InvalidCandidate {
	/// Failed to execute.`validate_block`. This includes function panicking.
	ExecutionError(String),
	/// Validation outputs check doesn't pass.
	InvalidOutputs,
	/// Execution timeout.
	Timeout,
	/// Validation input is over the limit.
	ParamsTooLarge(u64),
	/// Code size is over the limit.
	CodeTooLarge(u64),
	/// Code does not decompress correctly.
	CodeDecompressionFailure,
	/// PoV does not decompress correctly.
	PoVDecompressionFailure,
	/// Validation function returned invalid data.
	BadReturn,
	/// Invalid relay chain parent.
	BadParent,
	/// POV hash does not match.
	PoVHashMismatch,
	/// Bad collator signature.
	BadSignature,
	/// Para head hash does not match.
	ParaHeadHashMismatch,
	/// Validation code hash does not match.
	CodeHashMismatch,
}

/// This is a convenience type to allow the Erasure chunk proof to Decode into a nested BoundedVec
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct Proof(BoundedVec<BoundedVec<u8, 1, MERKLE_NODE_MAX_SIZE>, 1, MERKLE_PROOF_MAX_DEPTH>);

impl Proof {
	/// This function allows to convert back to the standard nested Vec format
	pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
		self.0.iter().map(|v| v.as_slice())
	}

	/// Construct an invalid dummy proof
	///
	/// Useful for testing, should absolutely not be used in production.
	pub fn dummy_proof() -> Proof {
		Proof(BoundedVec::from_vec(vec![BoundedVec::from_vec(vec![0]).unwrap()]).unwrap())
	}
}

#[derive(thiserror::Error, Debug)]
///
pub enum MerkleProofError {
	#[error("Merkle max proof depth exceeded {0} > {} .", MERKLE_PROOF_MAX_DEPTH)]
	/// This error signifies that the Proof length exceeds the trie's max depth
	MerkleProofDepthExceeded(usize),

	#[error("Merkle node max size exceeded {0} > {} .", MERKLE_NODE_MAX_SIZE)]
	/// This error signifies that a Proof node exceeds the 16-ary max node size
	MerkleProofNodeSizeExceeded(usize),
}

impl TryFrom<Vec<Vec<u8>>> for Proof {
	type Error = MerkleProofError;

	fn try_from(input: Vec<Vec<u8>>) -> Result<Self, Self::Error> {
		if input.len() > MERKLE_PROOF_MAX_DEPTH {
			return Err(Self::Error::MerkleProofDepthExceeded(input.len()))
		}
		let mut out = Vec::new();
		for element in input.into_iter() {
			let length = element.len();
			let data: BoundedVec<u8, 1, MERKLE_NODE_MAX_SIZE> = BoundedVec::from_vec(element)
				.map_err(|_| Self::Error::MerkleProofNodeSizeExceeded(length))?;
			out.push(data);
		}
		Ok(Proof(BoundedVec::from_vec(out).expect("Buffer size is deterined above. qed")))
	}
}

impl Decode for Proof {
	fn decode<I: Input>(value: &mut I) -> Result<Self, CodecError> {
		let temp: Vec<Vec<u8>> = Decode::decode(value)?;
		let mut out = Vec::new();
		for element in temp.into_iter() {
			let bounded_temp: Result<BoundedVec<u8, 1, MERKLE_NODE_MAX_SIZE>, CodecError> =
				BoundedVec::from_vec(element)
					.map_err(|_| "Inner node exceeds maximum node size.".into());
			out.push(bounded_temp?);
		}
		BoundedVec::from_vec(out)
			.map(Self)
			.map_err(|_| "Merkle proof depth exceeds maximum trie depth".into())
	}
}

impl Encode for Proof {
	fn size_hint(&self) -> usize {
		MERKLE_NODE_MAX_SIZE * MERKLE_PROOF_MAX_DEPTH
	}

	fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
		let temp = self.0.iter().map(|v| v.as_vec()).collect::<Vec<_>>();
		temp.using_encoded(f)
	}
}

impl Serialize for Proof {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_bytes(&self.encode())
	}
}

impl<'de> Deserialize<'de> for Proof {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		// Deserialize the string and get individual components
		let s = Vec::<u8>::deserialize(deserializer)?;
		let mut slice = s.as_slice();
		Decode::decode(&mut slice).map_err(de::Error::custom)
	}
}
