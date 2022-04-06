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

//! Message types for the overseer and subsystems.
//!
//! These messages are intended to define the protocol by which different subsystems communicate with each
//! other and signals that they receive from an overseer to coordinate their work.
//! This is intended for use with the `polkadot-overseer` crate.
//!
//! Subsystems' APIs are defined separately from their implementation, leading to easier mocking.

use cirrus_node_primitives::CollationGenerationConfig;
use sp_executor::{BundleEquivocationProof, FraudProof, InvalidTransactionProof};

/// Message to the Collation Generation subsystem.
#[derive(Debug)]
pub enum CollationGenerationMessage {
	/// Initialize the collation generation subsystem
	Initialize(CollationGenerationConfig),
	/// Fraud proof needs to be submitted to primary chain.
	FraudProof(FraudProof),
	/// Bundle equivocation proof needs to be submitted to primary chain.
	BundleEquivocationProof(BundleEquivocationProof),
	/// Invalid transaction proof needs to be submitted to primary chain.
	InvalidTransactionProof(InvalidTransactionProof),
}
