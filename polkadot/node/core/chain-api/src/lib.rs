// Copyright 2020 Parity Technologies (UK) Ltd.
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

//! Implements the Chain API Subsystem
//!
//! Provides access to the chain data. Every request may return an error.
//! At the moment, the implementation requires `Client` to implement `HeaderBackend`,
//! we may add more bounds in the future if we will need e.g. block bodies.
//!
//! Supported requests:
//! * Block hash to number
//! * Block hash to header
//! * Block weight (cumulative)
//! * Finalized block number to hash
//! * Last finalized block number
//! * Ancestors

#![deny(unused_results, unused_crate_dependencies)]
#![warn(missing_docs)]

use std::sync::Arc;

use futures::prelude::*;
use sc_client_api::{AuxStore, BlockBackend};
use sp_blockchain::HeaderBackend;

use polkadot_subsystem::{
	messages::ChainApiMessage, overseer, FromOverseer, OverseerSignal, SpawnedSubsystem,
	SubsystemContext, SubsystemError, SubsystemResult,
};
use subspace_runtime_primitives::opaque::{Block, BlockId};

/// The Chain API Subsystem implementation.
pub struct ChainApiSubsystem<Client> {
	client: Arc<Client>,
}

impl<Client> ChainApiSubsystem<Client> {
	/// Create a new Chain API subsystem with the given client.
	pub fn new(client: Arc<Client>) -> Self {
		ChainApiSubsystem { client }
	}
}

impl<Client, Context> overseer::Subsystem<Context, SubsystemError> for ChainApiSubsystem<Client>
where
	Client: HeaderBackend<Block> + BlockBackend<Block> + AuxStore + 'static,
	Context: SubsystemContext<Message = ChainApiMessage>,
	Context: overseer::SubsystemContext<Message = ChainApiMessage>,
{
	fn start(self, ctx: Context) -> SpawnedSubsystem {
		let future = run::<Client, Context>(ctx, self)
			.map_err(|e| SubsystemError::with_origin("chain-api", e))
			.boxed();
		SpawnedSubsystem { future, name: "chain-api-subsystem" }
	}
}

async fn run<Client, Context>(
	mut ctx: Context,
	subsystem: ChainApiSubsystem<Client>,
) -> SubsystemResult<()>
where
	Client: HeaderBackend<Block> + BlockBackend<Block> + AuxStore,
	Context: SubsystemContext<Message = ChainApiMessage>,
	Context: overseer::SubsystemContext<Message = ChainApiMessage>,
{
	loop {
		match ctx.recv().await? {
			FromOverseer::Signal(OverseerSignal::Conclude) => return Ok(()),
			FromOverseer::Signal(OverseerSignal::ActiveLeaves(_)) => {},
			FromOverseer::Signal(OverseerSignal::NewSlot(..)) => {},
			FromOverseer::Communication { msg } => match msg {
				ChainApiMessage::BlockHeader(hash, response_channel) => {
					let result = subsystem
						.client
						.header(BlockId::Hash(hash))
						.map_err(|e| e.to_string().into());
					let _ = response_channel.send(result);
				},
				ChainApiMessage::BlockBody(hash, response_channel) => {
					let result = subsystem
						.client
						.block_body(&BlockId::Hash(hash))
						.map_err(|e| e.to_string().into());
					let _ = response_channel.send(result);
				},
				ChainApiMessage::BestBlockHash(response_channel) => {
					let result = subsystem.client.info().best_hash;
					let _ = response_channel.send(Ok(result));
				},
			},
		}
	}
}
