// Copyright 2019-2021 Parity Technologies (UK) Ltd.
// This file is part of Cumulus.

// Cumulus is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Cumulus is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Cumulus.  If not, see <http://www.gnu.org/licenses/>.

use std::marker::PhantomData;

use sc_consensus::{
	import_queue::{BasicQueue, Verifier as VerifierT},
	BlockImport, BlockImportParams,
};
use sp_blockchain::Result as ClientResult;
use sp_consensus::{error::Error as ConsensusError, CacheKeyId};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};

/// A verifier that just checks the inherents.
pub struct Verifier<Block> {
	_marker: PhantomData<Block>,
}

impl<Block> Default for Verifier<Block> {
	/// Create a new instance.
	fn default() -> Self {
		Self { _marker: PhantomData }
	}
}

#[async_trait::async_trait]
impl<Block> VerifierT<Block> for Verifier<Block>
where
	Block: BlockT,
{
	async fn verify(
		&mut self,
		mut block_params: BlockImportParams<Block, ()>,
	) -> Result<(BlockImportParams<Block, ()>, Option<Vec<(CacheKeyId, Vec<u8>)>>), String> {
		block_params.post_hash = Some(block_params.header.hash());

		Ok((block_params, None))
	}
}

/// Start an import queue for a Cumulus collator that does not uses any special authoring logic.
pub fn import_queue<Block: BlockT, I>(
	block_import: I,
	spawner: &impl sp_core::traits::SpawnEssentialNamed,
	registry: Option<&substrate_prometheus_endpoint::Registry>,
) -> ClientResult<BasicQueue<Block, I::Transaction>>
where
	I: BlockImport<Block, Error = ConsensusError> + Send + Sync + 'static,
	I::Transaction: Send,
{
	Ok(BasicQueue::new(
		Verifier::default(),
		Box::new(cumulus_client_consensus_common::ParachainBlockImport::new(block_import)),
		None,
		spawner,
		registry,
	))
}
