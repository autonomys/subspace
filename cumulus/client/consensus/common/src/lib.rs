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

use sc_consensus::BlockImport;
use sp_runtime::traits::Block as BlockT;

/// Parachain specific block import.
///
/// This is used to set `block_import_params.fork_choice` to `false` as long as the block origin is
/// not `NetworkInitialSync`. The best block for parachains is determined by the relay chain. Meaning
/// we will update the best block, as it is included by the relay-chain.
pub struct ParachainBlockImport<I>(I);

impl<I> ParachainBlockImport<I> {
	/// Create a new instance.
	pub fn new(inner: I) -> Self {
		Self(inner)
	}
}

#[async_trait::async_trait]
impl<Block, I> BlockImport<Block> for ParachainBlockImport<I>
where
	Block: BlockT,
	I: BlockImport<Block> + Send,
{
	type Error = I::Error;
	type Transaction = I::Transaction;

	async fn check_block(
		&mut self,
		block: sc_consensus::BlockCheckParams<Block>,
	) -> Result<sc_consensus::ImportResult, Self::Error> {
		self.0.check_block(block).await
	}

	async fn import_block(
		&mut self,
		mut block_import_params: sc_consensus::BlockImportParams<Block, Self::Transaction>,
		cache: std::collections::HashMap<sp_consensus::CacheKeyId, Vec<u8>>,
	) -> Result<sc_consensus::ImportResult, Self::Error> {
		// Best block is determined by the relay chain, or if we are doing the intial sync
		// we import all blocks as new best.
		block_import_params.fork_choice = Some(sc_consensus::ForkChoiceStrategy::Custom(
			block_import_params.origin == sp_consensus::BlockOrigin::NetworkInitialSync,
		));
		self.0.import_block(block_import_params, cache).await
	}
}
