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

use sc_consensus::import_queue::{BasicQueue, Verifier as VerifierT};
use sc_consensus::{BlockImport, BlockImportParams, SharedBlockImport};
use sp_blockchain::Result as ClientResult;
use sp_consensus::error::Error as ConsensusError;
use sp_core::traits::SpawnEssentialNamed;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use std::marker::PhantomData;
use substrate_prometheus_endpoint::Registry;

/// A verifier that just checks the inherents.
pub struct Verifier<Block> {
    _marker: PhantomData<Block>,
}

impl<Block> Default for Verifier<Block> {
    /// Create a new instance.
    #[inline]
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<Block> VerifierT<Block> for Verifier<Block>
where
    Block: BlockT,
{
    async fn verify(
        &self,
        mut block_params: BlockImportParams<Block>,
    ) -> Result<BlockImportParams<Block>, String> {
        block_params.post_hash = Some(block_params.header.hash());

        Ok(block_params)
    }
}

/// Start an import queue for a Cumulus collator that does not uses any special authoring logic.
#[allow(clippy::type_complexity)]
pub fn import_queue<Block: BlockT, I>(
    block_import: I,
    spawner: &impl SpawnEssentialNamed,
    registry: Option<&Registry>,
) -> ClientResult<BasicQueue<Block>>
where
    I: BlockImport<Block, Error = ConsensusError> + Send + Sync + 'static,
{
    Ok(BasicQueue::new(
        Verifier::default(),
        SharedBlockImport::new(block_import),
        None,
        spawner,
        registry,
    ))
}
