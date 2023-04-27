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

use futures::lock::Mutex;
use sc_consensus::import_queue::{BasicQueue, Verifier as VerifierT};
use sc_consensus::{BlockCheckParams, BlockImport, BlockImportParams, ImportResult};
use sp_blockchain::Result as ClientResult;
use sp_consensus::error::Error as ConsensusError;
use sp_core::traits::SpawnEssentialNamed;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use std::marker::PhantomData;
use substrate_prometheus_endpoint::Registry;

/// Domain specific block import.
/// We use it to wrap Custom Block import the Core domain would need and share it between tasks.
pub struct DomainBlockImport<I> {
    inner: Mutex<I>,
}

impl<I> DomainBlockImport<I> {
    /// Create a new instance.
    pub fn new(inner: I) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }
}

#[async_trait::async_trait]
impl<Block, I> BlockImport<Block> for &DomainBlockImport<I>
where
    Block: BlockT,
    I: BlockImport<Block> + Send,
{
    type Error = I::Error;
    type Transaction = I::Transaction;

    async fn check_block(
        &mut self,
        block: BlockCheckParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        let mut inner = self.inner.lock().await;
        inner.check_block(block).await
    }

    async fn import_block(
        &mut self,
        block_import_params: BlockImportParams<Block, Self::Transaction>,
    ) -> Result<ImportResult, Self::Error> {
        let mut inner = self.inner.lock().await;
        inner.import_block(block_import_params).await
    }
}

/// A verifier that just checks the inherents.
pub struct Verifier<Block> {
    _marker: PhantomData<Block>,
}

impl<Block> Default for Verifier<Block> {
    /// Create a new instance.
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
        &mut self,
        mut block_params: BlockImportParams<Block, ()>,
    ) -> Result<BlockImportParams<Block, ()>, String> {
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
) -> ClientResult<BasicQueue<Block, I::Transaction>>
where
    I: BlockImport<Block, Error = ConsensusError> + Send + Sync + 'static,
    I::Transaction: Send,
{
    Ok(BasicQueue::new(
        Verifier::default(),
        Box::new(block_import),
        None,
        spawner,
        registry,
    ))
}
