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

use crate::notification::{SubspaceNotificationSender, SubspaceNotificationStream};
use sc_consensus::import_queue::{BasicQueue, Verifier as VerifierT};
use sc_consensus::{
    BlockCheckParams, BlockImport, BlockImportParams, ForkChoiceStrategy, ImportResult,
};
use sp_blockchain::Result as ClientResult;
use sp_consensus::error::Error as ConsensusError;
use sp_consensus::{BlockOrigin, CacheKeyId};
use sp_core::traits::SpawnEssentialNamed;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use substrate_prometheus_endpoint::Registry;

/// Secondary chain specific block import.
///
/// This is used to set `block_import_params.fork_choice` to `false` as long as the block origin is
/// not `NetworkInitialSync`. The best block for secondary chain is determined by the primary chain.
/// Meaning we will update the best block, as it is included by the primary chain.
struct SecondaryChainBlockImport<I, Number>
where
    Number: Clone + Send + Sync + Debug + 'static,
{
    inner: I,
    imported_block_notification_sender: SubspaceNotificationSender<Number>,
}

impl<I, Number> SecondaryChainBlockImport<I, Number>
where
    Number: Clone + Send + Sync + Debug + 'static,
{
    /// Create a new instance.
    fn new(
        inner: I,
        imported_block_notification_sender: SubspaceNotificationSender<Number>,
    ) -> Self {
        Self {
            inner,
            imported_block_notification_sender,
        }
    }
}

#[async_trait::async_trait]
impl<Block, I> BlockImport<Block> for SecondaryChainBlockImport<I, NumberFor<Block>>
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
        self.inner.check_block(block).await
    }

    async fn import_block(
        &mut self,
        mut block_import_params: BlockImportParams<Block, Self::Transaction>,
        cache: HashMap<CacheKeyId, Vec<u8>>,
    ) -> Result<ImportResult, Self::Error> {
        // Best block is determined by the primary chain, or if we are doing the initial sync
        // we import all blocks as new best.
        let number = *block_import_params.header.number();
        block_import_params.fork_choice = Some(ForkChoiceStrategy::Custom(
            block_import_params.origin == BlockOrigin::NetworkInitialSync,
        ));
        let import_result = self.inner.import_block(block_import_params, cache).await?;
        self.imported_block_notification_sender
            .notify(move || number);
        Ok(import_result)
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
    ) -> Result<
        (
            BlockImportParams<Block, ()>,
            Option<Vec<(CacheKeyId, Vec<u8>)>>,
        ),
        String,
    > {
        block_params.post_hash = Some(block_params.header.hash());

        Ok((block_params, None))
    }
}

/// Start an import queue for a Cumulus collator that does not uses any special authoring logic.
#[allow(clippy::type_complexity)]
pub fn import_queue<Block: BlockT, I>(
    block_import: I,
    spawner: &impl SpawnEssentialNamed,
    registry: Option<&Registry>,
) -> ClientResult<(
    BasicQueue<Block, I::Transaction>,
    SubspaceNotificationStream<NumberFor<Block>>,
)>
where
    I: BlockImport<Block, Error = ConsensusError> + Send + Sync + 'static,
    I::Transaction: Send,
{
    let (imported_block_notification_sender, imported_block_notification_receiver) =
        crate::notification::channel("system_domain_imported_block_notification_stream");
    Ok((
        BasicQueue::new(
            Verifier::default(),
            Box::new(SecondaryChainBlockImport::<I, NumberFor<Block>>::new(
                block_import,
                imported_block_notification_sender,
            )),
            None,
            spawner,
            registry,
        ),
        imported_block_notification_receiver,
    ))
}
