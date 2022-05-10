//! Subspace executor.

#![warn(missing_docs)]

use codec::{Decode, Encode};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_executor::{executor_ext::ExecutionReceiptError, ExecutionReceipt, ExecutorApi};
use sp_runtime::{
    generic::BlockId,
    traits::{Block as BlockT, Header as HeaderT, NumberFor},
};
use std::marker::PhantomData;
use std::sync::Arc;

/// Executor externality extension.
pub struct ExecutorExtension<PBlock, C, Hash> {
    client: Arc<C>,
    _phantom: PhantomData<(PBlock, Hash)>,
}

impl<PBlock, C, Hash> Clone for ExecutorExtension<PBlock, C, Hash> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<PBlock, C, Hash> ExecutorExtension<PBlock, C, Hash>
where
    PBlock: BlockT,
    C: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + Send + Sync,
    C::Api: ExecutorApi<PBlock, Hash>,
    Hash: Encode + Decode,
{
    /// Constructs a new instance of [`ExecutorExtension`].
    pub fn new(client: Arc<C>) -> Self {
        Self {
            client,
            _phantom: PhantomData::<(PBlock, Hash)>,
        }
    }

    /// Verifies the execution receipt.
    pub fn check_execution_receipt(
        &self,
        execution_receipt: ExecutionReceipt<NumberFor<PBlock>, PBlock::Hash, Hash>,
    ) -> Result<(), ExecutionReceiptError> {
        let primary_hash =
            PBlock::Hash::decode(&mut execution_receipt.primary_hash.encode().as_slice())
                .expect("Block Hash must be the correct type; qed");

        // Ensure the block at which receipt was created is part of the history.
        let header = self
            .client
            .header(BlockId::Hash(primary_hash)).map_err(|e| {
                tracing::error!(target: "executor", error = ?e, ?primary_hash, "Unable to retrieve the header");
                ExecutionReceiptError::Blockchain
            })?
            .ok_or(ExecutionReceiptError::UnknownBlock)?;

        if *header.number() != execution_receipt.primary_number {
            return Err(ExecutionReceiptError::UnexpectedPrimaryNumber);
        }

        Ok(())
    }
}

impl<PBlock, C, Hash> sp_executor::executor_ext::Externalities
    for ExecutorExtension<PBlock, C, Hash>
where
    PBlock: BlockT,
    C: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + Send + Sync,
    C::Api: ExecutorApi<PBlock, Hash>,
    Hash: Encode + Decode + Send + Sync,
{
    fn check_execution_receipt(
        &self,
        encoded_execution_receipt: Vec<u8>,
    ) -> Result<(), ExecutionReceiptError> {
        let execution_receipt =
            ExecutionReceipt::decode(&mut encoded_execution_receipt.as_slice())
            .map_err(|e| {
                tracing::error!(target: "executor", error = ?e, "Failed to decode the signed execution receipt");
                ExecutionReceiptError::Decode
            })?;
        ExecutorExtension::check_execution_receipt(self, execution_receipt)
    }
}
