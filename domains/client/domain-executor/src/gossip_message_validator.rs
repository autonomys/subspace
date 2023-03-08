use crate::fraud_proof::{find_trace_mismatch, FraudProofError, FraudProofGenerator};
use crate::utils::to_number_primitive;
use crate::{ExecutionReceiptFor, TransactionFor};
use futures::FutureExt;
use sc_client_api::{AuxStore, BlockBackend, ProofProvider, StateBackendFor};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::{CodeExecutor, SpawnNamed};
use sp_core::H256;
use sp_domains::fraud_proof::FraudProof;
use sp_domains::{DomainId, ExecutorPublicKey};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, HashFor, Header as HeaderT, NumberFor};
use std::sync::Arc;
use subspace_core_primitives::BlockNumber;

/// Error type for domain gossip handling.
#[derive(Debug, thiserror::Error)]
pub enum GossipMessageError {
    #[error("Bundle equivocation error")]
    BundleEquivocation,
    #[error(transparent)]
    FraudProof(#[from] FraudProofError),
    #[error(transparent)]
    Client(Box<sp_blockchain::Error>),
    #[error(transparent)]
    RuntimeApi(#[from] sp_api::ApiError),
    #[error(transparent)]
    RecvError(#[from] crossbeam::channel::RecvError),
    #[error("Failed to send local receipt result because the channel is disconnected")]
    SendError,
    #[error("The signature of bundle is invalid")]
    BadBundleSignature,
    #[error("Invalid bundle author, got: {got}, expected: {expected}")]
    InvalidBundleAuthor {
        got: ExecutorPublicKey,
        expected: ExecutorPublicKey,
    },
}

impl From<sp_blockchain::Error> for GossipMessageError {
    fn from(error: sp_blockchain::Error) -> Self {
        Self::Client(Box::new(error))
    }
}

/// Base domain gossip message validator.
pub struct GossipMessageValidator<Block, PBlock, Client, Backend, E> {
    client: Arc<Client>,
    spawner: Box<dyn SpawnNamed + Send + Sync>,
    fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, Backend, E>,
}

impl<Block, PBlock, Client, Backend, E> Clone
    for GossipMessageValidator<Block, PBlock, Client, Backend, E>
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            spawner: self.spawner.clone(),
            fraud_proof_generator: self.fraud_proof_generator.clone(),
        }
    }
}

impl<Block, PBlock, Client, Backend, E> GossipMessageValidator<Block, PBlock, Client, Backend, E>
where
    Block: BlockT,
    PBlock: BlockT,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + 'static,
    Client::Api: sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    E: CodeExecutor,
{
    pub(crate) fn new(
        client: Arc<Client>,
        spawner: Box<dyn SpawnNamed + Send + Sync>,
        fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, Backend, E>,
    ) -> Self {
        Self {
            client,
            spawner,
            fraud_proof_generator,
        }
    }

    /// The background is that a receipt received from the network points to a future block
    /// from the local view, so we need to wait for the receipt for the block at the same
    /// height to be produced locally in order to check the validity of the external receipt.
    async fn wait_for_local_future_receipt(
        &self,
        block_hash: Block::Hash,
        block_number: <Block::Header as HeaderT>::Number,
        tx: crossbeam::channel::Sender<
            sp_blockchain::Result<ExecutionReceiptFor<PBlock, Block::Hash>>,
        >,
    ) -> Result<(), GossipMessageError> {
        loop {
            match crate::aux_schema::load_execution_receipt(&*self.client, block_hash) {
                Ok(Some(local_receipt)) => {
                    return tx
                        .send(Ok(local_receipt))
                        .map_err(|_| GossipMessageError::SendError)
                }
                Ok(None) => {
                    // TODO: test how this works under the primary forks.
                    //       ref https://github.com/subspace/subspace/pull/250#discussion_r804247551
                    //
                    // Whether or not the best execution chain number on primary chain has been
                    // updated, the local client has proceeded to a higher block, that means the receipt
                    // of `block_hash` received from the network does not match the local one,
                    // we should just send back the local receipt at the same height.
                    if self.client.info().best_number >= block_number {
                        let local_block_hash = self
                            .client
                            .expect_block_hash_from_id(&BlockId::Number(block_number))?;
                        let local_receipt_result = crate::aux_schema::load_execution_receipt(
                            &*self.client,
                            local_block_hash,
                        )?
                        .ok_or_else(|| {
                            sp_blockchain::Error::Backend(format!(
                                "Execution receipt not found for {local_block_hash:?}"
                            ))
                        });
                        return tx
                            .send(local_receipt_result)
                            .map_err(|_| GossipMessageError::SendError);
                    } else {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
                Err(e) => return tx.send(Err(e)).map_err(|_| GossipMessageError::SendError),
            }
        }
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn validate_execution_receipt<PCB>(
        &self,
        signed_bundle_hash: H256,
        execution_receipt: &ExecutionReceiptFor<PBlock, Block::Hash>,
        head_receipt_number: BlockNumber,
        domain_id: DomainId,
    ) -> Result<Option<FraudProof<NumberFor<PCB>, PCB::Hash>>, GossipMessageError>
    where
        PCB: BlockT,
    {
        let primary_number = to_number_primitive(execution_receipt.primary_number);

        // Just ignore it if the receipt is too old and has been pruned.
        if crate::aux_schema::target_receipt_is_pruned(head_receipt_number, primary_number) {
            return Ok(None);
        }

        let block_hash = execution_receipt.domain_hash;
        let block_number = primary_number.into();

        // TODO: more efficient execution receipt checking strategy?
        let local_receipt = if let Some(local_receipt) =
            crate::aux_schema::load_execution_receipt(&*self.client, block_hash)?
        {
            local_receipt
        } else {
            // Wait for the local execution receipt until it's ready.
            let (tx, rx) = crossbeam::channel::bounded::<
                sp_blockchain::Result<ExecutionReceiptFor<PBlock, Block::Hash>>,
            >(1);
            let executor = self.clone();
            self.spawner.spawn(
                "wait-for-local-execution-receipt",
                None,
                async move {
                    if let Err(err) = executor
                        .wait_for_local_future_receipt(block_hash, block_number, tx)
                        .await
                    {
                        tracing::error!(?err, "Error occurred while waiting for the local receipt");
                    }
                }
                .boxed(),
            );
            rx.recv()??
        };

        // TODO: What happens for this obvious error?
        if local_receipt.trace.len() != execution_receipt.trace.len() {}

        if let Some(trace_mismatch_index) = find_trace_mismatch(&local_receipt, execution_receipt) {
            let fraud_proof = self.fraud_proof_generator.generate_proof::<PCB>(
                domain_id,
                trace_mismatch_index,
                &local_receipt,
                signed_bundle_hash,
            )?;
            Ok(Some(fraud_proof))
        } else {
            Ok(None)
        }
    }
}
