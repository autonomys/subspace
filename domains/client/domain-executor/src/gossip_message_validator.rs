use crate::fraud_proof::{find_trace_mismatch, FraudProofError, FraudProofGenerator};
use crate::parent_chain::ParentChainInterface;
use crate::utils::to_number_primitive;
use crate::{ExecutionReceiptFor, TransactionFor};
use codec::Encode;
use domain_runtime_primitives::{CheckTxValidityError, DomainCoreApi};
use futures::FutureExt;
use sc_client_api::{AuxStore, BlockBackend, ProofProvider, StateBackendFor};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::{CodeExecutor, SpawnNamed};
use sp_core::H256;
use sp_domains::fraud_proof::{BundleEquivocationProof, InvalidTransactionProof};
use sp_domains::{Bundle, DomainId, ExecutorPublicKey};
use sp_runtime::traits::{Block as BlockT, HashFor, Header as HeaderT, NumberFor};
use sp_trie::StorageProof;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::BlockNumber;

type FraudProof<ParentChainBlock> = sp_domains::fraud_proof::FraudProof<
    NumberFor<ParentChainBlock>,
    <ParentChainBlock as BlockT>::Hash,
>;

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
    #[inline]
    fn from(error: sp_blockchain::Error) -> Self {
        Self::Client(Box::new(error))
    }
}

/// Base domain gossip message validator.
pub struct GossipMessageValidator<
    Block,
    PBlock,
    ParentChainBlock,
    Client,
    PClient,
    Backend,
    E,
    TransactionPool,
    ParentChain,
> {
    client: Arc<Client>,
    spawner: Box<dyn SpawnNamed + Send + Sync>,
    parent_chain: ParentChain,
    transaction_pool: Arc<TransactionPool>,
    fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, PClient, Backend, E>,
    _phantom_data: PhantomData<ParentChainBlock>,
}

impl<
        Block,
        PBlock,
        ParentChainBlock,
        Client,
        PClient,
        Backend,
        E,
        TransactionPool,
        ParentChain,
    > Clone
    for GossipMessageValidator<
        Block,
        PBlock,
        ParentChainBlock,
        Client,
        PClient,
        Backend,
        E,
        TransactionPool,
        ParentChain,
    >
where
    ParentChain: Clone,
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            spawner: self.spawner.clone(),
            parent_chain: self.parent_chain.clone(),
            transaction_pool: self.transaction_pool.clone(),
            fraud_proof_generator: self.fraud_proof_generator.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<
        Block,
        PBlock,
        ParentChainBlock,
        Client,
        PClient,
        Backend,
        E,
        TransactionPool,
        ParentChain,
    >
    GossipMessageValidator<
        Block,
        PBlock,
        ParentChainBlock,
        Client,
        PClient,
        Backend,
        E,
        TransactionPool,
        ParentChain,
    >
where
    Block: BlockT,
    PBlock: BlockT,
    ParentChainBlock: BlockT,
    Block::Hash: Into<H256>,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + 'static,
    Client::Api: DomainCoreApi<Block>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    PClient: HeaderBackend<PBlock> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    E: CodeExecutor,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    ParentChain: ParentChainInterface<Block, ParentChainBlock> + Send + Sync + Clone + 'static,
{
    pub(crate) fn new(
        client: Arc<Client>,
        spawner: Box<dyn SpawnNamed + Send + Sync>,
        parent_chain: ParentChain,
        transaction_pool: Arc<TransactionPool>,
        fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, PClient, Backend, E>,
    ) -> Self {
        Self {
            client,
            spawner,
            parent_chain,
            transaction_pool,
            fraud_proof_generator,
            _phantom_data: Default::default(),
        }
    }

    pub(crate) fn check_bundle_equivocation(
        &self,
        bundle: &Bundle<Block::Extrinsic, NumberFor<PBlock>, PBlock::Hash, Block::Hash>,
    ) -> Result<(), GossipMessageError> {
        // TODO: check bundle equivocation
        let bundle_is_an_equivocation = false;

        if bundle_is_an_equivocation {
            let equivocation_proof =
                BundleEquivocationProof::dummy_at(bundle.sealed_header.header.slot_number);
            let fraud_proof =
                FraudProof::<ParentChainBlock>::BundleEquivocation(equivocation_proof);
            self.parent_chain.submit_fraud_proof_unsigned(fraud_proof)?;
            Err(GossipMessageError::BundleEquivocation)
        } else {
            Ok(())
        }
    }

    pub(crate) fn validate_bundle_receipts(
        &self,
        receipts: &[ExecutionReceiptFor<PBlock, Block::Hash>],
        domain_id: DomainId,
    ) -> Result<(), GossipMessageError> {
        let head_receipt_number = self
            .parent_chain
            .head_receipt_number(self.parent_chain.best_hash())?;
        let head_receipt_number = to_number_primitive(head_receipt_number);

        for receipt in receipts {
            if let Some(fraud_proof) =
                self.validate_execution_receipt(receipt, head_receipt_number, domain_id)?
            {
                self.parent_chain.submit_fraud_proof_unsigned(fraud_proof)?;
            }
        }

        Ok(())
    }

    pub(crate) fn validate_bundle_transactions(
        &self,
        extrinsics: &[Block::Extrinsic],
        domain_id: DomainId,
        at: Block::Hash,
    ) -> Result<(), GossipMessageError> {
        let block_number = self
            .client
            .number(at)?
            .ok_or_else(|| sp_blockchain::Error::Backend(format!("Number for #{at} not found")))?;

        for (_index, extrinsic) in extrinsics.iter().enumerate() {
            let tx_hash = self.transaction_pool.hash_of(extrinsic);

            if self.transaction_pool.ready_transaction(&tx_hash).is_some() {
                // TODO: Set the status of each tx in the bundle to seen
            } else if let Err(transaction_fee_err) = self
                .client
                .runtime_api()
                .check_transaction_validity(at, extrinsic.clone(), at)?
            {
                let storage_proof = match transaction_fee_err {
                    CheckTxValidityError::Lookup => StorageProof::empty(),
                    CheckTxValidityError::InvalidTransaction {
                        error,
                        storage_keys,
                    } => {
                        tracing::debug!(
                            ?extrinsic,
                            ?error,
                            "Invalid transaction at #{block_number},{at}"
                        );
                        self.client
                            .read_proof(at, &mut storage_keys.iter().map(|s| s.as_slice()))?
                    }
                };

                // TODO: Include verifiable bundle solution
                let invalid_transaction_proof = InvalidTransactionProof {
                    domain_id,
                    block_number: to_number_primitive(block_number),
                    domain_block_hash: at.into(),
                    invalid_extrinsic: extrinsic.encode(), // TODO: Verifiable invalid extrinsic
                    storage_proof,
                };

                let fraud_proof =
                    FraudProof::<ParentChainBlock>::InvalidTransaction(invalid_transaction_proof);

                self.parent_chain.submit_fraud_proof_unsigned(fraud_proof)?;
            }

            // TODO: also check invalid XDM?
        }

        Ok(())
    }

    /// The background is that a receipt received from the network points to a future block
    /// from the local view, so we need to wait for the receipt for the block at the same
    /// height to be produced locally in order to check the validity of the external receipt.
    #[allow(clippy::never_loop)]
    async fn wait_for_local_future_receipt(
        &self,
        primary_block_hash: PBlock::Hash,
        _block_number: <Block::Header as HeaderT>::Number,
        tx: crossbeam::channel::Sender<
            sp_blockchain::Result<ExecutionReceiptFor<PBlock, Block::Hash>>,
        >,
    ) -> Result<(), GossipMessageError> {
        loop {
            match crate::aux_schema::load_execution_receipt(&*self.client, primary_block_hash) {
                Ok(Some(local_receipt)) => {
                    return tx
                        .send(Ok(local_receipt))
                        .map_err(|_| GossipMessageError::SendError)
                }
                Ok(None) => {
                    unimplemented!(
                        "TODO: rework the following logic once the compact bundle is a thing"
                    )

                    /*
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
                    */
                }
                Err(e) => return tx.send(Err(e)).map_err(|_| GossipMessageError::SendError),
            }
        }
    }

    fn validate_execution_receipt(
        &self,
        execution_receipt: &ExecutionReceiptFor<PBlock, Block::Hash>,
        head_receipt_number: BlockNumber,
        domain_id: DomainId,
    ) -> Result<Option<FraudProof<ParentChainBlock>>, GossipMessageError> {
        let primary_number = to_number_primitive(execution_receipt.primary_number);

        // Just ignore it if the receipt is too old and has been pruned.
        if crate::aux_schema::target_receipt_is_pruned(head_receipt_number, primary_number) {
            return Ok(None);
        }

        let primary_block_hash = execution_receipt.primary_hash;
        let block_number = primary_number.into();

        // TODO: more efficient execution receipt checking strategy?
        let local_receipt = if let Some(local_receipt) =
            crate::aux_schema::load_execution_receipt(&*self.client, primary_block_hash)?
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
                        .wait_for_local_future_receipt(primary_block_hash, block_number, tx)
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

        if let Some(trace_mismatch_index) =
            find_trace_mismatch(&local_receipt.trace, &execution_receipt.trace)
        {
            let fraud_proof = self
                .fraud_proof_generator
                .generate_invalid_state_transition_proof::<ParentChainBlock>(
                    domain_id,
                    trace_mismatch_index,
                    &local_receipt,
                    execution_receipt.hash(),
                )?;
            Ok(Some(fraud_proof))
        } else {
            Ok(None)
        }
    }
}
