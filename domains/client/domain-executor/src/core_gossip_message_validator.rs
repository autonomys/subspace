use crate::fraud_proof::{find_trace_mismatch, FraudProofError, FraudProofGenerator};
use crate::{ExecutionReceiptFor, TransactionFor, LOG_TARGET};
use codec::{Decode, Encode};
use domain_client_executor_gossip::{Action, GossipMessageHandler};
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use futures::FutureExt;
use sc_client_api::{AuxStore, BlockBackend, ProofProvider};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::{CodeExecutor, SpawnNamed};
use sp_core::H256;
use sp_domains::fraud_proof::{BundleEquivocationProof, InvalidTransactionProof};
use sp_domains::{Bundle, ExecutorApi, ExecutorPublicKey, SignedBundle};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, HashFor, Header as HeaderT, NumberFor};
use sp_runtime::RuntimeAppPublic;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::BlockNumber;
use system_runtime_primitives::SystemDomainApi;

/// The implementation of the Domain `Executor`.
pub struct CoreGossipMessageValidator<
    Block,
    SBlock,
    PBlock,
    Client,
    SClient,
    PClient,
    TransactionPool,
    Backend,
    E,
> where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
{
    // TODO: no longer used in executor, revisit this with ParachainBlockImport together.
    primary_chain_client: Arc<PClient>,
    client: Arc<Client>,
    spawner: Box<dyn SpawnNamed + Send + Sync>,
    transaction_pool: Arc<TransactionPool>,
    backend: Arc<Backend>,
    fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, Backend, E>,
    _phantom_data: PhantomData<(SBlock, SClient)>,
}

impl<Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E> Clone
    for CoreGossipMessageValidator<
        Block,
        SBlock,
        PBlock,
        Client,
        SClient,
        PClient,
        TransactionPool,
        Backend,
        E,
    >
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            primary_chain_client: self.primary_chain_client.clone(),
            client: self.client.clone(),
            spawner: self.spawner.clone(),
            transaction_pool: self.transaction_pool.clone(),
            backend: self.backend.clone(),
            fraud_proof_generator: self.fraud_proof_generator.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E>
    CoreGossipMessageValidator<
        Block,
        SBlock,
        PBlock,
        Client,
        SClient,
        PClient,
        TransactionPool,
        Backend,
        E,
    >
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + 'static,
    Client::Api: DomainCoreApi<Block, AccountId>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<
            Block,
            StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
        >,
    for<'b> &'b Client: sc_consensus::BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + ProofProvider<SBlock> + 'static,
    SClient::Api:
        DomainCoreApi<SBlock, AccountId> + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    PClient: HeaderBackend<PBlock>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    Backend: sc_client_api::Backend<Block> + Send + Sync + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    E: CodeExecutor,
{
    pub fn new(
        primary_chain_client: Arc<PClient>,
        client: Arc<Client>,
        spawner: Box<dyn SpawnNamed + Send + Sync>,
        transaction_pool: Arc<TransactionPool>,
        backend: Arc<Backend>,
        fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, Backend, E>,
    ) -> Self {
        Self {
            primary_chain_client,
            client,
            spawner,
            transaction_pool,
            backend,
            fraud_proof_generator,
            _phantom_data: PhantomData::default(),
        }
    }

    /// The background is that a receipt received from the network points to a future block
    /// from the local view, so we need to wait for the receipt for the block at the same
    /// height to be produced locally in order to check the validity of the external receipt.
    async fn wait_for_local_future_receipt(
        &self,
        secondary_block_hash: Block::Hash,
        secondary_block_number: <Block::Header as HeaderT>::Number,
        tx: crossbeam::channel::Sender<
            sp_blockchain::Result<ExecutionReceiptFor<PBlock, Block::Hash>>,
        >,
    ) -> Result<(), GossipMessageError> {
        loop {
            match crate::aux_schema::load_execution_receipt(&*self.client, secondary_block_hash) {
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
                    if self.client.info().best_number >= secondary_block_number {
                        let local_block_hash = self
                            .client
                            .expect_block_hash_from_id(&BlockId::Number(secondary_block_number))?;
                        let local_receipt_result = crate::aux_schema::load_execution_receipt(
                            &*self.client,
                            local_block_hash,
                        )?
                        .ok_or_else(|| {
                            sp_blockchain::Error::Backend(format!(
                                "Execution receipt not found for {:?}",
                                local_block_hash
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

    fn validate_gossiped_execution_receipt(
        &self,
        signed_bundle_hash: H256,
        execution_receipt: &ExecutionReceiptFor<PBlock, Block::Hash>,
    ) -> Result<(), GossipMessageError> {
        let primary_number: BlockNumber = execution_receipt
            .primary_number
            .try_into()
            .unwrap_or_else(|_| panic!("Primary number must fit into u32; qed"));

        let head_receipt_number = self
            .primary_chain_client
            .runtime_api()
            .head_receipt_number(&BlockId::Hash(self.primary_chain_client.info().best_hash))?;
        let head_receipt_number: BlockNumber = head_receipt_number
            .try_into()
            .unwrap_or_else(|_| panic!("Primary number must fit into u32; qed"));

        // Just ignore it if the receipt is too old and has been pruned.
        if crate::aux_schema::target_receipt_is_pruned(head_receipt_number, primary_number) {
            return Ok(());
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
                        tracing::error!(
                            target: LOG_TARGET,
                            ?err,
                            "Error occurred while waiting for the local receipt"
                        );
                    }
                }
                .boxed(),
            );
            rx.recv()??
        };

        // TODO: What happens for this obvious error?
        if local_receipt.trace.len() != execution_receipt.trace.len() {}

        if let Some(trace_mismatch_index) = find_trace_mismatch(&local_receipt, execution_receipt) {
            let fraud_proof = self.fraud_proof_generator.generate_proof(
                trace_mismatch_index,
                &local_receipt,
                signed_bundle_hash,
            )?;

            self.primary_chain_client
                .runtime_api()
                .submit_fraud_proof_unsigned(
                    &BlockId::Hash(self.primary_chain_client.info().best_hash),
                    fraud_proof,
                )?;
        }

        Ok(())
    }
}

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

impl<Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E>
    GossipMessageHandler<PBlock, Block>
    for CoreGossipMessageValidator<
        Block,
        SBlock,
        PBlock,
        Client,
        SClient,
        PClient,
        TransactionPool,
        Backend,
        E,
    >
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + ProvideRuntimeApi<Block>
        + AuxStore
        + ProofProvider<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: DomainCoreApi<Block, AccountId>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<
            Block,
            StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
        >,
    for<'b> &'b Client: sc_consensus::BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + ProofProvider<SBlock> + 'static,
    SClient::Api:
        DomainCoreApi<SBlock, AccountId> + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    PClient: HeaderBackend<PBlock>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    Backend: sc_client_api::Backend<Block> + Send + Sync + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    E: CodeExecutor,
{
    type Error = GossipMessageError;

    fn on_bundle(
        &self,
        signed_bundle: &SignedBundle<
            Block::Extrinsic,
            NumberFor<PBlock>,
            PBlock::Hash,
            Block::Hash,
        >,
    ) -> Result<Action, Self::Error> {
        let signed_bundle_hash = signed_bundle.hash();

        let SignedBundle {
            bundle,
            proof_of_election,
            signature,
        } = signed_bundle;

        let check_equivocation =
            |_bundle: &Bundle<Block::Extrinsic, NumberFor<PBlock>, PBlock::Hash, Block::Hash>| {
                // TODO: check bundle equivocation
                let bundle_is_an_equivocation = false;
                if bundle_is_an_equivocation {
                    Some(BundleEquivocationProof::dummy_at(bundle.header.slot_number))
                } else {
                    None
                }
            };

        // A bundle equivocation occurs.
        if let Some(equivocation_proof) = check_equivocation(bundle) {
            // TODO: report to the system domain instead of primary chain.
            self.primary_chain_client
                .runtime_api()
                .submit_bundle_equivocation_proof_unsigned(
                    &BlockId::Hash(self.primary_chain_client.info().best_hash),
                    equivocation_proof,
                )?;
            return Err(GossipMessageError::BundleEquivocation);
        }

        let bundle_exists = false;

        if bundle_exists {
            Ok(Action::Empty)
        } else {
            let _primary_hash =
                PBlock::Hash::decode(&mut bundle.header.primary_hash.encode().as_slice())
                    .expect("Hash type must be correct");

            let executor_public_key = &proof_of_election.executor_public_key;

            if !executor_public_key.verify(&bundle.hash(), signature) {
                return Err(Self::Error::BadBundleSignature);
            }

            // TODO: validate the bundle election.

            // TODO: Validate the receipts correctly when the bundle gossip is re-enabled.
            for receipt in &bundle.receipts {
                self.validate_gossiped_execution_receipt(signed_bundle_hash, receipt)?;
            }

            for extrinsic in bundle.extrinsics.iter() {
                let tx_hash = self.transaction_pool.hash_of(extrinsic);

                if self.transaction_pool.ready_transaction(&tx_hash).is_some() {
                    // TODO: Set the status of each tx in the bundle to seen
                } else {
                    // TODO: check the legality
                    //
                    // if illegal => illegal tx proof
                    let invalid_transaction_proof = InvalidTransactionProof;

                    self.primary_chain_client
                        .runtime_api()
                        .submit_invalid_transaction_proof_unsigned(
                            &BlockId::Hash(self.primary_chain_client.info().best_hash),
                            invalid_transaction_proof,
                        )?;
                }
            }

            // TODO: all checks pass, add to the bundle pool

            Ok(Action::RebroadcastBundle)
        }
    }
}
