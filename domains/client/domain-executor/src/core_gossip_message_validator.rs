use crate::fraud_proof::FraudProofGenerator;
use crate::gossip_message_validator::{GossipMessageError, GossipMessageValidator};
use crate::{ExecutionReceiptFor, TransactionFor};
use domain_client_executor_gossip::{Action, GossipMessageHandler};
use sc_client_api::{AuxStore, BlockBackend, ProofProvider};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::{CodeExecutor, SpawnNamed};
use sp_core::H256;
use sp_domains::fraud_proof::{BundleEquivocationProof, InvalidTransactionProof};
use sp_domains::{Bundle, ExecutorApi, SignedBundle};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, HashFor, NumberFor};
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
    transaction_pool: Arc<TransactionPool>,
    gossip_message_validator: GossipMessageValidator<Block, PBlock, Client, PClient, Backend, E>,
    _phantom_data: PhantomData<(SBlock, SClient, Backend)>,
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
            transaction_pool: self.transaction_pool.clone(),
            gossip_message_validator: self.gossip_message_validator.clone(),
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
    Client::Api: sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<
            Block,
            StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
        >,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api: SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    E: CodeExecutor,
{
    pub fn new(
        primary_chain_client: Arc<PClient>,
        client: Arc<Client>,
        spawner: Box<dyn SpawnNamed + Send + Sync>,
        transaction_pool: Arc<TransactionPool>,
        fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, Backend, E>,
    ) -> Self {
        let gossip_message_validator = GossipMessageValidator::new(
            primary_chain_client.clone(),
            client.clone(),
            spawner,
            fraud_proof_generator,
        );
        Self {
            primary_chain_client,
            client,
            transaction_pool,
            gossip_message_validator,
            _phantom_data: PhantomData::default(),
        }
    }

    fn validate_gossiped_execution_receipt(
        &self,
        signed_bundle_hash: H256,
        execution_receipt: &ExecutionReceiptFor<PBlock, Block::Hash>,
    ) -> Result<(), GossipMessageError> {
        let head_receipt_number = self
            .primary_chain_client
            .runtime_api()
            .head_receipt_number(&BlockId::Hash(self.primary_chain_client.info().best_hash))?;
        let head_receipt_number: BlockNumber = head_receipt_number
            .try_into()
            .unwrap_or_else(|_| panic!("Primary number must fit into u32; qed"));

        if let Some(fraud_proof) = self.gossip_message_validator.validate_execution_receipt(
            signed_bundle_hash,
            execution_receipt,
            head_receipt_number,
        )? {
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
        + 'static,
    Client::Api: sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<
            Block,
            StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
        >,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api: SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    Backend: sc_client_api::Backend<Block> + 'static,
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
