use crate::fraud_proof::FraudProofGenerator;
use crate::gossip_message_validator::{GossipMessageError, GossipMessageValidator};
use crate::parent_chain::ParentChainInterface;
use crate::TransactionFor;
use domain_client_executor_gossip::{Action, GossipMessageHandler};
use sc_client_api::{AuxStore, BlockBackend, ProofProvider, StateBackendFor};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::{CodeExecutor, SpawnNamed};
use sp_domains::fraud_proof::{BundleEquivocationProof, FraudProof, InvalidTransactionProof};
use sp_domains::{Bundle, SignedBundle};
use sp_runtime::traits::{Block as BlockT, HashFor, NumberFor};
use sp_runtime::RuntimeAppPublic;
use std::sync::Arc;
use system_runtime_primitives::SystemDomainApi;

/// Gossip message validator for system domain.
pub struct SystemGossipMessageValidator<
    Block,
    PBlock,
    Client,
    TransactionPool,
    Backend,
    E,
    ParentChain,
> {
    parent_chain: ParentChain,
    client: Arc<Client>,
    transaction_pool: Arc<TransactionPool>,
    gossip_message_validator: GossipMessageValidator<Block, PBlock, Client, Backend, E>,
}

impl<Block, PBlock, Client, TransactionPool, Backend, E, ParentChain> Clone
    for SystemGossipMessageValidator<
        Block,
        PBlock,
        Client,
        TransactionPool,
        Backend,
        E,
        ParentChain,
    >
where
    ParentChain: Clone,
{
    fn clone(&self) -> Self {
        Self {
            parent_chain: self.parent_chain.clone(),
            client: self.client.clone(),
            transaction_pool: self.transaction_pool.clone(),
            gossip_message_validator: self.gossip_message_validator.clone(),
        }
    }
}

impl<Block, PBlock, Client, TransactionPool, Backend, E, ParentChain>
    SystemGossipMessageValidator<Block, PBlock, Client, TransactionPool, Backend, E, ParentChain>
where
    Block: BlockT,
    PBlock: BlockT,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + 'static,
    Client::Api: SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    E: CodeExecutor,
    ParentChain: ParentChainInterface<PBlock>,
{
    pub fn new(
        parent_chain: ParentChain,
        client: Arc<Client>,
        spawner: Box<dyn SpawnNamed + Send + Sync>,
        transaction_pool: Arc<TransactionPool>,
        fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, Backend, E>,
    ) -> Self {
        let gossip_message_validator =
            GossipMessageValidator::new(client.clone(), spawner, fraud_proof_generator);
        Self {
            parent_chain,
            client,
            transaction_pool,
            gossip_message_validator,
        }
    }
}

impl<Block, PBlock, Client, TransactionPool, Backend, E, ParentChain>
    GossipMessageHandler<PBlock, Block>
    for SystemGossipMessageValidator<
        Block,
        PBlock,
        Client,
        TransactionPool,
        Backend,
        E,
        ParentChain,
    >
where
    Block: BlockT,
    PBlock: BlockT,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + ProvideRuntimeApi<Block>
        + AuxStore
        + ProofProvider<Block>
        + 'static,
    Client::Api: SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    E: CodeExecutor,
    ParentChain: ParentChainInterface<PBlock>,
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
            bundle_solution,
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
            let fraud_proof = FraudProof::BundleEquivocation(equivocation_proof);
            self.parent_chain.submit_fraud_proof_unsigned(fraud_proof)?;
            return Err(GossipMessageError::BundleEquivocation);
        }

        let bundle_exists = false;

        if bundle_exists {
            Ok(Action::Empty)
        } else {
            let executor_public_key = &bundle_solution.proof_of_election().executor_public_key;

            if !executor_public_key.verify(&bundle.hash(), signature) {
                return Err(Self::Error::BadBundleSignature);
            }

            // TODO: validate the bundle election.

            // TODO: Validate the receipts correctly when the bundle gossip is re-enabled.
            let domain_id = bundle_solution.proof_of_election().domain_id;
            for receipt in &bundle.receipts {
                self.gossip_message_validator
                    .validate_gossiped_execution_receipt::<PBlock, _>(
                        &self.parent_chain,
                        signed_bundle_hash,
                        receipt,
                        domain_id,
                    )?;
            }

            for extrinsic in bundle.extrinsics.iter() {
                let tx_hash = self.transaction_pool.hash_of(extrinsic);

                if self.transaction_pool.ready_transaction(&tx_hash).is_some() {
                    // TODO: Set the status of each tx in the bundle to seen
                } else {
                    // TODO: check the legality
                    //
                    // if illegal => illegal tx proof
                    let invalid_transaction_proof = InvalidTransactionProof { domain_id };
                    let fraud_proof = FraudProof::InvalidTransaction(invalid_transaction_proof);

                    self.parent_chain.submit_fraud_proof_unsigned(fraud_proof)?;
                }
            }

            // TODO: all checks pass, add to the bundle pool

            Ok(Action::RebroadcastBundle)
        }
    }
}
