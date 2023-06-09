use crate::fraud_proof::FraudProofGenerator;
use crate::gossip_message_validator::{GossipMessageError, GossipMessageValidator};
use crate::parent_chain::ParentChainInterface;
use crate::TransactionFor;
use domain_client_executor_gossip::{Action, GossipMessageHandler};
use domain_runtime_primitives::DomainCoreApi;
use sc_client_api::{AuxStore, BlockBackend, ProofProvider, StateBackendFor};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::{CodeExecutor, SpawnNamed};
use sp_core::H256;
use sp_domains::Bundle;
use sp_runtime::traits::{Block as BlockT, HashFor, NumberFor};
use std::sync::Arc;
use system_runtime_primitives::SystemDomainApi;

/// Gossip message validator for system domain.
pub struct SystemGossipMessageValidator<
    Block,
    PBlock,
    Client,
    PClient,
    TransactionPool,
    Backend,
    E,
    ParentChain,
> {
    client: Arc<Client>,
    gossip_message_validator: GossipMessageValidator<
        Block,
        PBlock,
        PBlock,
        Client,
        PClient,
        Backend,
        E,
        TransactionPool,
        ParentChain,
    >,
}

impl<Block, PBlock, Client, PClient, TransactionPool, Backend, E, ParentChain> Clone
    for SystemGossipMessageValidator<
        Block,
        PBlock,
        Client,
        PClient,
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
            client: self.client.clone(),
            gossip_message_validator: self.gossip_message_validator.clone(),
        }
    }
}

impl<Block, PBlock, Client, PClient, TransactionPool, Backend, E, ParentChain>
    SystemGossipMessageValidator<
        Block,
        PBlock,
        Client,
        PClient,
        TransactionPool,
        Backend,
        E,
        ParentChain,
    >
where
    Block: BlockT,
    PBlock: BlockT,
    Block::Hash: Into<H256>,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + 'static,
    Client::Api: DomainCoreApi<Block>
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash, Block::Hash>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    PClient: HeaderBackend<PBlock> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    E: CodeExecutor,
    ParentChain: ParentChainInterface<Block, PBlock> + Send + Sync + Clone + 'static,
{
    pub fn new(
        parent_chain: ParentChain,
        client: Arc<Client>,
        spawner: Box<dyn SpawnNamed + Send + Sync>,
        transaction_pool: Arc<TransactionPool>,
        fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, PClient, Backend, E>,
    ) -> Self {
        let gossip_message_validator = GossipMessageValidator::new(
            client.clone(),
            spawner,
            parent_chain,
            transaction_pool,
            fraud_proof_generator,
        );
        Self {
            client,
            gossip_message_validator,
        }
    }

    pub fn validate_gossiped_bundle(
        &self,
        bundle: &Bundle<Block::Extrinsic, NumberFor<PBlock>, PBlock::Hash, Block::Hash>,
    ) -> Result<Action, GossipMessageError> {
        self.gossip_message_validator
            .check_bundle_equivocation(bundle)?;

        let bundle_exists = false;

        if bundle_exists {
            Ok(Action::Empty)
        } else {
            if !bundle.header.verify_signature() {
                return Err(GossipMessageError::BadBundleSignature);
            }

            // TODO: validate the bundle election.

            let domain_id = bundle.domain_id();

            self.gossip_message_validator
                .validate_bundle_receipts(&bundle.receipts, domain_id)?;

            let at = bundle.header.bundle_solution.creation_block_hash();

            self.gossip_message_validator.validate_bundle_transactions(
                &bundle.extrinsics,
                domain_id,
                *at,
            )?;

            // TODO: all checks pass, add to the bundle pool

            Ok(Action::RebroadcastBundle)
        }
    }
}

impl<Block, PBlock, Client, PClient, TransactionPool, Backend, E, ParentChain>
    GossipMessageHandler<PBlock, Block>
    for SystemGossipMessageValidator<
        Block,
        PBlock,
        Client,
        PClient,
        TransactionPool,
        Backend,
        E,
        ParentChain,
    >
where
    Block: BlockT,
    PBlock: BlockT,
    Block::Hash: Into<H256>,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + ProvideRuntimeApi<Block>
        + AuxStore
        + ProofProvider<Block>
        + 'static,
    Client::Api: DomainCoreApi<Block>
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash, Block::Hash>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    Backend: sc_client_api::Backend<Block> + 'static,
    PClient: HeaderBackend<PBlock> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    E: CodeExecutor,
    ParentChain: ParentChainInterface<Block, PBlock> + Send + Sync + Clone + 'static,
{
    type Error = GossipMessageError;

    fn on_bundle(
        &self,
        bundle: &Bundle<Block::Extrinsic, NumberFor<PBlock>, PBlock::Hash, Block::Hash>,
    ) -> Result<Action, Self::Error> {
        self.validate_gossiped_bundle(bundle)
    }
}
