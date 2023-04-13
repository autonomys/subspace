use crate::fraud_proof::FraudProofGenerator;
use crate::gossip_message_validator::{GossipMessageError, GossipMessageValidator};
use crate::parent_chain::ParentChainInterface;
use crate::TransactionFor;
use domain_client_executor_gossip::{Action, GossipMessageHandler};
use sc_client_api::{AuxStore, BlockBackend, ProofProvider, StateBackendFor};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::{CodeExecutor, SpawnNamed};
use sp_domains::SignedBundle;
use sp_runtime::traits::{Block as BlockT, HashFor, NumberFor};
use sp_runtime::RuntimeAppPublic;
use std::marker::PhantomData;
use std::sync::Arc;
use system_runtime_primitives::SystemDomainApi;

/// Gossip message validator for core domain.
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
    ParentChain,
> where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
{
    client: Arc<Client>,
    gossip_message_validator: GossipMessageValidator<
        Block,
        PBlock,
        SBlock,
        Client,
        PClient,
        Backend,
        E,
        TransactionPool,
        ParentChain,
    >,
    _phantom_data: PhantomData<SClient>,
}

impl<Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E, ParentChain>
    Clone
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
        ParentChain,
    >
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
    ParentChain: Clone,
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            gossip_message_validator: self.gossip_message_validator.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E, ParentChain>
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
        ParentChain,
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
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api: SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    PClient: HeaderBackend<PBlock> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    E: CodeExecutor,
    ParentChain: ParentChainInterface<SBlock> + Send + Sync + Clone + 'static,
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
            _phantom_data: PhantomData::default(),
        }
    }
}

impl<Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E, ParentChain>
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
        ParentChain,
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
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api: SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    PClient: HeaderBackend<PBlock> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    E: CodeExecutor,
    ParentChain: ParentChainInterface<SBlock> + Send + Sync + Clone + 'static,
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
        let SignedBundle {
            bundle,
            bundle_solution,
            signature,
        } = signed_bundle;

        self.gossip_message_validator
            .check_bundle_equivocation(bundle)?;

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

            self.gossip_message_validator
                .validate_bundle_receipts(&bundle.receipts, domain_id)?;

            self.gossip_message_validator
                .validate_bundle_transactions(&bundle.extrinsics, domain_id)?;

            // TODO: all checks pass, add to the bundle pool

            Ok(Action::RebroadcastBundle)
        }
    }
}
