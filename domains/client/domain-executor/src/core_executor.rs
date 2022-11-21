use crate::core_bundle_processor::CoreBundleProcessor;
use crate::core_bundle_producer::CoreBundleProducer;
use crate::domain_block_processor::DomainBlockProcessor;
use crate::fraud_proof::FraudProofGenerator;
use crate::utils::BlockInfo;
use crate::{BundleSender, TransactionFor};
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use futures::channel::mpsc;
use futures::{FutureExt, Stream};
use sc_client_api::{AuxStore, BlockBackend, ProofProvider};
use sc_consensus::ForkChoiceStrategy;
use sc_network::NetworkService;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::SelectChain;
use sp_consensus_slots::Slot;
use sp_core::traits::{CodeExecutor, SpawnEssentialNamed, SpawnNamed};
use sp_domains::{DomainId, ExecutorApi};
use sp_keystore::SyncCryptoStorePtr;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{
    Block as BlockT, HashFor, Header as HeaderT, NumberFor, One, Saturating, Zero,
};
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;
use system_runtime_primitives::SystemDomainApi;

/// The implementation of the Domain `Executor`.
pub struct Executor<Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E>
where
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
    for Executor<Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E>
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
    Executor<Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E>
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
    /// Create a new instance.
    #[allow(clippy::too_many_arguments)]
    pub async fn new<SE, SC, IBNS, NSNS>(
        domain_id: DomainId,
        system_domain_client: Arc<SClient>,
        primary_chain_client: Arc<PClient>,
        primary_network: Arc<NetworkService<PBlock, PBlock::Hash>>,
        spawn_essential: &SE,
        select_chain: &SC,
        imported_block_notification_stream: IBNS,
        new_slot_notification_stream: NSNS,
        client: Arc<Client>,
        spawner: Box<dyn SpawnNamed + Send + Sync>,
        transaction_pool: Arc<TransactionPool>,
        bundle_sender: Arc<BundleSender<Block, PBlock>>,
        backend: Arc<Backend>,
        code_executor: Arc<E>,
        is_authority: bool,
        keystore: SyncCryptoStorePtr,
        block_import_throttling_buffer_size: u32,
    ) -> Result<Self, sp_consensus::Error>
    where
        SE: SpawnEssentialNamed,
        SC: SelectChain<PBlock>,
        IBNS: Stream<Item = (NumberFor<PBlock>, ForkChoiceStrategy, mpsc::Sender<()>)>
            + Send
            + 'static,
        NSNS: Stream<Item = (Slot, Blake2b256Hash)> + Send + 'static,
    {
        let active_leaves = active_leaves(primary_chain_client.as_ref(), select_chain).await?;

        let bundle_producer = CoreBundleProducer::new(
            domain_id,
            system_domain_client.clone(),
            client.clone(),
            transaction_pool.clone(),
            bundle_sender,
            is_authority,
            keystore.clone(),
        );

        let fraud_proof_generator = FraudProofGenerator::new(
            client.clone(),
            spawner.clone(),
            backend.clone(),
            code_executor,
        );

        let domain_block_processor = DomainBlockProcessor::new(
            domain_id,
            client.clone(),
            primary_chain_client.clone(),
            primary_network,
            backend.clone(),
            fraud_proof_generator.clone(),
        );

        let bundle_processor = CoreBundleProcessor::new(
            domain_id,
            primary_chain_client.clone(),
            system_domain_client,
            client.clone(),
            backend.clone(),
            is_authority,
            keystore,
            spawner.clone(),
            domain_block_processor,
        );

        spawn_essential.spawn_essential_blocking(
            "executor-worker",
            None,
            crate::core_domain_worker::start_worker(
                domain_id,
                primary_chain_client.clone(),
                client.clone(),
                bundle_producer,
                bundle_processor,
                imported_block_notification_stream,
                new_slot_notification_stream,
                active_leaves,
                block_import_throttling_buffer_size,
            )
            .boxed(),
        );

        Ok(Self {
            primary_chain_client,
            client,
            spawner,
            transaction_pool,
            backend,
            fraud_proof_generator,
            _phantom_data: PhantomData::default(),
        })
    }

    pub fn fraud_proof_generator(&self) -> FraudProofGenerator<Block, PBlock, Client, Backend, E> {
        self.fraud_proof_generator.clone()
    }
}

/// Returns the active leaves the overseer should start with.
///
/// The longest chain is used as the fork choice for the leaves as the primary block's fork choice
/// is only available in the imported primary block notifications.
async fn active_leaves<PBlock, PClient, SC>(
    client: &PClient,
    select_chain: &SC,
) -> Result<Vec<BlockInfo<PBlock>>, sp_consensus::Error>
where
    PBlock: BlockT,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    SC: SelectChain<PBlock>,
{
    let best_block = select_chain.best_chain().await?;

    // No leaves if starting from the genesis.
    if best_block.number().is_zero() {
        return Ok(Vec::new());
    }

    let mut leaves = select_chain
        .leaves()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|hash| {
            let number = client.number(hash).ok()??;

            // Only consider leaves that are in maximum an uncle of the best block.
            if number < best_block.number().saturating_sub(One::one()) || hash == best_block.hash()
            {
                return None;
            };

            let parent_hash = *client.header(BlockId::Hash(hash)).ok()??.parent_hash();

            Some(BlockInfo {
                hash,
                parent_hash,
                number,
                fork_choice: ForkChoiceStrategy::LongestChain,
            })
        })
        .collect::<Vec<_>>();

    // Sort by block number and get the maximum number of leaves
    leaves.sort_by_key(|b| b.number);

    leaves.push(BlockInfo {
        hash: best_block.hash(),
        parent_hash: *best_block.parent_hash(),
        number: *best_block.number(),
        fork_choice: ForkChoiceStrategy::LongestChain,
    });

    /// The maximum number of active leaves we forward to the [`Overseer`] on startup.
    const MAX_ACTIVE_LEAVES: usize = 4;

    Ok(leaves.into_iter().rev().take(MAX_ACTIVE_LEAVES).collect())
}
