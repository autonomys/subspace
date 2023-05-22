use crate::domain_block_processor::{DomainBlockProcessor, PendingPrimaryBlocks};
use crate::parent_chain::{CoreDomainParentChain, ParentChainInterface};
use crate::utils::translate_number_type;
use crate::TransactionFor;
use domain_block_preprocessor::runtime_api_full::RuntimeApiFull;
use domain_block_preprocessor::CoreDomainBlockPreprocessor;
use domain_runtime_primitives::{DomainCoreApi, InherentExtrinsicApi};
use sc_client_api::{AuxStore, BlockBackend, Finalizer, StateBackendFor};
use sc_consensus::BlockImport;
use sp_api::{CallApiAt, NumberFor, ProvideRuntimeApi};
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_core::traits::CodeExecutor;
use sp_domains::{DomainId, ExecutorApi};
use sp_keystore::KeystorePtr;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, HashFor};
use std::sync::Arc;
use system_runtime_primitives::SystemDomainApi;

pub(crate) struct CoreBundleProcessor<
    Block,
    SBlock,
    PBlock,
    Client,
    SClient,
    PClient,
    Backend,
    E,
    BI,
> where
    Block: BlockT,
{
    domain_id: DomainId,
    primary_chain_client: Arc<PClient>,
    system_domain_client: Arc<SClient>,
    parent_chain: CoreDomainParentChain<SClient, SBlock, PBlock>,
    client: Arc<Client>,
    backend: Arc<Backend>,
    keystore: KeystorePtr,
    core_domain_block_preprocessor: CoreDomainBlockPreprocessor<
        Block,
        PBlock,
        SBlock,
        PClient,
        SClient,
        RuntimeApiFull<Client>,
    >,
    domain_block_processor: DomainBlockProcessor<Block, PBlock, Client, PClient, Backend, E, BI>,
}

impl<Block, SBlock, PBlock, Client, SClient, PClient, Backend, E, BI> Clone
    for CoreBundleProcessor<Block, SBlock, PBlock, SClient, Client, PClient, Backend, E, BI>
where
    Block: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            primary_chain_client: self.primary_chain_client.clone(),
            system_domain_client: self.system_domain_client.clone(),
            parent_chain: self.parent_chain.clone(),
            client: self.client.clone(),
            backend: self.backend.clone(),
            keystore: self.keystore.clone(),
            core_domain_block_preprocessor: self.core_domain_block_preprocessor.clone(),
            domain_block_processor: self.domain_block_processor.clone(),
        }
    }
}

impl<Block, SBlock, PBlock, Client, SClient, PClient, Backend, E, BI>
    CoreBundleProcessor<Block, SBlock, PBlock, Client, SClient, PClient, Backend, E, BI>
where
    Block: BlockT,
    SBlock: BlockT,
    NumberFor<SBlock>: From<NumberFor<Block>>,
    SBlock::Hash: From<Block::Hash>,
    PBlock: BlockT,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + Finalizer<Block, Backend>
        + 'static,
    Client::Api: DomainCoreApi<Block>
        + MessengerApi<Block, NumberFor<Block>>
        + sp_block_builder::BlockBuilder<Block>
        + InherentExtrinsicApi<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    for<'b> &'b BI: BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api: DomainCoreApi<SBlock>
        + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>
        + MessengerApi<SBlock, NumberFor<SBlock>>,
    PClient: HeaderBackend<PBlock>
        + HeaderMetadata<PBlock, Error = sp_blockchain::Error>
        + BlockBackend<PBlock>
        + CallApiAt<PBlock>
        + ProvideRuntimeApi<PBlock>
        + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    E: CodeExecutor,
{
    pub(crate) fn new(
        domain_id: DomainId,
        primary_chain_client: Arc<PClient>,
        system_domain_client: Arc<SClient>,
        client: Arc<Client>,
        backend: Arc<Backend>,
        keystore: KeystorePtr,
        domain_block_processor: DomainBlockProcessor<
            Block,
            PBlock,
            Client,
            PClient,
            Backend,
            E,
            BI,
        >,
    ) -> Self {
        let parent_chain = CoreDomainParentChain::<SClient, SBlock, PBlock>::new(
            system_domain_client.clone(),
            domain_id,
        );
        let core_domain_block_preprocessor = CoreDomainBlockPreprocessor::new(
            domain_id,
            RuntimeApiFull::new(client.clone()),
            primary_chain_client.clone(),
            system_domain_client.clone(),
        );
        Self {
            domain_id,
            primary_chain_client,
            system_domain_client,
            parent_chain,
            client,
            backend,
            keystore,
            core_domain_block_preprocessor,
            domain_block_processor,
        }
    }

    // TODO: Handle the returned error properly, ref to https://github.com/subspace/subspace/pull/695#discussion_r926721185
    pub(crate) async fn process_bundles(
        self,
        primary_info: (PBlock::Hash, NumberFor<PBlock>),
    ) -> sp_blockchain::Result<()> {
        let (primary_hash, primary_number) = primary_info;

        tracing::debug!("Processing imported primary block #{primary_number},{primary_hash}");

        let maybe_pending_primary_blocks = self
            .domain_block_processor
            .pending_imported_primary_blocks(primary_hash, primary_number)?;

        if let Some(PendingPrimaryBlocks {
            initial_parent,
            primary_imports,
        }) = maybe_pending_primary_blocks
        {
            tracing::trace!(
                ?initial_parent,
                ?primary_imports,
                "Pending primary blocks to process"
            );

            let mut domain_parent = initial_parent;

            for primary_info in primary_imports {
                domain_parent = self
                    .process_bundles_at((primary_info.hash, primary_info.number), domain_parent)
                    .await?;
            }
        }

        Ok(())
    }

    async fn process_bundles_at(
        &self,
        primary_info: (PBlock::Hash, NumberFor<PBlock>),
        parent_info: (Block::Hash, NumberFor<Block>),
    ) -> sp_blockchain::Result<(Block::Hash, NumberFor<Block>)> {
        let (primary_hash, primary_number) = primary_info;
        let (parent_hash, parent_number) = parent_info;

        tracing::debug!(
            "Building a new domain block from primary block #{primary_number},{primary_hash} \
            on top of parent block #{parent_number},{parent_hash}"
        );

        let extrinsics = self
            .core_domain_block_preprocessor
            .preprocess_primary_block(primary_hash, parent_hash)?;

        let domain_block_result = self
            .domain_block_processor
            .process_domain_block(
                (primary_hash, primary_number),
                (parent_hash, parent_number),
                extrinsics,
                Default::default(),
            )
            .await?;

        // TODO: just make it compile for now, likely wrong, rethink about it.
        let system_domain_hash = self.system_domain_client.info().best_hash;

        let head_receipt_number = self
            .system_domain_client
            .runtime_api()
            .head_receipt_number(system_domain_hash, self.domain_id)?;
        let head_receipt_number =
            translate_number_type::<NumberFor<SBlock>, NumberFor<Block>>(head_receipt_number);

        // TODO: can be re-enabled once the TODO above is resolved
        // assert!(
        // domain_block_result.header_number > head_receipt_number,
        // "Consensus chain number must larger than execution chain number by at least 1"
        // );

        let oldest_receipt_number = self
            .system_domain_client
            .runtime_api()
            .oldest_receipt_number(system_domain_hash, self.domain_id)?;
        let oldest_receipt_number =
            translate_number_type::<NumberFor<SBlock>, NumberFor<Block>>(oldest_receipt_number);

        let built_block_info = (
            domain_block_result.header_hash,
            domain_block_result.header_number,
        );

        if let Some(fraud_proof) = self
            .domain_block_processor
            .on_domain_block_processed::<SBlock>(
                primary_hash,
                domain_block_result,
                head_receipt_number,
                oldest_receipt_number,
            )?
        {
            self.parent_chain.submit_fraud_proof_unsigned(fraud_proof)?;
        }

        Ok(built_block_info)
    }
}
