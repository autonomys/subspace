use crate::domain_block_processor::{DomainBlockProcessor, PendingPrimaryBlocks, ReceiptsChecker};
use crate::{DomainParentChain, TransactionFor};
use domain_block_preprocessor::runtime_api_full::RuntimeApiFull;
use domain_block_preprocessor::DomainBlockPreprocessor;
use domain_runtime_primitives::{DomainCoreApi, InherentExtrinsicApi};
use sc_client_api::{AuxStore, BlockBackend, Finalizer, StateBackendFor};
use sc_consensus::BlockImport;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_core::traits::CodeExecutor;
use sp_domains::{DomainId, ExecutorApi};
use sp_keystore::KeystorePtr;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, HashFor};
use sp_runtime::Digest;
use std::sync::Arc;

type DomainReceiptsChecker<Block, PBlock, Client, PClient, Backend, E> = ReceiptsChecker<
    Block,
    Client,
    PBlock,
    PClient,
    Backend,
    E,
    DomainParentChain<Block, PBlock, PClient>,
    PBlock,
>;

pub(crate) struct BundleProcessor<Block, PBlock, Client, PClient, Backend, E, BI>
where
    Block: BlockT,
    PBlock: BlockT,
{
    domain_id: DomainId,
    primary_chain_client: Arc<PClient>,
    client: Arc<Client>,
    backend: Arc<Backend>,
    keystore: KeystorePtr,
    domain_receipts_checker: DomainReceiptsChecker<Block, PBlock, Client, PClient, Backend, E>,
    domain_block_preprocessor:
        DomainBlockPreprocessor<Block, PBlock, PClient, RuntimeApiFull<Client>>,
    domain_block_processor: DomainBlockProcessor<Block, PBlock, Client, PClient, Backend, BI>,
}

impl<Block, PBlock, Client, PClient, Backend, E, BI> Clone
    for BundleProcessor<Block, PBlock, Client, PClient, Backend, E, BI>
where
    Block: BlockT,
    PBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            primary_chain_client: self.primary_chain_client.clone(),
            client: self.client.clone(),
            backend: self.backend.clone(),
            keystore: self.keystore.clone(),
            domain_receipts_checker: self.domain_receipts_checker.clone(),
            domain_block_preprocessor: self.domain_block_preprocessor.clone(),
            domain_block_processor: self.domain_block_processor.clone(),
        }
    }
}

impl<Block, PBlock, Client, PClient, Backend, E, BI>
    BundleProcessor<Block, PBlock, Client, PClient, Backend, E, BI>
where
    Block: BlockT,
    PBlock: BlockT,
    NumberFor<PBlock>: From<NumberFor<Block>> + Into<NumberFor<Block>>,
    PBlock::Hash: From<Block::Hash>,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + Finalizer<Block, Backend>
        + 'static,
    Client::Api: DomainCoreApi<Block>
        + MessengerApi<Block, NumberFor<Block>>
        + InherentExtrinsicApi<Block>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    for<'b> &'b BI: BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    PClient: HeaderBackend<PBlock>
        + HeaderMetadata<PBlock, Error = sp_blockchain::Error>
        + BlockBackend<PBlock>
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
        client: Arc<Client>,
        backend: Arc<Backend>,
        keystore: KeystorePtr,
        domain_receipts_checker: DomainReceiptsChecker<Block, PBlock, Client, PClient, Backend, E>,
        domain_block_processor: DomainBlockProcessor<Block, PBlock, Client, PClient, Backend, BI>,
    ) -> Self {
        let domain_block_preprocessor = DomainBlockPreprocessor::new(
            domain_id,
            primary_chain_client.clone(),
            RuntimeApiFull::new(client.clone()),
        );
        Self {
            domain_id,
            primary_chain_client,
            client,
            backend,
            keystore,
            domain_receipts_checker,
            domain_block_preprocessor,
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
                if let Some(next_domain_parent) = self
                    .process_bundles_at((primary_info.hash, primary_info.number), domain_parent)
                    .await?
                {
                    domain_parent = next_domain_parent;
                }
            }
        }

        Ok(())
    }

    async fn process_bundles_at(
        &self,
        primary_info: (PBlock::Hash, NumberFor<PBlock>),
        parent_info: (Block::Hash, NumberFor<Block>),
    ) -> sp_blockchain::Result<Option<(Block::Hash, NumberFor<Block>)>> {
        let (primary_hash, primary_number) = primary_info;
        let (parent_hash, parent_number) = parent_info;

        tracing::debug!(
            "Building a new domain block from primary block #{primary_number},{primary_hash} \
            on top of parent block #{parent_number},{parent_hash}"
        );

        // TODO: Retrieve using consensus chain runtime API
        let head_receipt_number = parent_number;
        // let head_receipt_number = self
        // .primary_chain_client
        // .runtime_api()
        // .head_receipt_number(primary_hash, self.domain_id)?
        // .into();

        let extrinsics = match self
            .domain_block_preprocessor
            .preprocess_primary_block(primary_hash, parent_hash)?
        {
            Some(exts) => exts,
            None => {
                tracing::debug!(
                    "No domain bundle contains in primary block {primary_info:?}, skip building domain block"
                );
                self.domain_block_processor.on_domain_block_processed(
                    primary_hash,
                    None,
                    head_receipt_number,
                )?;
                return Ok(None);
            }
        };

        let domain_block_result = self
            .domain_block_processor
            .process_domain_block(
                (primary_hash, primary_number),
                (parent_hash, parent_number),
                extrinsics,
                Digest::default(),
            )
            .await?;

        assert!(
            domain_block_result.header_number > head_receipt_number,
            "Consensus chain number must larger than execution chain number by at least 1"
        );

        let built_block_info = (
            domain_block_result.header_hash,
            domain_block_result.header_number,
        );

        self.domain_block_processor.on_domain_block_processed(
            primary_hash,
            Some(domain_block_result),
            head_receipt_number,
        )?;

        self.domain_receipts_checker
            .check_state_transition(primary_hash)?;

        Ok(Some(built_block_info))
    }
}
