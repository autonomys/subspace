use crate::domain_block_processor::{DomainBlockProcessor, PendingPrimaryBlocks, ReceiptsChecker};
use crate::utils::translate_number_type;
use crate::TransactionFor;
use domain_block_preprocessor::runtime_api_full::RuntimeApiFull;
use domain_block_preprocessor::SystemDomainBlockPreprocessor;
use domain_runtime_primitives::DomainCoreApi;
use sc_client_api::{AuxStore, BlockBackend, Finalizer, StateBackendFor};
use sc_consensus::BlockImport;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_core::traits::CodeExecutor;
use sp_domain_digests::AsPredigest;
use sp_domains::ExecutorApi;
use sp_keystore::KeystorePtr;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, HashFor, One, Zero};
use sp_runtime::{Digest, DigestItem};
use std::sync::Arc;
use system_runtime_primitives::SystemDomainApi;

pub(crate) struct SystemBundleProcessor<Block, PBlock, Client, PClient, Backend, E>
where
    Block: BlockT,
    PBlock: BlockT,
{
    primary_chain_client: Arc<PClient>,
    client: Arc<Client>,
    backend: Arc<Backend>,
    keystore: KeystorePtr,
    receipts_checker: ReceiptsChecker<Block, Client, PBlock, PClient, Backend, E>,
    system_domain_block_preprocessor:
        SystemDomainBlockPreprocessor<Block, PBlock, PClient, RuntimeApiFull<Client>>,
    domain_block_processor: DomainBlockProcessor<Block, PBlock, Client, PClient, Backend, Client>,
}

impl<Block, PBlock, Client, PClient, Backend, E> Clone
    for SystemBundleProcessor<Block, PBlock, Client, PClient, Backend, E>
where
    Block: BlockT,
    PBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            primary_chain_client: self.primary_chain_client.clone(),
            client: self.client.clone(),
            backend: self.backend.clone(),
            keystore: self.keystore.clone(),
            receipts_checker: self.receipts_checker.clone(),
            system_domain_block_preprocessor: self.system_domain_block_preprocessor.clone(),
            domain_block_processor: self.domain_block_processor.clone(),
        }
    }
}

impl<Block, PBlock, Client, PClient, Backend, E>
    SystemBundleProcessor<Block, PBlock, Client, PClient, Backend, E>
where
    Block: BlockT,
    PBlock: BlockT,
    NumberFor<PBlock>: From<NumberFor<Block>>,
    PBlock::Hash: From<Block::Hash>,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + Finalizer<Block, Backend>
        + 'static,
    Client::Api: DomainCoreApi<Block>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>
        + MessengerApi<Block, NumberFor<Block>>,
    for<'b> &'b Client: BlockImport<
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
        primary_chain_client: Arc<PClient>,
        client: Arc<Client>,
        backend: Arc<Backend>,
        keystore: KeystorePtr,
        receipts_checker: ReceiptsChecker<Block, Client, PBlock, PClient, Backend, E>,
        domain_block_processor: DomainBlockProcessor<
            Block,
            PBlock,
            Client,
            PClient,
            Backend,
            Client,
        >,
    ) -> Self {
        let system_domain_block_preprocessor = SystemDomainBlockPreprocessor::new(
            primary_chain_client.clone(),
            RuntimeApiFull::new(client.clone()),
        );
        Self {
            primary_chain_client,
            client,
            backend,
            keystore,
            receipts_checker,
            system_domain_block_preprocessor,
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
            .system_domain_block_preprocessor
            .preprocess_primary_block(primary_hash, parent_hash)?;

        let logs = if primary_number == One::one() {
            // Manually inject the genesis block info.
            vec![
                DigestItem::primary_block_info::<NumberFor<PBlock>, _>((
                    Zero::zero(),
                    self.primary_chain_client.info().genesis_hash,
                )),
                DigestItem::primary_block_info((primary_number, primary_hash)),
            ]
        } else {
            vec![DigestItem::primary_block_info((
                primary_number,
                primary_hash,
            ))]
        };

        let digests = Digest { logs };

        let domain_block_result = self
            .domain_block_processor
            .process_domain_block(
                (primary_hash, primary_number),
                (parent_hash, parent_number),
                extrinsics,
                digests,
            )
            .await?;

        let head_receipt_number = self
            .primary_chain_client
            .runtime_api()
            .head_receipt_number(primary_hash)?;
        let head_receipt_number =
            translate_number_type::<NumberFor<PBlock>, NumberFor<Block>>(head_receipt_number);

        assert!(
            domain_block_result.header_number > head_receipt_number,
            "Consensus chain number must larger than execution chain number by at least 1"
        );

        let oldest_receipt_number = self
            .primary_chain_client
            .runtime_api()
            .oldest_receipt_number(primary_hash)?;
        let oldest_receipt_number =
            translate_number_type::<NumberFor<PBlock>, NumberFor<Block>>(oldest_receipt_number);

        let built_block_info = (
            domain_block_result.header_hash,
            domain_block_result.header_number,
        );

        self.domain_block_processor.on_domain_block_processed(
            primary_hash,
            domain_block_result,
            head_receipt_number,
        )?;

        // TODO: The applied txs can be fully removed from the transaction pool

        if let Some(fraud_proof) = self
            .receipts_checker
            .check_invalid_state_transition::<PBlock>(primary_hash, oldest_receipt_number)?
        {
            self.primary_chain_client
                .runtime_api()
                .submit_fraud_proof_unsigned(
                    self.primary_chain_client.info().best_hash,
                    fraud_proof,
                )?;
        }

        Ok(built_block_info)
    }
}
