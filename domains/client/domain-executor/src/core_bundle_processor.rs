use crate::domain_block_processor::{
    preprocess_primary_block, DomainBlockProcessor, PendingPrimaryBlocks,
};
use crate::parent_chain::{CoreDomainParentChain, ParentChainInterface};
use crate::utils::translate_number_type;
use crate::TransactionFor;
use domain_runtime_primitives::{AccountId, DomainCoreApi, DomainExtrinsicApi};
use sc_client_api::{AuxStore, BlockBackend, StateBackendFor};
use sc_consensus::{BlockImport, ForkChoiceStrategy};
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_core::traits::CodeExecutor;
use sp_domain_digests::AsPredigest;
use sp_domains::state_root_tracker::StateRootUpdate;
use sp_domains::{DomainId, ExecutorApi};
use sp_keystore::SyncCryptoStorePtr;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, HashFor, Header as HeaderT};
use sp_runtime::Digest;
use std::marker::PhantomData;
use std::sync::Arc;
use system_runtime_primitives::SystemDomainApi;

pub(crate) struct CoreBundleProcessor<Block, SBlock, PBlock, Client, SClient, PClient, Backend, E>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
{
    domain_id: DomainId,
    primary_chain_client: Arc<PClient>,
    system_domain_client: Arc<SClient>,
    parent_chain: CoreDomainParentChain<SClient, SBlock, PBlock>,
    client: Arc<Client>,
    backend: Arc<Backend>,
    keystore: SyncCryptoStorePtr,
    domain_block_processor: DomainBlockProcessor<Block, PBlock, Client, PClient, Backend, E>,
    _phantom_data: PhantomData<(SBlock, PBlock)>,
}

impl<Block, SBlock, PBlock, Client, SClient, PClient, Backend, E> Clone
    for CoreBundleProcessor<Block, SBlock, PBlock, SClient, Client, PClient, Backend, E>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
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
            domain_block_processor: self.domain_block_processor.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, SBlock, PBlock, Client, SClient, PClient, Backend, E>
    CoreBundleProcessor<Block, SBlock, PBlock, Client, SClient, PClient, Backend, E>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
    Client:
        HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block> + 'static,
    Client::Api: DomainCoreApi<Block, AccountId>
        + DomainExtrinsicApi<Block, NumberFor<PBlock>, PBlock::Hash>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    for<'b> &'b Client: BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api:
        DomainCoreApi<SBlock, AccountId> + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
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
        system_domain_client: Arc<SClient>,
        client: Arc<Client>,
        backend: Arc<Backend>,
        keystore: SyncCryptoStorePtr,
        domain_block_processor: DomainBlockProcessor<Block, PBlock, Client, PClient, Backend, E>,
    ) -> Self {
        let parent_chain = CoreDomainParentChain::<SClient, SBlock, PBlock>::new(
            system_domain_client.clone(),
            domain_id,
        );
        Self {
            domain_id,
            primary_chain_client,
            system_domain_client,
            parent_chain,
            client,
            backend,
            keystore,
            domain_block_processor,
            _phantom_data: PhantomData::default(),
        }
    }

    // TODO: Handle the returned error properly, ref to https://github.com/subspace/subspace/pull/695#discussion_r926721185
    pub(crate) async fn process_bundles(
        self,
        primary_info: (PBlock::Hash, NumberFor<PBlock>, ForkChoiceStrategy),
    ) -> Result<(), sp_blockchain::Error> {
        tracing::debug!(?primary_info, "Processing imported primary block");

        let (primary_hash, primary_number, fork_choice) = primary_info;

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

            for (i, primary_info) in primary_imports.iter().enumerate() {
                // Use the origin fork_choice for the target primary block,
                // the intermediate ones use `Custom(false)`.
                let fork_choice = if i == primary_imports.len() - 1 {
                    fork_choice
                } else {
                    ForkChoiceStrategy::Custom(false)
                };

                domain_parent = self
                    .process_bundles_at(
                        (primary_info.hash, primary_info.number, fork_choice),
                        domain_parent,
                    )
                    .await?;
            }
        }

        Ok(())
    }

    async fn process_bundles_at(
        &self,
        primary_info: (PBlock::Hash, NumberFor<PBlock>, ForkChoiceStrategy),
        parent_info: (Block::Hash, NumberFor<Block>),
    ) -> Result<(Block::Hash, NumberFor<Block>), sp_blockchain::Error> {
        let (primary_hash, primary_number, fork_choice) = primary_info;
        let (parent_hash, parent_number) = parent_info;

        tracing::debug!(
            "Building a new domain block derived from primary block #{primary_number},{primary_hash} \
            on top of #{parent_number},{parent_hash}"
        );

        let (bundles, shuffling_seed, maybe_new_runtime) =
            preprocess_primary_block(self.domain_id, &*self.primary_chain_client, primary_hash)?;

        let extrinsics = self.domain_block_processor.bundles_to_extrinsics(
            parent_hash,
            bundles,
            shuffling_seed,
        )?;

        // include the latest state root of the system domain
        let system_domain_hash = self.system_domain_client.info().best_hash;
        let digests = self
            .system_domain_client
            .header(system_domain_hash)?
            .map(|header| {
                let item = AsPredigest::system_domain_state_root_update(StateRootUpdate {
                    number: *header.number(),
                    state_root: *header.state_root(),
                });

                Digest { logs: vec![item] }
            })
            .unwrap_or_default();

        let domain_block_result = self
            .domain_block_processor
            .process_domain_block(
                (primary_hash, primary_number),
                (parent_hash, parent_number),
                extrinsics,
                maybe_new_runtime,
                fork_choice,
                digests,
            )
            .await?;

        // TODO: just make it compile for now, likely wrong, rethink about it.
        let system_domain_hash = self.system_domain_client.info().best_hash;

        let head_receipt_number = self
            .system_domain_client
            .runtime_api()
            .head_receipt_number(&BlockId::Hash(system_domain_hash), self.domain_id)?;
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
            .oldest_receipt_number(&BlockId::Hash(system_domain_hash), self.domain_id)?;
        let oldest_receipt_number =
            translate_number_type::<NumberFor<SBlock>, NumberFor<Block>>(oldest_receipt_number);

        let built_block_info = (
            domain_block_result.header_hash,
            domain_block_result.header_number,
        );

        if let Some(fraud_proof) = self.domain_block_processor.on_domain_block_processed(
            primary_hash,
            domain_block_result,
            head_receipt_number,
            oldest_receipt_number,
        )? {
            self.parent_chain.submit_fraud_proof_unsigned(fraud_proof)?;
        }

        Ok(built_block_info)
    }
}
