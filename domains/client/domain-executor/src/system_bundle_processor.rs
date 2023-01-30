use crate::domain_block_processor::{
    preprocess_primary_block, DomainBlockProcessor, PendingPrimaryBlocks,
};
use crate::utils::{translate_number_type, DomainBundles};
use crate::TransactionFor;
use codec::Decode;
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use sc_client_api::{AuxStore, BlockBackend, StateBackendFor};
use sc_consensus::{BlockImport, ForkChoiceStrategy};
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_core::traits::CodeExecutor;
use sp_domain_digests::AsPredigest;
use sp_domains::{DomainId, ExecutorApi};
use sp_keystore::SyncCryptoStorePtr;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, HashFor};
use sp_runtime::{Digest, DigestItem};
use std::sync::Arc;
use subspace_core_primitives::Randomness;
use system_runtime_primitives::SystemDomainApi;

pub(crate) struct SystemBundleProcessor<Block, PBlock, Client, PClient, Backend, E>
where
    PBlock: BlockT,
{
    primary_chain_client: Arc<PClient>,
    client: Arc<Client>,
    backend: Arc<Backend>,
    keystore: SyncCryptoStorePtr,
    domain_block_processor: DomainBlockProcessor<Block, PBlock, Client, PClient, Backend, E>,
}

impl<Block, PBlock, Client, PClient, Backend, E> Clone
    for SystemBundleProcessor<Block, PBlock, Client, PClient, Backend, E>
where
    PBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            primary_chain_client: self.primary_chain_client.clone(),
            client: self.client.clone(),
            backend: self.backend.clone(),
            keystore: self.keystore.clone(),
            domain_block_processor: self.domain_block_processor.clone(),
        }
    }
}

impl<Block, PBlock, Client, PClient, Backend, E>
    SystemBundleProcessor<Block, PBlock, Client, PClient, Backend, E>
where
    Block: BlockT,
    PBlock: BlockT,
    Client:
        HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block> + 'static,
    Client::Api: DomainCoreApi<Block, AccountId>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>,
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
        keystore: SyncCryptoStorePtr,
        domain_block_processor: DomainBlockProcessor<Block, PBlock, Client, PClient, Backend, E>,
    ) -> Self {
        Self {
            primary_chain_client,
            client,
            backend,
            keystore,
            domain_block_processor,
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
        tracing::debug!(?primary_info, ?parent_info, "Building a new domain block");

        let (primary_hash, primary_number, fork_choice) = primary_info;
        let (parent_hash, parent_number) = parent_info;

        let (bundles, shuffling_seed, maybe_new_runtime) =
            preprocess_primary_block(DomainId::SYSTEM, &*self.primary_chain_client, primary_hash)?;

        let extrinsics = self.bundles_to_extrinsics(parent_hash, bundles, shuffling_seed)?;

        let primary_block_info = DigestItem::primary_block_info((primary_number, primary_hash));
        let digests = Digest {
            logs: vec![primary_block_info],
        };

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

        let head_receipt_number = self
            .primary_chain_client
            .runtime_api()
            .head_receipt_number(&BlockId::Hash(primary_hash))?;
        let head_receipt_number =
            translate_number_type::<NumberFor<PBlock>, NumberFor<Block>>(head_receipt_number);

        assert!(
            domain_block_result.header_number > head_receipt_number,
            "Consensus chain number must larger than execution chain number by at least 1"
        );

        let oldest_receipt_number = self
            .primary_chain_client
            .runtime_api()
            .oldest_receipt_number(&BlockId::Hash(primary_hash))?;
        let oldest_receipt_number =
            translate_number_type::<NumberFor<PBlock>, NumberFor<Block>>(oldest_receipt_number);

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
            self.primary_chain_client
                .runtime_api()
                .submit_fraud_proof_unsigned(
                    &BlockId::Hash(self.primary_chain_client.info().best_hash),
                    fraud_proof,
                )?;
        }

        Ok(built_block_info)
    }

    fn bundles_to_extrinsics(
        &self,
        parent_hash: Block::Hash,
        bundles: DomainBundles<Block, PBlock>,
        shuffling_seed: Randomness,
    ) -> Result<Vec<Block::Extrinsic>, sp_blockchain::Error> {
        let (system_bundles, core_bundles) = match bundles {
            DomainBundles::System(system_bundles, core_bundles) => (system_bundles, core_bundles),
            DomainBundles::Core(_) => {
                return Err(sp_blockchain::Error::Application(Box::from(
                    "System bundle processor can not process core bundles.",
                )));
            }
        };

        let origin_system_extrinsics = self
            .domain_block_processor
            .compile_own_domain_bundles(system_bundles);
        let extrinsics = self
            .client
            .runtime_api()
            .construct_submit_core_bundle_extrinsics(&BlockId::Hash(parent_hash), core_bundles)?
            .into_iter()
            .filter_map(
                |uxt| match <<Block as BlockT>::Extrinsic>::decode(&mut uxt.as_slice()) {
                    Ok(uxt) => Some(uxt),
                    Err(e) => {
                        tracing::error!(
                            error = ?e,
                            "Failed to decode the opaque extrisic in bundle, this should not happen"
                        );
                        None
                    }
                },
            )
            .chain(origin_system_extrinsics)
            .collect::<Vec<_>>();

        self.domain_block_processor
            .deduplicate_and_shuffle_extrinsics(parent_hash, extrinsics, shuffling_seed)
    }
}
