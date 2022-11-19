use crate::domain_block_processor::DomainBlockProcessor;
use crate::utils::translate_number_type;
use crate::TransactionFor;
use codec::Decode;
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use sc_client_api::{AuxStore, BlockBackend};
use sc_consensus::{BlockImport, ForkChoiceStrategy};
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::traits::{CodeExecutor, SpawnNamed};
use sp_domain_digests::AsPredigest;
use sp_domain_tracker::StateRootUpdate;
use sp_domains::{ExecutorApi, OpaqueBundle, SignedOpaqueBundle};
use sp_keystore::SyncCryptoStorePtr;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, HashFor, Header as HeaderT};
use sp_runtime::Digest;
use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::Randomness;
use system_runtime_primitives::SystemDomainApi;

const LOG_TARGET: &str = "bundle-processor";

pub(crate) struct SystemBundleProcessor<Block, PBlock, Client, PClient, Backend, E>
where
    Block: BlockT,
    PBlock: BlockT,
{
    primary_chain_client: Arc<PClient>,
    client: Arc<Client>,
    backend: Arc<Backend>,
    is_authority: bool,
    keystore: SyncCryptoStorePtr,
    spawner: Box<dyn SpawnNamed + Send + Sync>,
    domain_block_processor: DomainBlockProcessor<Block, PBlock, Client, PClient, Backend, E>,
    _phantom_data: PhantomData<PBlock>,
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
            is_authority: self.is_authority,
            keystore: self.keystore.clone(),
            spawner: self.spawner.clone(),
            domain_block_processor: self.domain_block_processor.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

type SystemAndCoreBundles<Block, PBlock> = (
    Vec<OpaqueBundle<NumberFor<PBlock>, <PBlock as BlockT>::Hash, <Block as BlockT>::Hash>>,
    Vec<SignedOpaqueBundle<NumberFor<PBlock>, <PBlock as BlockT>::Hash, <Block as BlockT>::Hash>>,
);

impl<Block, PBlock, Client, PClient, Backend, E>
    SystemBundleProcessor<Block, PBlock, Client, PClient, Backend, E>
where
    Block: BlockT,
    PBlock: BlockT,
    Client:
        HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block> + 'static,
    Client::Api: DomainCoreApi<Block, AccountId>
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<
            Block,
            StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
        >,
    for<'b> &'b Client: BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    E: CodeExecutor,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        primary_chain_client: Arc<PClient>,
        client: Arc<Client>,
        backend: Arc<Backend>,
        is_authority: bool,
        keystore: SyncCryptoStorePtr,
        spawner: Box<dyn SpawnNamed + Send + Sync>,
        domain_block_processor: DomainBlockProcessor<Block, PBlock, Client, PClient, Backend, E>,
    ) -> Self {
        Self {
            primary_chain_client,
            client,
            backend,
            is_authority,
            keystore,
            spawner,
            domain_block_processor,
            _phantom_data: PhantomData::default(),
        }
    }

    // TODO: Handle the returned error properly, ref to https://github.com/subspace/subspace/pull/695#discussion_r926721185
    pub(crate) async fn process_bundles(
        self,
        (primary_hash, primary_number, fork_choice): (
            PBlock::Hash,
            NumberFor<PBlock>,
            ForkChoiceStrategy,
        ),
        bundles: SystemAndCoreBundles<Block, PBlock>,
        shuffling_seed: Randomness,
        maybe_new_runtime: Option<Cow<'static, [u8]>>,
    ) -> Result<(), sp_blockchain::Error> {
        let parent_hash = self.client.info().best_hash;
        let parent_number = self.client.info().best_number;

        let extrinsics = self.bundles_to_extrinsics(parent_hash, bundles, shuffling_seed)?;

        let digests = self
            .client
            .header(BlockId::Hash(parent_hash))?
            .map(|header| {
                let item = AsPredigest::system_domain_state_root_update(StateRootUpdate {
                    number: parent_number,
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

        let best_execution_chain_number = self
            .primary_chain_client
            .runtime_api()
            .best_execution_chain_number(&BlockId::Hash(primary_hash))?;
        let best_execution_chain_number = translate_number_type::<
            NumberFor<PBlock>,
            NumberFor<Block>,
        >(best_execution_chain_number);

        assert!(
            domain_block_result.header_number > best_execution_chain_number,
            "Consensus chain number must larger than execution chain number by at least 1"
        );

        let oldest_receipt_number = self
            .primary_chain_client
            .runtime_api()
            .oldest_receipt_number(&BlockId::Hash(primary_hash))?;
        let oldest_receipt_number =
            translate_number_type::<NumberFor<PBlock>, NumberFor<Block>>(oldest_receipt_number);

        if let Some(fraud_proof) = self.domain_block_processor.on_domain_block_processed(
            primary_hash,
            domain_block_result,
            best_execution_chain_number,
            oldest_receipt_number,
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

    fn bundles_to_extrinsics(
        &self,
        parent_hash: Block::Hash,
        (system_bundles, core_bundles): SystemAndCoreBundles<Block, PBlock>,
        shuffling_seed: Randomness,
    ) -> Result<Vec<Block::Extrinsic>, sp_blockchain::Error> {
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
                            target: LOG_TARGET,
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
