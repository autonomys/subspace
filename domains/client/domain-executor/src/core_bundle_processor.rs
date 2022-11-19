use crate::domain_block_processor::{DomainBlockProcessor, DomainBlockResult};
use crate::fraud_proof::FraudProofGenerator;
use crate::TransactionFor;
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use sc_client_api::{AuxStore, BlockBackend};
use sc_consensus::{BlockImport, ForkChoiceStrategy};
use sc_network::NetworkService;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus::SyncOracle;
use sp_core::traits::{CodeExecutor, SpawnNamed};
use sp_domain_digests::AsPredigest;
use sp_domain_tracker::StateRootUpdate;
use sp_domains::{DomainId, ExecutorApi, OpaqueBundle};
use sp_keystore::SyncCryptoStorePtr;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, HashFor, Header as HeaderT};
use sp_runtime::Digest;
use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::{BlockNumber, Randomness};
use system_runtime_primitives::SystemDomainApi;

const LOG_TARGET: &str = "bundle-processor";

pub(crate) struct CoreBundleProcessor<Block, SBlock, PBlock, Client, SClient, PClient, Backend, E>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
{
    domain_id: DomainId,
    primary_chain_client: Arc<PClient>,
    primary_network: Arc<NetworkService<PBlock, PBlock::Hash>>,
    system_domain_client: Arc<SClient>,
    client: Arc<Client>,
    backend: Arc<Backend>,
    is_authority: bool,
    keystore: SyncCryptoStorePtr,
    spawner: Box<dyn SpawnNamed + Send + Sync>,
    fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, Backend, E>,
    domain_block_processor: DomainBlockProcessor<Block, PBlock, Client, PClient, Backend>,
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
            primary_network: self.primary_network.clone(),
            system_domain_client: self.system_domain_client.clone(),
            client: self.client.clone(),
            backend: self.backend.clone(),
            is_authority: self.is_authority,
            keystore: self.keystore.clone(),
            spawner: self.spawner.clone(),
            fraud_proof_generator: self.fraud_proof_generator.clone(),
            domain_block_processor: self.domain_block_processor.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

type CoreBundles<Block, PBlock> =
    Vec<OpaqueBundle<NumberFor<PBlock>, <PBlock as BlockT>::Hash, <Block as BlockT>::Hash>>;

impl<Block, SBlock, PBlock, Client, SClient, PClient, Backend, E>
    CoreBundleProcessor<Block, SBlock, PBlock, Client, SClient, PClient, Backend, E>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
    Client:
        HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block> + 'static,
    Client::Api: DomainCoreApi<Block, AccountId>
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
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api:
        DomainCoreApi<SBlock, AccountId> + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    E: CodeExecutor,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        domain_id: DomainId,
        primary_chain_client: Arc<PClient>,
        primary_network: Arc<NetworkService<PBlock, PBlock::Hash>>,
        system_domain_client: Arc<SClient>,
        client: Arc<Client>,
        backend: Arc<Backend>,
        is_authority: bool,
        keystore: SyncCryptoStorePtr,
        spawner: Box<dyn SpawnNamed + Send + Sync>,
        fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, Backend, E>,
    ) -> Self {
        let domain_block_processor = DomainBlockProcessor::new(
            client.clone(),
            primary_chain_client.clone(),
            backend.clone(),
        );
        Self {
            domain_id,
            primary_chain_client,
            primary_network,
            system_domain_client,
            client,
            backend,
            is_authority,
            keystore,
            spawner,
            fraud_proof_generator,
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
        bundles: CoreBundles<Block, PBlock>,
        shuffling_seed: Randomness,
        maybe_new_runtime: Option<Cow<'static, [u8]>>,
    ) -> Result<(), sp_blockchain::Error> {
        let parent_hash = self.client.info().best_hash;
        let parent_number = self.client.info().best_number;

        let extrinsics = self.bundles_to_extrinsics(parent_hash, bundles, shuffling_seed)?;

        // include the latest state root of the system domain
        let system_domain_hash = self.system_domain_client.info().best_hash;
        let digests = self
            .system_domain_client
            .header(BlockId::Hash(system_domain_hash))?
            .map(|header| {
                let item = AsPredigest::system_domain_state_root_update(StateRootUpdate {
                    number: *header.number(),
                    state_root: *header.state_root(),
                });

                Digest { logs: vec![item] }
            })
            .unwrap_or_default();

        let DomainBlockResult {
            header_hash,
            header_number,
            execution_receipt,
        } = self
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

        let best_execution_chain_number = self
            .system_domain_client
            .runtime_api()
            .best_execution_chain_number(&BlockId::Hash(system_domain_hash), self.domain_id)?;

        let best_execution_chain_number: BlockNumber = best_execution_chain_number
            .try_into()
            .unwrap_or_else(|_| panic!("Primary number must fit into u32; qed"));

        let best_execution_chain_number = best_execution_chain_number.into();

        assert!(
            header_number > best_execution_chain_number,
            "Consensus chain number must larger than execution chain number by at least 1"
        );

        crate::aux_schema::write_execution_receipt::<_, Block, PBlock>(
            &*self.client,
            (header_hash, header_number),
            best_execution_chain_number,
            &execution_receipt,
        )?;

        // TODO: The applied txs can be fully removed from the transaction pool

        self.domain_block_processor
            .check_receipts_in_primary_block(primary_hash, self.domain_id)?;

        if self.primary_network.is_major_syncing() {
            tracing::debug!(
                target: LOG_TARGET,
                "Skip checking the receipts as the primary node is still major syncing..."
            );
            return Ok(());
        }

        // Submit fraud proof for the first unconfirmed incorrent ER.
        let oldest_receipt_number = self
            .system_domain_client
            .runtime_api()
            .oldest_receipt_number(&BlockId::Hash(system_domain_hash), self.domain_id)?;
        crate::aux_schema::prune_expired_bad_receipts(&*self.client, oldest_receipt_number)?;

        self.try_submit_fraud_proof_for_first_unconfirmed_bad_receipt()?;

        Ok(())
    }

    fn bundles_to_extrinsics(
        &self,
        parent_hash: Block::Hash,
        bundles: CoreBundles<Block, PBlock>,
        shuffling_seed: Randomness,
    ) -> Result<Vec<Block::Extrinsic>, sp_blockchain::Error> {
        let extrinsics = self
            .domain_block_processor
            .compile_own_domain_bundles(bundles);
        self.domain_block_processor
            .deduplicate_and_shuffle_extrinsics(parent_hash, extrinsics, shuffling_seed)
    }

    fn try_submit_fraud_proof_for_first_unconfirmed_bad_receipt(
        &self,
    ) -> Result<(), sp_blockchain::Error> {
        if let Some((bad_signed_bundle_hash, trace_mismatch_index, block_hash)) =
            crate::aux_schema::find_first_unconfirmed_bad_receipt_info::<_, Block, NumberFor<PBlock>>(
                &*self.client,
            )?
        {
            let local_receipt =
                crate::aux_schema::load_execution_receipt(&*self.client, block_hash)?.ok_or_else(
                    || {
                        sp_blockchain::Error::Backend(format!(
                            "Execution receipt not found for {block_hash:?}"
                        ))
                    },
                )?;

            let fraud_proof = self
                .fraud_proof_generator
                .generate_proof(trace_mismatch_index, &local_receipt, bad_signed_bundle_hash)
                .map_err(|err| {
                    sp_blockchain::Error::Application(Box::from(format!(
                        "Failed to generate fraud proof: {err}"
                    )))
                })?;

            // TODO: self.system_domain_client.runtime_api().submit_fraud_proof_unsigned()
            self.primary_chain_client
                .runtime_api()
                .submit_fraud_proof_unsigned(
                    &BlockId::Hash(self.primary_chain_client.info().best_hash),
                    fraud_proof,
                )?;
        }

        Ok(())
    }
}
