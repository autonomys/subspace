use crate::domain_block_processor::{DomainBlockProcessor, DomainBlockResult};
use crate::fraud_proof::FraudProofGenerator;
use crate::TransactionFor;
use codec::Decode;
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
use sp_domains::{DomainId, ExecutorApi, OpaqueBundle, SignedOpaqueBundle};
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

pub(crate) struct SystemBundleProcessor<Block, PBlock, Client, PClient, Backend, E>
where
    Block: BlockT,
    PBlock: BlockT,
{
    primary_chain_client: Arc<PClient>,
    primary_network: Arc<NetworkService<PBlock, PBlock::Hash>>,
    client: Arc<Client>,
    backend: Arc<Backend>,
    is_authority: bool,
    keystore: SyncCryptoStorePtr,
    spawner: Box<dyn SpawnNamed + Send + Sync>,
    fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, Backend, E>,
    domain_block_processor: DomainBlockProcessor<Block, PBlock, Client, PClient, Backend>,
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
            primary_network: self.primary_network.clone(),
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
        primary_network: Arc<NetworkService<PBlock, PBlock::Hash>>,
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
            primary_chain_client,
            primary_network,
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

        let best_execution_chain_number = self
            .primary_chain_client
            .runtime_api()
            .best_execution_chain_number(&BlockId::Hash(primary_hash))?;

        let best_execution_chain_number: BlockNumber = best_execution_chain_number
            .try_into()
            .unwrap_or_else(|_| panic!("Primary number must fit into u32; qed"));

        let best_execution_chain_number = best_execution_chain_number.into();

        assert!(
            header_number > best_execution_chain_number,
            "Consensus chain number must larger than execution chain number by at least 1"
        );

        let oldest_receipt_number = self
            .primary_chain_client
            .runtime_api()
            .oldest_receipt_number(&BlockId::Hash(primary_hash))?;

        crate::aux_schema::write_execution_receipt::<_, Block, PBlock>(
            &*self.client,
            (header_hash, header_number),
            best_execution_chain_number,
            &execution_receipt,
        )?;

        // TODO: The applied txs can be fully removed from the transaction pool

        self.domain_block_processor
            .check_receipts_in_primary_block(primary_hash, DomainId::SYSTEM)?;

        if self.primary_network.is_major_syncing() {
            tracing::debug!(
                target: LOG_TARGET,
                "Skip checking the receipts as the primary node is still major syncing..."
            );
            return Ok(());
        }

        // Submit fraud proof for the first unconfirmed incorrent ER.
        crate::aux_schema::prune_expired_bad_receipts(&*self.client, oldest_receipt_number)?;

        self.try_submit_fraud_proof_for_first_unconfirmed_bad_receipt()?;

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
