use crate::bundle_election_solver::BundleElectionSolver;
use crate::domain_bundle_proposer::DomainBundleProposer;
use crate::parent_chain::ParentChainInterface;
use crate::sortition::TransactionSelector;
use crate::utils::ExecutorSlotInfo;
use crate::BundleSender;
use codec::Decode;
use domain_runtime_primitives::DomainCoreApi;
use sc_client_api::{AuxStore, BlockBackend};
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderBackend;
use sp_domains::{
    Bundle, DomainId, ExecutorApi, ExecutorPublicKey, ExecutorSignature, SealedBundleHeader,
};
use sp_keystore::KeystorePtr;
use sp_runtime::traits::{Block as BlockT, One, Saturating, Zero};
use sp_runtime::RuntimeAppPublic;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::U256;

type OpaqueBundle<Block, PBlock> =
    sp_domains::OpaqueBundle<NumberFor<PBlock>, <PBlock as BlockT>::Hash, <Block as BlockT>::Hash>;

pub(super) struct DomainBundleProducer<
    Block,
    PBlock,
    ParentChainBlock,
    Client,
    PClient,
    ParentChain,
    TransactionPool,
> where
    Block: BlockT,
    PBlock: BlockT,
{
    domain_id: DomainId,
    primary_chain_client: Arc<PClient>,
    client: Arc<Client>,
    parent_chain: ParentChain,
    bundle_sender: Arc<BundleSender<Block, PBlock>>,
    keystore: KeystorePtr,
    bundle_election_solver: BundleElectionSolver<Block, PBlock>,
    domain_bundle_proposer: DomainBundleProposer<Block, Client, PBlock, PClient, TransactionPool>,
    _phantom_data: PhantomData<ParentChainBlock>,
}

impl<Block, PBlock, ParentChainBlock, Client, PClient, ParentChain, TransactionPool> Clone
    for DomainBundleProducer<
        Block,
        PBlock,
        ParentChainBlock,
        Client,
        PClient,
        ParentChain,
        TransactionPool,
    >
where
    Block: BlockT,
    PBlock: BlockT,
    ParentChain: Clone,
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            primary_chain_client: self.primary_chain_client.clone(),
            client: self.client.clone(),
            parent_chain: self.parent_chain.clone(),
            bundle_sender: self.bundle_sender.clone(),
            keystore: self.keystore.clone(),
            bundle_election_solver: self.bundle_election_solver.clone(),
            domain_bundle_proposer: self.domain_bundle_proposer.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, PBlock, ParentChainBlock, Client, PClient, ParentChain, TransactionPool>
    DomainBundleProducer<
        Block,
        PBlock,
        ParentChainBlock,
        Client,
        PClient,
        ParentChain,
        TransactionPool,
    >
where
    Block: BlockT,
    PBlock: BlockT,
    ParentChainBlock: BlockT,
    NumberFor<Block>: Into<NumberFor<PBlock>>,
    NumberFor<ParentChainBlock>: Into<NumberFor<Block>>,
    Client: HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block>,
    Client::Api: BlockBuilder<Block> + DomainCoreApi<Block>,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock>,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    ParentChain: ParentChainInterface<Block, ParentChainBlock> + Clone,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        domain_id: DomainId,
        primary_chain_client: Arc<PClient>,
        client: Arc<Client>,
        parent_chain: ParentChain,
        domain_bundle_proposer: DomainBundleProposer<
            Block,
            Client,
            PBlock,
            PClient,
            TransactionPool,
        >,
        bundle_sender: Arc<BundleSender<Block, PBlock>>,
        keystore: KeystorePtr,
    ) -> Self {
        let bundle_election_solver = BundleElectionSolver::<Block, PBlock>::new(keystore.clone());
        Self {
            domain_id,
            primary_chain_client,
            client,
            parent_chain,
            bundle_sender,
            keystore,
            bundle_election_solver,
            domain_bundle_proposer,
            _phantom_data: PhantomData,
        }
    }

    pub(super) async fn produce_bundle(
        self,
        primary_info: (PBlock::Hash, NumberFor<PBlock>),
        slot_info: ExecutorSlotInfo,
    ) -> sp_blockchain::Result<Option<OpaqueBundle<Block, PBlock>>> {
        let ExecutorSlotInfo {
            slot,
            global_challenge,
        } = slot_info;

        let best_receipt_is_written = crate::aux_schema::primary_hash_for::<_, _, PBlock::Hash>(
            &*self.client,
            self.client.info().best_hash,
        )?
        .is_some();

        // TODO: remove once the receipt generation can be done before the domain block is
        // committed to the database, in other words, only when the receipt of block N+1 has
        // been generated can the `client.info().best_number` be updated from N to N+1.
        //
        // This requires:
        // 1. Reimplement `runtime_api.intermediate_roots()` on the client side.
        // 2. Add a hook before the upstream `client.commit_operation(op)`.
        let domain_best_number = if best_receipt_is_written {
            self.client.info().best_number
        } else {
            self.client.info().best_number.saturating_sub(One::one())
        };

        let should_skip_slot = {
            let primary_block_number = primary_info.1;
            let head_receipt_number = self
                .parent_chain
                .head_receipt_number(self.parent_chain.best_hash())?;

            // Receipt for block #0 does not exist, simply skip slot here to bypasss this case and
            // make the code cleaner
            primary_block_number.is_zero()
                // Executor hasn't able to finish the processing of domain block #1.
                || domain_best_number.is_zero()
                // Executor is lagging behind the receipt chain on its parent chain as another executor
                // already processed a block higher than the local best and submitted the receipt to
                // the parent chain, we ought to catch up with the primary block processing before
                // producing new bundle.
                || domain_best_number <= head_receipt_number
        };

        if should_skip_slot {
            tracing::warn!(
                ?domain_best_number,
                "Skipping bundle production on slot {slot}"
            );
            return Ok(None);
        }

        if let Some(bundle_solution) = self
            .bundle_election_solver
            .solve_bundle_election_challenge(self.domain_id, global_challenge)?
        {
            tracing::info!("📦 Claimed bundle at slot {slot}");

            let proof_of_election = bundle_solution.proof_of_election();
            let bundle_author = proof_of_election.executor_public_key.clone();
            let tx_range = self
                .primary_chain_client
                .runtime_api()
                .domain_tx_range(primary_info.0, self.domain_id)
                .map_err(|error| {
                    sp_blockchain::Error::Application(Box::from(format!(
                        "Error getting tx range: {error}"
                    )))
                })?;
            let tx_selector = TransactionSelector::new(
                U256::from_be_bytes(proof_of_election.vrf_hash()),
                tx_range,
                self.client.clone(),
            );
            let (bundle_header, receipt, extrinsics) = self
                .domain_bundle_proposer
                .propose_bundle_at(
                    bundle_solution,
                    slot,
                    primary_info,
                    self.parent_chain.clone(),
                    tx_selector,
                )
                .await?;

            let to_sign = bundle_header.hash();

            let signature = self
                .keystore
                .sr25519_sign(
                    ExecutorPublicKey::ID,
                    bundle_author.as_ref(),
                    to_sign.as_ref(),
                )
                .map_err(|error| {
                    sp_blockchain::Error::Application(Box::from(format!(
                        "Error occurred when signing the bundle: {error}"
                    )))
                })?
                .ok_or_else(|| {
                    sp_blockchain::Error::Application(Box::from(
                        "This should not happen as the existence of key was just checked",
                    ))
                })?;

            let signature = ExecutorSignature::decode(&mut signature.as_ref()).map_err(|err| {
                sp_blockchain::Error::Application(Box::from(format!(
                    "Failed to decode the signature of bundle: {err}"
                )))
            })?;

            let bundle = Bundle {
                sealed_header: SealedBundleHeader::new(bundle_header, signature),
                receipt,
                extrinsics,
            };

            // TODO: Re-enable the bundle gossip over X-Net when the compact bundle is supported.
            // if let Err(e) = self.bundle_sender.unbounded_send(signed_bundle.clone()) {
            // tracing::error!(error = ?e, "Failed to send transaction bundle");
            // }

            Ok(Some(bundle.into_opaque_bundle()))
        } else {
            Ok(None)
        }
    }
}
