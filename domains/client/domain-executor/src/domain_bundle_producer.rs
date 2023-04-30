use crate::bundle_election_solver::{BundleElectionSolver, PreliminaryBundleSolution};
use crate::domain_bundle_proposer::DomainBundleProposer;
use crate::parent_chain::ParentChainInterface;
use crate::utils::{to_number_primitive, ExecutorSlotInfo};
use crate::BundleSender;
use codec::Decode;
use domain_runtime_primitives::DomainCoreApi;
use sc_client_api::{AuxStore, BlockBackend, ProofProvider};
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderBackend;
use sp_domains::{
    Bundle, BundleSolution, DomainId, ExecutorPublicKey, ExecutorSignature, SignedBundle,
};
use sp_keystore::KeystorePtr;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, One, Saturating, Zero};
use sp_runtime::RuntimeAppPublic;
use std::marker::PhantomData;
use std::sync::Arc;
use system_runtime_primitives::SystemDomainApi;

type SignedOpaqueBundle<Block, PBlock> = sp_domains::SignedOpaqueBundle<
    NumberFor<PBlock>,
    <PBlock as BlockT>::Hash,
    <Block as BlockT>::Hash,
>;

pub(super) struct DomainBundleProducer<
    Block,
    SBlock,
    PBlock,
    ParentChainBlock,
    Client,
    SClient,
    PClient,
    ParentChain,
    TransactionPool,
> where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
{
    domain_id: DomainId,
    system_domain_client: Arc<SClient>,
    client: Arc<Client>,
    parent_chain: ParentChain,
    bundle_sender: Arc<BundleSender<Block, PBlock>>,
    keystore: KeystorePtr,
    bundle_election_solver: BundleElectionSolver<SBlock, PBlock, SClient>,
    domain_bundle_proposer: DomainBundleProposer<Block, Client, PBlock, PClient, TransactionPool>,
    _phantom_data: PhantomData<ParentChainBlock>,
}

impl<
        Block,
        SBlock,
        PBlock,
        ParentChainBlock,
        Client,
        SClient,
        PClient,
        ParentChain,
        TransactionPool,
    > Clone
    for DomainBundleProducer<
        Block,
        SBlock,
        PBlock,
        ParentChainBlock,
        Client,
        SClient,
        PClient,
        ParentChain,
        TransactionPool,
    >
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
    ParentChain: Clone,
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            system_domain_client: self.system_domain_client.clone(),
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

impl<
        Block,
        SBlock,
        PBlock,
        ParentChainBlock,
        Client,
        SClient,
        PClient,
        ParentChain,
        TransactionPool,
    >
    DomainBundleProducer<
        Block,
        SBlock,
        PBlock,
        ParentChainBlock,
        Client,
        SClient,
        PClient,
        ParentChain,
        TransactionPool,
    >
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
    ParentChainBlock: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block>,
    Client::Api: BlockBuilder<Block>,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + ProofProvider<SBlock>,
    SClient::Api: DomainCoreApi<SBlock> + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    PClient: HeaderBackend<PBlock>,
    ParentChain: ParentChainInterface<ParentChainBlock> + Clone,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
    pub(super) fn new(
        domain_id: DomainId,
        system_domain_client: Arc<SClient>,
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
        let bundle_election_solver = BundleElectionSolver::<SBlock, PBlock, SClient>::new(
            system_domain_client.clone(),
            keystore.clone(),
        );
        Self {
            domain_id,
            system_domain_client,
            client,
            parent_chain,
            bundle_sender,
            keystore,
            bundle_election_solver,
            domain_bundle_proposer,
            _phantom_data: PhantomData::default(),
        }
    }

    pub(super) async fn produce_bundle(
        self,
        primary_info: (PBlock::Hash, NumberFor<PBlock>),
        slot_info: ExecutorSlotInfo,
    ) -> sp_blockchain::Result<Option<SignedOpaqueBundle<Block, PBlock>>> {
        let ExecutorSlotInfo {
            slot,
            global_challenge,
        } = slot_info;

        let best_hash = self.system_domain_client.info().best_hash;
        let best_number = self.system_domain_client.info().best_number;

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

        let should_skip_slot = if domain_best_number.is_zero() {
            let primary_block_number = primary_info.1;

            // Executor hasn't able to finish the processing of domain block #1.
            !primary_block_number.is_zero()
        } else {
            let head_receipt_number = self
                .parent_chain
                .head_receipt_number(self.parent_chain.best_hash())?
                .into();

            // Executor is lagging behind the receipt chain on its parent chain as another executor
            // already processed a block higher than the local best and submitted the receipt to
            // the parent chain, we ought to catch up with the primary block processing before
            // producing new bundle.
            domain_best_number <= head_receipt_number
        };

        if should_skip_slot {
            tracing::warn!(
                ?domain_best_number,
                "Skipping bundle production on slot {slot}"
            );
            return Ok(None);
        }

        if let Some(preliminary_bundle_solution) = self
            .bundle_election_solver
            .solve_bundle_election_challenge::<Block>(
                best_hash,
                best_number,
                self.domain_id,
                global_challenge,
            )?
        {
            tracing::info!("📦 Claimed bundle at slot {slot}");

            let bundle = self
                .domain_bundle_proposer
                .propose_bundle_at(slot, primary_info, self.parent_chain.clone())
                .await?;

            let bundle_solution = self.construct_bundle_solution(preliminary_bundle_solution)?;

            Ok(Some(sign_new_bundle::<Block, PBlock>(
                bundle,
                self.keystore,
                bundle_solution,
            )?))
        } else {
            Ok(None)
        }
    }

    fn construct_bundle_solution(
        &self,
        preliminary_bundle_solution: PreliminaryBundleSolution<Block::Hash>,
    ) -> sp_blockchain::Result<BundleSolution<Block::Hash>> {
        match preliminary_bundle_solution {
            PreliminaryBundleSolution::System {
                authority_stake_weight,
                authority_witness,
                proof_of_election,
            } => Ok(BundleSolution::System {
                authority_stake_weight,
                authority_witness,
                proof_of_election,
            }),
            PreliminaryBundleSolution::Core(proof_of_election) => {
                let core_block_number = to_number_primitive(self.client.info().best_number);
                let core_block_hash = self.client.info().best_hash;
                let core_state_root = *self
                    .client
                    .header(core_block_hash)?
                    .expect("Best block header must exist; qed")
                    .state_root();
                Ok(BundleSolution::Core {
                    proof_of_election,
                    core_block_number,
                    core_block_hash,
                    core_state_root,
                })
            }
        }
    }
}

pub(crate) fn sign_new_bundle<Block: BlockT, PBlock: BlockT>(
    bundle: Bundle<Block::Extrinsic, NumberFor<PBlock>, PBlock::Hash, Block::Hash>,
    keystore: KeystorePtr,
    bundle_solution: BundleSolution<Block::Hash>,
) -> sp_blockchain::Result<SignedOpaqueBundle<Block, PBlock>> {
    let to_sign = bundle.hash();
    let bundle_author = bundle_solution
        .proof_of_election()
        .executor_public_key
        .clone();
    match keystore.sr25519_sign(
        ExecutorPublicKey::ID,
        bundle_author.as_ref(),
        to_sign.as_ref(),
    ) {
        Ok(Some(signature)) => {
            let signed_bundle = SignedBundle {
                bundle,
                bundle_solution,
                signature: ExecutorSignature::decode(&mut signature.as_ref()).map_err(|err| {
                    sp_blockchain::Error::Application(Box::from(format!(
                        "Failed to decode the signature of bundle: {err}"
                    )))
                })?,
            };

            // TODO: Re-enable the bundle gossip over X-Net when the compact bundle is supported.
            // if let Err(e) = self.bundle_sender.unbounded_send(signed_bundle.clone()) {
            // tracing::error!(error = ?e, "Failed to send transaction bundle");
            // }

            Ok(signed_bundle.into_signed_opaque_bundle())
        }
        Ok(None) => Err(sp_blockchain::Error::Application(Box::from(
            "This should not happen as the existence of key was just checked",
        ))),
        Err(error) => Err(sp_blockchain::Error::Application(Box::from(format!(
            "Error occurred when signing the bundle: {error}"
        )))),
    }
}
