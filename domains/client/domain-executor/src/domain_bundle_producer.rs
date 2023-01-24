use crate::bundle_election_solver::BundleElectionSolver;
use crate::domain_bundle_proposer::DomainBundleProposer;
use crate::parent_chain::ParentChainInterface;
use crate::utils::{to_number_primitive, ExecutorSlotInfo};
use crate::BundleSender;
use codec::Decode;
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use sc_client_api::{AuxStore, BlockBackend, ProofProvider};
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderBackend;
use sp_domains::{
    Bundle, BundleSolution, DomainId, ExecutorPublicKey, ExecutorSignature, ProofOfElection,
    SignedBundle,
};
use sp_keystore::{SyncCryptoStore, SyncCryptoStorePtr};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
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
    keystore: SyncCryptoStorePtr,
    bundle_election_solver: BundleElectionSolver<SBlock, PBlock, SClient>,
    domain_bundle_proposer: DomainBundleProposer<Block, Client, TransactionPool>,
    _phantom_data: PhantomData<(SBlock, PBlock, ParentChainBlock)>,
}

impl<Block, SBlock, PBlock, ParentChainBlock, Client, SClient, ParentChain, TransactionPool> Clone
    for DomainBundleProducer<
        Block,
        SBlock,
        PBlock,
        ParentChainBlock,
        Client,
        SClient,
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

impl<Block, SBlock, PBlock, ParentChainBlock, Client, SClient, ParentChain, TransactionPool>
    DomainBundleProducer<
        Block,
        SBlock,
        PBlock,
        ParentChainBlock,
        Client,
        SClient,
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
    SClient::Api:
        DomainCoreApi<SBlock, AccountId> + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    ParentChain: ParentChainInterface<ParentChainBlock> + Clone,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        domain_id: DomainId,
        system_domain_client: Arc<SClient>,
        client: Arc<Client>,
        parent_chain: ParentChain,
        transaction_pool: Arc<TransactionPool>,
        bundle_sender: Arc<BundleSender<Block, PBlock>>,
        keystore: SyncCryptoStorePtr,
    ) -> Self {
        let bundle_election_solver = BundleElectionSolver::<SBlock, PBlock, SClient>::new(
            system_domain_client.clone(),
            keystore.clone(),
        );
        let domain_bundle_proposer = DomainBundleProposer::new(client.clone(), transaction_pool);
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
    ) -> Result<Option<SignedOpaqueBundle<Block, PBlock>>, sp_blockchain::Error> {
        let ExecutorSlotInfo {
            slot,
            global_challenge,
        } = slot_info;

        let best_hash = self.system_domain_client.info().best_hash;
        let best_number = self.system_domain_client.info().best_number;

        if let Some(proof_of_election) = self
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
                .propose_bundle_at::<PBlock, _, _>(slot, primary_info, self.parent_chain.clone())
                .await?;

            let bundle_solution = self.construct_bundle_solution(proof_of_election)?;

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
        proof_of_election: ProofOfElection<Block::Hash>,
    ) -> Result<BundleSolution<Block::Hash>, sp_blockchain::Error> {
        if self.domain_id.is_system() {
            Ok(BundleSolution::System(proof_of_election))
        } else if self.domain_id.is_core() {
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
        } else {
            unreachable!("Open domains are unsupported")
        }
    }
}

pub(crate) fn sign_new_bundle<Block: BlockT, PBlock: BlockT>(
    bundle: Bundle<Block::Extrinsic, NumberFor<PBlock>, PBlock::Hash, Block::Hash>,
    keystore: SyncCryptoStorePtr,
    bundle_solution: BundleSolution<Block::Hash>,
) -> Result<SignedOpaqueBundle<Block, PBlock>, sp_blockchain::Error> {
    let to_sign = bundle.hash();
    let bundle_author = bundle_solution
        .proof_of_election()
        .executor_public_key
        .clone();
    match SyncCryptoStore::sign_with(
        &*keystore,
        ExecutorPublicKey::ID,
        &bundle_author.into(),
        to_sign.as_ref(),
    ) {
        Ok(Some(signature)) => {
            let signed_bundle = SignedBundle {
                bundle,
                bundle_solution,
                signature: ExecutorSignature::decode(&mut signature.as_slice()).map_err(|err| {
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
