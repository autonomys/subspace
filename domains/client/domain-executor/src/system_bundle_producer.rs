use crate::bundle_election_solver::BundleElectionSolver;
use crate::domain_bundle_producer::sign_new_bundle;
use crate::domain_bundle_proposer::DomainBundleProposer;
use crate::parent_chain::SystemDomainParentChain;
use crate::utils::ExecutorSlotInfo;
use crate::BundleSender;
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use sc_client_api::{AuxStore, BlockBackend, ProofProvider};
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderBackend;
use sp_domains::{BundleSolution, DomainId, ExecutorApi, SignedOpaqueBundle};
use sp_keystore::SyncCryptoStorePtr;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use system_runtime_primitives::SystemDomainApi;

pub(super) struct SystemBundleProducer<Block, PBlock, Client, PClient, TransactionPool>
where
    Block: BlockT,
    PBlock: BlockT,
{
    domain_id: DomainId,
    primary_chain_client: Arc<PClient>,
    client: Arc<Client>,
    parent_chain: SystemDomainParentChain<PClient, Block, PBlock>,
    bundle_sender: Arc<BundleSender<Block, PBlock>>,
    is_authority: bool,
    keystore: SyncCryptoStorePtr,
    bundle_election_solver: BundleElectionSolver<Block, PBlock, Client>,
    domain_bundle_proposer: DomainBundleProposer<Block, Client, TransactionPool>,
}

impl<Block, PBlock, Client, PClient, TransactionPool> Clone
    for SystemBundleProducer<Block, PBlock, Client, PClient, TransactionPool>
where
    Block: BlockT,
    PBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            primary_chain_client: self.primary_chain_client.clone(),
            client: self.client.clone(),
            parent_chain: self.parent_chain.clone(),
            bundle_sender: self.bundle_sender.clone(),
            is_authority: self.is_authority,
            keystore: self.keystore.clone(),
            bundle_election_solver: self.bundle_election_solver.clone(),
            domain_bundle_proposer: self.domain_bundle_proposer.clone(),
        }
    }
}

impl<Block, PBlock, Client, PClient, TransactionPool>
    SystemBundleProducer<Block, PBlock, Client, PClient, TransactionPool>
where
    Block: BlockT,
    PBlock: BlockT,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>,
    Client::Api: DomainCoreApi<Block, AccountId>
        + BlockBuilder<Block>
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock>,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
    pub(super) fn new(
        domain_id: DomainId,
        primary_chain_client: Arc<PClient>,
        client: Arc<Client>,
        transaction_pool: Arc<TransactionPool>,
        bundle_sender: Arc<BundleSender<Block, PBlock>>,
        is_authority: bool,
        keystore: SyncCryptoStorePtr,
    ) -> Self {
        let bundle_election_solver = BundleElectionSolver::new(client.clone(), keystore.clone());
        let domain_bundle_proposer = DomainBundleProposer::new(client.clone(), transaction_pool);
        let parent_chain =
            SystemDomainParentChain::<PClient, Block, PBlock>::new(primary_chain_client.clone());
        Self {
            domain_id,
            primary_chain_client,
            client,
            parent_chain,
            bundle_sender,
            is_authority,
            keystore,
            bundle_election_solver,
            domain_bundle_proposer,
        }
    }

    pub(super) async fn produce_bundle(
        self,
        primary_info: (PBlock::Hash, NumberFor<PBlock>),
        slot_info: ExecutorSlotInfo,
    ) -> Result<
        Option<SignedOpaqueBundle<NumberFor<PBlock>, PBlock::Hash, Block::Hash>>,
        sp_blockchain::Error,
    > {
        if !self.is_authority {
            return Ok(None);
        }

        let ExecutorSlotInfo {
            slot,
            global_challenge,
        } = slot_info;

        let best_hash = self.client.info().best_hash;
        let best_number = self.client.info().best_number;

        if let Some(proof_of_election) = self
            .bundle_election_solver
            .solve_bundle_election_challenge(
                best_hash,
                best_number,
                self.domain_id,
                global_challenge,
            )?
        {
            tracing::info!("📦 Claimed bundle at slot {slot}");

            let bundle = self
                .domain_bundle_proposer
                .propose_bundle_at::<PBlock, _, _>(
                    slot,
                    primary_info,
                    self.parent_chain,
                    primary_info.0,
                )
                .await?;

            Ok(Some(sign_new_bundle::<Block, PBlock>(
                bundle,
                self.keystore,
                BundleSolution::System(proof_of_election),
            )?))
        } else {
            Ok(None)
        }
    }
}
