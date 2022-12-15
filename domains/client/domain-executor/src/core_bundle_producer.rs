use crate::bundle_election_solver::BundleElectionSolver;
use crate::domain_bundle_producer::{sign_new_bundle, ParentChainInterface};
use crate::domain_bundle_proposer::DomainBundleProposer;
use crate::utils::{to_number_primitive, ExecutorSlotInfo};
use crate::BundleSender;
use codec::{Decode, Encode};
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use sc_client_api::{AuxStore, BlockBackend, ProofProvider};
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderBackend;
use sp_domains::{BundleSolution, DomainId, ProofOfElection, SignedOpaqueBundle};
use sp_keystore::SyncCryptoStorePtr;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::BlockNumber;
use system_runtime_primitives::SystemDomainApi;

pub(super) struct CoreBundleProducer<Block, SBlock, PBlock, Client, SClient, TransactionPool>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
{
    domain_id: DomainId,
    system_domain_client: Arc<SClient>,
    client: Arc<Client>,
    bundle_sender: Arc<BundleSender<Block, PBlock>>,
    is_authority: bool,
    keystore: SyncCryptoStorePtr,
    bundle_election_solver: BundleElectionSolver<SBlock, PBlock, SClient>,
    domain_bundle_proposer: DomainBundleProposer<Block, Client, TransactionPool>,
    _phantom_data: PhantomData<(SBlock, PBlock)>,
}

impl<Block, SBlock, PBlock, Client, SClient, TransactionPool> Clone
    for CoreBundleProducer<Block, SBlock, PBlock, Client, SClient, TransactionPool>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            system_domain_client: self.system_domain_client.clone(),
            client: self.client.clone(),
            bundle_sender: self.bundle_sender.clone(),
            is_authority: self.is_authority,
            keystore: self.keystore.clone(),
            bundle_election_solver: self.bundle_election_solver.clone(),
            domain_bundle_proposer: self.domain_bundle_proposer.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, SBlock, PBlock, Client, SClient, TransactionPool> ParentChainInterface<SBlock::Hash>
    for CoreBundleProducer<Block, SBlock, PBlock, Client, SClient, TransactionPool>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
    SClient: ProvideRuntimeApi<SBlock>,
    SClient::Api: SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
{
    fn head_receipt_number(&self, at: SBlock::Hash) -> Result<BlockNumber, sp_api::ApiError> {
        let head_receipt_number = self
            .system_domain_client
            .runtime_api()
            .head_receipt_number(&BlockId::Hash(at), self.domain_id)?;
        Ok(to_number_primitive(head_receipt_number))
    }

    fn maximum_receipt_drift(&self, at: SBlock::Hash) -> Result<BlockNumber, sp_api::ApiError> {
        let max_drift = self
            .system_domain_client
            .runtime_api()
            .maximum_receipt_drift(&BlockId::Hash(at))?;
        Ok(to_number_primitive(max_drift))
    }
}

impl<Block, SBlock, PBlock, Client, SClient, TransactionPool>
    CoreBundleProducer<Block, SBlock, PBlock, Client, SClient, TransactionPool>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block>,
    Client::Api: BlockBuilder<Block>,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + ProofProvider<SBlock>,
    SClient::Api:
        DomainCoreApi<SBlock, AccountId> + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
    pub(super) fn new(
        domain_id: DomainId,
        system_domain_client: Arc<SClient>,
        client: Arc<Client>,
        transaction_pool: Arc<TransactionPool>,
        bundle_sender: Arc<BundleSender<Block, PBlock>>,
        is_authority: bool,
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
            bundle_sender,
            is_authority,
            keystore,
            bundle_election_solver,
            domain_bundle_proposer,
            _phantom_data: PhantomData::default(),
        }
    }

    pub(super) async fn produce_bundle<R>(
        self,
        primary_info: (PBlock::Hash, NumberFor<PBlock>),
        slot_info: ExecutorSlotInfo,
        parent_chain: R,
    ) -> Result<
        Option<SignedOpaqueBundle<NumberFor<PBlock>, PBlock::Hash, Block::Hash>>,
        sp_blockchain::Error,
    >
    where
        R: ParentChainInterface<SBlock::Hash>,
    {
        if !self.is_authority {
            return Ok(None);
        }

        let ExecutorSlotInfo {
            slot,
            global_challenge,
        } = slot_info;

        let best_hash = self.system_domain_client.info().best_hash;
        let best_number = self.system_domain_client.info().best_number;

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
                .propose_bundle_at::<PBlock, _, _>(slot, primary_info, parent_chain, best_hash)
                .await?;

            let core_block_number = to_number_primitive(self.client.info().best_number);
            let core_block_hash = self.client.info().best_hash;
            let core_state_root = *self
                .client
                .header(BlockId::Hash(core_block_hash))?
                .expect("Best block header must exist; qed")
                .state_root();

            let as_core_block_hash = |system_block_hash: SBlock::Hash| {
                Block::Hash::decode(&mut system_block_hash.encode().as_slice()).unwrap()
            };

            let proof_of_election = ProofOfElection {
                domain_id: proof_of_election.domain_id,
                vrf_output: proof_of_election.vrf_output,
                vrf_proof: proof_of_election.vrf_proof,
                executor_public_key: proof_of_election.executor_public_key,
                global_challenge: proof_of_election.global_challenge,
                state_root: as_core_block_hash(proof_of_election.state_root),
                storage_proof: proof_of_election.storage_proof,
                block_number: proof_of_election.block_number,
                block_hash: as_core_block_hash(proof_of_election.block_hash),
            };

            Ok(Some(sign_new_bundle::<Block, PBlock>(
                bundle,
                self.keystore,
                BundleSolution::Core {
                    proof_of_election,
                    core_block_number,
                    core_block_hash,
                    core_state_root,
                },
            )?))
        } else {
            Ok(None)
        }
    }
}
