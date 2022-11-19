use crate::bundle_election_solver::BundleElectionSolver;
use crate::domain_bundle_producer::ReceiptInterface;
use crate::domain_bundle_proposer::DomainBundleProposer;
use crate::utils::ExecutorSlotInfo;
use crate::BundleSender;
use codec::Decode;
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use sc_client_api::{AuxStore, BlockBackend, ProofProvider};
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderBackend;
use sp_domains::{
    DomainId, ExecutorApi, ExecutorPublicKey, ExecutorSignature, SignedBundle, SignedOpaqueBundle,
};
use sp_keystore::{SyncCryptoStore, SyncCryptoStorePtr};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::Block as BlockT;
use sp_runtime::RuntimeAppPublic;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::BlockNumber;
use system_runtime_primitives::SystemDomainApi;

const LOG_TARGET: &str = "bundle-producer";

pub(super) struct SystemBundleProducer<Block, PBlock, Client, PClient, TransactionPool>
where
    Block: BlockT,
    PBlock: BlockT,
{
    domain_id: DomainId,
    primary_chain_client: Arc<PClient>,
    client: Arc<Client>,
    bundle_sender: Arc<BundleSender<Block, PBlock>>,
    is_authority: bool,
    keystore: SyncCryptoStorePtr,
    bundle_election_solver: BundleElectionSolver<Block, PBlock, Client>,
    domain_bundle_proposer: DomainBundleProposer<Block, Client, TransactionPool>,
    _phantom_data: PhantomData<PBlock>,
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
            bundle_sender: self.bundle_sender.clone(),
            is_authority: self.is_authority,
            keystore: self.keystore.clone(),
            bundle_election_solver: self.bundle_election_solver.clone(),
            domain_bundle_proposer: self.domain_bundle_proposer.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, PBlock, Client, PClient, TransactionPool> ReceiptInterface<PBlock::Hash>
    for SystemBundleProducer<Block, PBlock, Client, PClient, TransactionPool>
where
    Block: BlockT,
    PBlock: BlockT,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>,
    Client::Api: DomainCoreApi<Block, AccountId>
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>
        + BlockBuilder<Block>,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock>,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
    fn best_execution_chain_number(
        &self,
        at: PBlock::Hash,
    ) -> Result<BlockNumber, sp_api::ApiError> {
        let best_execution_chain_number = self
            .primary_chain_client
            .runtime_api()
            .best_execution_chain_number(&BlockId::Hash(at))?;

        let best_execution_chain_number: BlockNumber = best_execution_chain_number
            .try_into()
            .unwrap_or_else(|_| panic!("Primary number must fit into u32; qed"));

        Ok(best_execution_chain_number)
    }

    fn maximum_receipt_drift(&self, at: PBlock::Hash) -> Result<BlockNumber, sp_api::ApiError> {
        let max_drift = self
            .primary_chain_client
            .runtime_api()
            .maximum_receipt_drift(&BlockId::Hash(at))?;

        let max_drift: BlockNumber = max_drift
            .try_into()
            .unwrap_or_else(|_| panic!("Primary number must fit into u32; qed"));

        Ok(max_drift)
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
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>
        + BlockBuilder<Block>,
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
        Self {
            domain_id,
            primary_chain_client,
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
        receipt_interface: R,
    ) -> Result<
        Option<SignedOpaqueBundle<NumberFor<PBlock>, PBlock::Hash, Block::Hash>>,
        sp_blockchain::Error,
    >
    where
        R: ReceiptInterface<PBlock::Hash>,
    {
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
            tracing::info!(target: LOG_TARGET, "📦 Claimed bundle at slot {slot}");

            let bundle = self
                .domain_bundle_proposer
                .propose_bundle_at::<PBlock, _, _>(
                    slot,
                    primary_info,
                    receipt_interface,
                    primary_info.0,
                )
                .await?;

            let to_sign = bundle.hash();

            match SyncCryptoStore::sign_with(
                &*self.keystore,
                ExecutorPublicKey::ID,
                &proof_of_election.executor_public_key.clone().into(),
                to_sign.as_ref(),
            ) {
                Ok(Some(signature)) => {
                    let signed_bundle = SignedBundle {
                        bundle,
                        proof_of_election,
                        signature: ExecutorSignature::decode(&mut signature.as_slice()).map_err(
                            |err| {
                                sp_blockchain::Error::Application(Box::from(format!(
                                    "Failed to decode the signature of bundle: {err}"
                                )))
                            },
                        )?,
                    };

                    // TODO: Re-enable the bundle gossip over X-Net when the compact bundle is supported.
                    // if let Err(e) = self.bundle_sender.unbounded_send(signed_bundle.clone()) {
                    // tracing::error!(target: LOG_TARGET, error = ?e, "Failed to send transaction bundle");
                    // }

                    Ok(Some(signed_bundle.into_signed_opaque_bundle()))
                }
                Ok(None) => Err(sp_blockchain::Error::Application(Box::from(
                    "This should not happen as the existence of key was just checked",
                ))),
                Err(error) => Err(sp_blockchain::Error::Application(Box::from(format!(
                    "Error occurred when signing the bundle: {error}"
                )))),
            }
        } else {
            Ok(None)
        }
    }
}
