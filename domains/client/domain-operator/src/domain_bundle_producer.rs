use crate::bundle_producer_election_solver::BundleProducerElectionSolver;
use crate::domain_bundle_proposer::DomainBundleProposer;
use crate::utils::OperatorSlotInfo;
use crate::BundleSender;
use codec::Decode;
use domain_runtime_primitives::DomainCoreApi;
use sc_client_api::{AuxStore, BlockBackend};
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderBackend;
use sp_domains::{
    Bundle, BundleProducerElectionApi, DomainId, DomainsApi, OperatorId, OperatorPublicKey,
    OperatorSignature, SealedBundleHeader,
};
use sp_keystore::KeystorePtr;
use sp_runtime::traits::{Block as BlockT, NumberFor, Zero};
use sp_runtime::RuntimeAppPublic;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::convert::{AsRef, Into};
use std::sync::Arc;
use subspace_runtime_primitives::Balance;
use tracing::info;

type OpaqueBundle<Block, CBlock> = sp_domains::OpaqueBundle<
    NumberFor<CBlock>,
    <CBlock as BlockT>::Hash,
    <Block as BlockT>::Header,
    Balance,
>;

pub struct DomainBundleProducer<Block, CBlock, Client, CClient, TransactionPool>
where
    Block: BlockT,
    CBlock: BlockT,
{
    domain_id: DomainId,
    consensus_client: Arc<CClient>,
    client: Arc<Client>,
    bundle_sender: Arc<BundleSender<Block, CBlock>>,
    keystore: KeystorePtr,
    bundle_producer_election_solver: BundleProducerElectionSolver<Block, CBlock, CClient>,
    domain_bundle_proposer: DomainBundleProposer<Block, Client, CBlock, CClient, TransactionPool>,
    skip_empty_bundle_production: bool,
}

impl<Block, CBlock, Client, CClient, TransactionPool> Clone
    for DomainBundleProducer<Block, CBlock, Client, CClient, TransactionPool>
where
    Block: BlockT,
    CBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            consensus_client: self.consensus_client.clone(),
            client: self.client.clone(),
            bundle_sender: self.bundle_sender.clone(),
            keystore: self.keystore.clone(),
            bundle_producer_election_solver: self.bundle_producer_election_solver.clone(),
            domain_bundle_proposer: self.domain_bundle_proposer.clone(),
            skip_empty_bundle_production: self.skip_empty_bundle_production,
        }
    }
}

impl<Block, CBlock, Client, CClient, TransactionPool>
    DomainBundleProducer<Block, CBlock, Client, CClient, TransactionPool>
where
    Block: BlockT,
    CBlock: BlockT,
    NumberFor<Block>: Into<NumberFor<CBlock>>,
    NumberFor<CBlock>: Into<NumberFor<Block>>,
    Client: HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block>,
    Client::Api: BlockBuilder<Block> + DomainCoreApi<Block> + TaggedTransactionQueue<Block>,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock>,
    CClient::Api: DomainsApi<CBlock, Block::Header> + BundleProducerElectionApi<CBlock, Balance>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain_id: DomainId,
        consensus_client: Arc<CClient>,
        client: Arc<Client>,
        domain_bundle_proposer: DomainBundleProposer<
            Block,
            Client,
            CBlock,
            CClient,
            TransactionPool,
        >,
        bundle_sender: Arc<BundleSender<Block, CBlock>>,
        keystore: KeystorePtr,
        skip_empty_bundle_production: bool,
    ) -> Self {
        let bundle_producer_election_solver = BundleProducerElectionSolver::<Block, CBlock, _>::new(
            keystore.clone(),
            consensus_client.clone(),
        );
        Self {
            domain_id,
            consensus_client,
            client,
            bundle_sender,
            keystore,
            bundle_producer_election_solver,
            domain_bundle_proposer,
            skip_empty_bundle_production,
        }
    }

    pub async fn produce_bundle(
        &mut self,
        operator_id: OperatorId,
        slot_info: OperatorSlotInfo,
    ) -> sp_blockchain::Result<Option<OpaqueBundle<Block, CBlock>>> {
        let OperatorSlotInfo {
            slot,
            global_randomness,
        } = slot_info;

        let domain_best_number = self.client.info().best_number;
        let consensus_chain_best_hash = self.consensus_client.info().best_hash;
        let should_skip_slot = {
            let head_receipt_number = self
                .consensus_client
                .runtime_api()
                .head_receipt_number(consensus_chain_best_hash, self.domain_id)?;

            // Operator is lagging behind the receipt chain on its parent chain as another operator
            // already processed a block higher than the local best and submitted the receipt to
            // the parent chain, we ought to catch up with the consensus block processing before
            // producing new bundle.
            !domain_best_number.is_zero() && domain_best_number <= head_receipt_number
        };

        if should_skip_slot {
            tracing::warn!(
                ?domain_best_number,
                "Skipping bundle production on slot {slot}"
            );
            return Ok(None);
        }

        if let Some((proof_of_election, operator_signing_key)) =
            self.bundle_producer_election_solver.solve_challenge(
                slot,
                consensus_chain_best_hash,
                self.domain_id,
                operator_id,
                global_randomness,
            )?
        {
            tracing::info!("📦 Claimed bundle at slot {slot}");

            let tx_range = self
                .consensus_client
                .runtime_api()
                .domain_tx_range(consensus_chain_best_hash, self.domain_id)
                .map_err(|error| {
                    sp_blockchain::Error::Application(Box::from(format!(
                        "Error getting tx range: {error}"
                    )))
                })?;
            let (bundle_header, extrinsics) = self
                .domain_bundle_proposer
                .propose_bundle_at(proof_of_election, tx_range)
                .await?;

            // if there are no extrinsics and no receipts to confirm, skip the bundle
            if self.skip_empty_bundle_production
                && extrinsics.is_empty()
                && !self
                    .consensus_client
                    .runtime_api()
                    .non_empty_er_exists(consensus_chain_best_hash, self.domain_id)?
            {
                tracing::warn!(
                    ?domain_best_number,
                    "Skipping empty bundle production on slot {slot}"
                );
                return Ok(None);
            }

            info!("🔖 Producing bundle at slot {:?}", slot_info.slot);

            let to_sign = bundle_header.hash();

            let signature = self
                .keystore
                .sr25519_sign(
                    OperatorPublicKey::ID,
                    operator_signing_key.as_ref(),
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

            let signature = OperatorSignature::decode(&mut signature.as_ref()).map_err(|err| {
                sp_blockchain::Error::Application(Box::from(format!(
                    "Failed to decode the signature of bundle: {err}"
                )))
            })?;

            let bundle = Bundle {
                sealed_header: SealedBundleHeader::new(bundle_header, signature),
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
