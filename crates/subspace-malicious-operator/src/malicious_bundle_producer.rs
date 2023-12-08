use crate::malicious_bundle_tamper::MaliciousBundleTamper;
use domain_client_operator::domain_bundle_producer::DomainBundleProducer;
use domain_client_operator::domain_bundle_proposer::DomainBundleProposer;
use domain_client_operator::{OpaqueBundleFor, OperatorSlotInfo};
use domain_runtime_primitives::opaque::Block as DomainBlock;
use domain_runtime_primitives::DomainCoreApi;
use frame_system_rpc_runtime_api::AccountNonceApi;
use futures::{Stream, StreamExt, TryFutureExt};
use pallet_domains::OperatorConfig;
use parity_scale_codec::Encode;
use sc_client_api::{AuxStore, BlockBackend, HeaderBackend};
use sc_service::config::KeystoreConfig;
use sc_service::KeystoreContainer;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_utils::mpsc::tracing_unbounded;
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::Info;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::FarmerPublicKey;
use sp_core::crypto::UncheckedFrom;
use sp_core::Get;
use sp_domains::{BundleProducerElectionApi, DomainId, DomainsApi, OperatorId, OperatorPublicKey};
use sp_keyring::Sr25519Keyring;
use sp_keystore::KeystorePtr;
use sp_runtime::traits::Block as BlockT;
use sp_runtime::{generic, RuntimeAppPublic};
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::error::Error;
use std::sync::Arc;
use subspace_core_primitives::Randomness;
use subspace_runtime::{
    CheckStorageAccess, DisablePallets, Runtime, RuntimeCall, SignedExtra, UncheckedExtrinsic,
};
use subspace_runtime_primitives::opaque::Block as CBlock;
use subspace_runtime_primitives::{AccountId, Balance, Nonce};

pub struct MaliciousBundleProducer<Client, CClient, TransactionPool> {
    domain_id: DomainId,
    sudo_acccount: AccountId,
    consensus_keystore: KeystorePtr,
    operator_keystore: KeystorePtr,
    consensus_client: Arc<CClient>,
    consensus_offchain_tx_pool_factory: OffchainTransactionPoolFactory<CBlock>,
    bundle_producer: DomainBundleProducer<DomainBlock, CBlock, Client, CClient, TransactionPool>,
    malicious_bundle_makder: MaliciousBundleTamper<DomainBlock, CBlock, Client>,
    malicious_operator_status: MaliciousOperatorStatus,
}

impl<Client, CClient, TransactionPool> MaliciousBundleProducer<Client, CClient, TransactionPool>
where
    Client: HeaderBackend<DomainBlock>
        + BlockBackend<DomainBlock>
        + AuxStore
        + ProvideRuntimeApi<DomainBlock>
        + 'static,
    Client::Api: BlockBuilder<DomainBlock>
        + DomainCoreApi<DomainBlock>
        + TaggedTransactionQueue<DomainBlock>,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + 'static,
    CClient::Api: DomainsApi<CBlock, <DomainBlock as BlockT>::Header>
        + BundleProducerElectionApi<CBlock, Balance>
        + AccountNonceApi<CBlock, AccountId, Nonce>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = DomainBlock> + 'static,
{
    pub fn new(
        domain_id: DomainId,
        domain_client: Arc<Client>,
        consensus_client: Arc<CClient>,
        consensus_keystore: KeystorePtr,
        consensus_offchain_tx_pool_factory: OffchainTransactionPoolFactory<CBlock>,
        domain_transaction_pool: Arc<TransactionPool>,
    ) -> Self {
        let operator_keystore = KeystoreContainer::new(&KeystoreConfig::InMemory)
            .expect("create in-memory keystore container must succeed")
            .keystore();

        let domain_bundle_proposer = DomainBundleProposer::new(
            domain_id,
            domain_client.clone(),
            consensus_client.clone(),
            domain_transaction_pool,
        );

        let (bundle_sender, _bundle_receiver) = tracing_unbounded("domain_bundle_stream", 100);
        let bundle_producer = DomainBundleProducer::new(
            domain_id,
            consensus_client.clone(),
            domain_client.clone(),
            domain_bundle_proposer,
            Arc::new(bundle_sender),
            operator_keystore.clone(),
            // The malicious operator doesn't skip empty bundle
            false,
        );

        let malicious_bundle_makder =
            MaliciousBundleTamper::new(domain_client, operator_keystore.clone());

        let sudo_acccount = consensus_client
            .runtime_api()
            .sudo_account_id(consensus_client.info().best_hash)
            .expect("Failed to get sudo account");

        Self {
            domain_id,
            consensus_client,
            consensus_keystore,
            operator_keystore,
            bundle_producer,
            malicious_bundle_makder,
            malicious_operator_status: MaliciousOperatorStatus::NoStatus,
            sudo_acccount,
            consensus_offchain_tx_pool_factory,
        }
    }

    async fn handle_new_slot(
        &self,
        operator_id: OperatorId,
        new_slot_info: OperatorSlotInfo,
    ) -> Option<OpaqueBundleFor<DomainBlock, CBlock>> {
        let slot = new_slot_info.slot;
        let consensus_block_info = {
            let info = self.consensus_client.info();
            sp_blockchain::HashAndNumber {
                number: info.best_number,
                hash: info.best_hash,
            }
        };
        self.bundle_producer
            .clone()
            .produce_bundle(operator_id, consensus_block_info.clone(), new_slot_info)
            .unwrap_or_else(move |error| {
                tracing::error!(
                    ?consensus_block_info,
                    ?slot,
                    ?operator_id,
                    ?error,
                    "Error at malicious operator producing bundle"
                );
                None
            })
            .await
    }

    pub async fn start<NSNS: Stream<Item = (Slot, Randomness)> + Send + 'static>(
        mut self,
        new_slot_notification_stream: NSNS,
    ) {
        let mut new_slot_notification_stream = Box::pin(new_slot_notification_stream);
        while let Some((slot, global_randomness)) = new_slot_notification_stream.next().await {
            if let Some((operator_id, signing_key)) =
                self.malicious_operator_status.registered_operator()
            {
                let maybe_opaque_bundle = self
                    .handle_new_slot(
                        *operator_id,
                        OperatorSlotInfo {
                            slot,
                            global_randomness,
                        },
                    )
                    .await;

                if let Some(mut opaque_bundle) = maybe_opaque_bundle {
                    if let Err(err) = self
                        .malicious_bundle_makder
                        .maybe_tamper_bundle(&mut opaque_bundle, signing_key)
                    {
                        tracing::error!(?err, "Got error when try to tamper bundle");
                    }
                    if let Err(err) = self.submit_bundle(opaque_bundle) {
                        tracing::info!(?err, "Malicious operator failed to submit bundle");
                    }
                }
            }
        }
    }

    fn submit_bundle(
        &self,
        opaque_bundle: OpaqueBundleFor<DomainBlock, CBlock>,
    ) -> Result<(), Box<dyn Error>> {
        let call = UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
        );
        self.consensus_offchain_tx_pool_factory
            .offchain_transaction_pool(self.consensus_client.info().best_hash)
            .submit_transaction(etx.encode())
            .map_err(|err| {
                sp_blockchain::Error::Application(
                    format!("Failed to submit consensus extrinsic, call {call:?}, err {err:?}")
                        .into(),
                )
            })?;

        Ok(())
    }
}
