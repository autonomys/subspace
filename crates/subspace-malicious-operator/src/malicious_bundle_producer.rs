use crate::malicious_bundle_tamper::MaliciousBundleTamper;
use domain_client_operator::domain_bundle_producer::{BundleProducer, TestBundleProducer};
use domain_client_operator::domain_bundle_proposer::DomainBundleProposer;
use domain_client_operator::{OpaqueBundleFor, OperatorSlotInfo};
use domain_runtime_primitives::opaque::Block as DomainBlock;
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
use sp_core::crypto::UncheckedFrom;
use sp_domains::core_api::DomainCoreApi;
use sp_domains::{BundleProducerElectionApi, DomainId, DomainsApi, OperatorId, OperatorPublicKey};
use sp_keyring::Sr25519Keyring;
use sp_keystore::{Keystore, KeystorePtr};
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use sp_runtime::{generic, RuntimeAppPublic};
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::error::Error;
use std::sync::Arc;
use subspace_core_primitives::pot::PotOutput;
use subspace_runtime::{DisablePallets, Runtime, RuntimeCall, SignedExtra, UncheckedExtrinsic};
use subspace_runtime_primitives::opaque::Block as CBlock;
use subspace_runtime_primitives::{AccountId, Balance, Nonce};

const MALICIOUS_OPR_STAKE_MULTIPLIER: Balance = 3;

enum MaliciousOperatorStatus {
    Registering(OperatorPublicKey),
    Registered {
        operator_id: OperatorId,
        signing_key: OperatorPublicKey,
    },
    NoStatus,
}

impl MaliciousOperatorStatus {
    fn registering(&mut self, signing_key: OperatorPublicKey) {
        *self = MaliciousOperatorStatus::Registering(signing_key)
    }

    fn registered(&mut self, operator_id: OperatorId, signing_key: OperatorPublicKey) {
        *self = MaliciousOperatorStatus::Registered {
            operator_id,
            signing_key,
        }
    }

    fn no_status(&mut self) {
        *self = MaliciousOperatorStatus::NoStatus
    }

    fn registered_operator(&self) -> Option<(OperatorId, OperatorPublicKey)> {
        match self {
            MaliciousOperatorStatus::Registered {
                operator_id,
                signing_key,
            } => Some((*operator_id, signing_key.clone())),
            _ => None,
        }
    }

    fn registering_signing_key(&self) -> Option<OperatorPublicKey> {
        match self {
            MaliciousOperatorStatus::Registering(key) => Some(key.clone()),
            _ => None,
        }
    }
}

pub struct MaliciousBundleProducer<Client, CClient, TransactionPool> {
    domain_id: DomainId,
    sudo_account: AccountId,
    consensus_keystore: KeystorePtr,
    operator_keystore: KeystorePtr,
    consensus_client: Arc<CClient>,
    consensus_offchain_tx_pool_factory: OffchainTransactionPoolFactory<CBlock>,
    bundle_producer: TestBundleProducer<DomainBlock, CBlock, Client, CClient, TransactionPool>,
    malicious_bundle_tamper: MaliciousBundleTamper<DomainBlock, CBlock, Client>,
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
        + MessengerApi<DomainBlock, NumberFor<CBlock>, <CBlock as BlockT>::Hash>
        + TaggedTransactionQueue<DomainBlock>,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + 'static,
    CClient::Api: DomainsApi<CBlock, <DomainBlock as BlockT>::Header>
        + BundleProducerElectionApi<CBlock, Balance>
        + AccountNonceApi<CBlock, AccountId, Nonce>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<
            Block = DomainBlock,
            Hash = <DomainBlock as BlockT>::Hash,
        > + 'static,
{
    pub fn new(
        domain_id: DomainId,
        domain_client: Arc<Client>,
        consensus_client: Arc<CClient>,
        consensus_keystore: KeystorePtr,
        consensus_offchain_tx_pool_factory: OffchainTransactionPoolFactory<CBlock>,
        domain_transaction_pool: Arc<TransactionPool>,
        sudo_account: AccountId,
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
        let bundle_producer = TestBundleProducer::new(
            domain_id,
            consensus_client.clone(),
            domain_client.clone(),
            domain_bundle_proposer,
            Arc::new(bundle_sender),
            operator_keystore.clone(),
            // The malicious operator doesn't skip empty bundle
            false,
            false,
        );

        let malicious_bundle_tamper =
            MaliciousBundleTamper::new(domain_client, operator_keystore.clone());

        Self {
            domain_id,
            consensus_client,
            consensus_keystore,
            operator_keystore,
            bundle_producer,
            malicious_bundle_tamper,
            malicious_operator_status: MaliciousOperatorStatus::NoStatus,
            sudo_account,
            consensus_offchain_tx_pool_factory,
        }
    }

    async fn handle_new_slot(
        &mut self,
        operator_id: OperatorId,
        new_slot_info: OperatorSlotInfo,
    ) -> Option<OpaqueBundleFor<DomainBlock, CBlock>> {
        let slot = new_slot_info.slot;
        self.bundle_producer
            .produce_bundle(operator_id, new_slot_info)
            .unwrap_or_else(move |error| {
                tracing::error!(
                    ?slot,
                    ?operator_id,
                    ?error,
                    "Error at malicious operator producing bundle"
                );
                None
            })
            .await
            .and_then(|res| res.into_opaque_bundle())
    }

    pub async fn start<NSNS: Stream<Item = (Slot, PotOutput)> + Send + 'static>(
        mut self,
        new_slot_notification_stream: NSNS,
    ) {
        let mut new_slot_notification_stream = Box::pin(new_slot_notification_stream);
        while let Some((slot, proof_of_time)) = new_slot_notification_stream.next().await {
            if let Some((operator_id, signing_key)) =
                self.malicious_operator_status.registered_operator()
            {
                let maybe_opaque_bundle = self
                    .handle_new_slot(
                        operator_id,
                        OperatorSlotInfo {
                            slot,
                            proof_of_time,
                        },
                    )
                    .await;

                if let Some(mut opaque_bundle) = maybe_opaque_bundle {
                    if let Err(err) = self
                        .malicious_bundle_tamper
                        .maybe_tamper_bundle(&mut opaque_bundle, &signing_key)
                    {
                        tracing::error!(?err, "Got error when try to tamper bundle");
                    }
                    if let Err(err) = self.submit_bundle(opaque_bundle) {
                        tracing::info!(?err, "Malicious operator failed to submit bundle");
                    }
                }
            }

            // Periodically check the malicious operator status
            if u64::from(slot) % 10 == 0 {
                if let Err(err) = self.update_malicious_operator_status() {
                    tracing::error!(?err, "Failed to update malicious operator status");
                }
            }
        }
    }

    fn update_malicious_operator_status(&mut self) -> Result<(), Box<dyn Error>> {
        let consensus_best_hash = self.consensus_client.info().best_hash;
        let (mut current_operators, next_operators) = self
            .consensus_client
            .runtime_api()
            .domain_operators(consensus_best_hash, self.domain_id)?
            .ok_or_else(|| {
                sp_blockchain::Error::Application(
                    format!("Operator set for domain {} not found", self.domain_id).into(),
                )
            })?;

        if let Some((malicious_operator_id, _)) =
            self.malicious_operator_status.registered_operator()
        {
            if next_operators.contains(&malicious_operator_id) {
                return Ok(());
            } else {
                tracing::info!(
                    ?malicious_operator_id,
                    "Current malicious operator is missing from next operator set, probably got slashed"
                );
                // Remove the current malicious operator to not account its stake toward
                // `current_total_stake` otherwise the next malicious operator will stake
                // more and more fund
                current_operators.remove(&malicious_operator_id);
                self.malicious_operator_status.no_status();
            }
        }

        let signing_key = match &self.malicious_operator_status.registering_signing_key() {
            Some(k) => k.clone(),
            None => {
                let public_key: OperatorPublicKey = self
                    .operator_keystore
                    .sr25519_generate_new(OperatorPublicKey::ID, None)?
                    .into();

                self.malicious_operator_status
                    .registering(public_key.clone());

                tracing::info!(?public_key, "Start register new malicious operator");

                public_key
            }
        };

        let mut maybe_operator_id = None;
        for operator_id in current_operators.keys().chain(next_operators.iter()) {
            if let Some((operator_signing_key, _)) = self
                .consensus_client
                .runtime_api()
                .operator(consensus_best_hash, *operator_id)?
            {
                if operator_signing_key == signing_key {
                    maybe_operator_id = Some(*operator_id);
                    break;
                }
            }
        }

        // If the `signing_key` is linked to a operator, the previous registration request succeeded,
        // otherwise we need to retry
        match maybe_operator_id {
            None => {
                let nonce = self.sudo_acccount_nonce()?;
                let current_total_stake: Balance = current_operators.into_values().sum();
                self.submit_register_operator(
                    nonce,
                    signing_key,
                    // Ideally we should use the `next_total_stake` but it is tricky to get
                    MALICIOUS_OPR_STAKE_MULTIPLIER * current_total_stake,
                )?;
                self.submit_force_staking_epoch_transition(nonce + 1)?;
            }
            Some(operator_id) => {
                if !next_operators.contains(&operator_id) {
                    // The operator id not present in `next_operators` means the operator is deregistered
                    // or slashed, which should not happen since we haven't use this operator to submit bad
                    // ER yet. But just set `malicious_operator_status` to `NoStatus` to register a new operator.
                    self.malicious_operator_status.no_status();
                } else if !current_operators.contains_key(&operator_id) {
                    self.submit_force_staking_epoch_transition(self.sudo_acccount_nonce()?)?;
                } else {
                    tracing::info!(
                        ?operator_id,
                        ?signing_key,
                        "Registered a new malicious operator"
                    );
                    self.malicious_operator_status
                        .registered(operator_id, signing_key);
                }
            }
        }

        Ok(())
    }

    fn sudo_acccount_nonce(&self) -> Result<Nonce, Box<dyn Error>> {
        Ok(self.consensus_client.runtime_api().account_nonce(
            self.consensus_client.info().best_hash,
            self.sudo_account.clone(),
        )?)
    }

    fn submit_bundle(
        &self,
        opaque_bundle: OpaqueBundleFor<DomainBlock, CBlock>,
    ) -> Result<(), Box<dyn Error>> {
        let call = pallet_domains::Call::submit_bundle { opaque_bundle };
        self.submit_consensus_extrinsic(None, call.into())
    }

    fn submit_register_operator(
        &self,
        nonce: Nonce,
        signing_key: OperatorPublicKey,
        staking_amount: Balance,
    ) -> Result<(), Box<dyn Error>> {
        let call = pallet_domains::Call::register_operator {
            domain_id: self.domain_id,
            amount: staking_amount,
            config: OperatorConfig {
                signing_key,
                minimum_nominator_stake: Balance::MAX,
                nomination_tax: Default::default(),
            },
        };
        self.submit_consensus_extrinsic(Some(nonce), call.into())
    }

    fn submit_force_staking_epoch_transition(&self, nonce: Nonce) -> Result<(), Box<dyn Error>> {
        let call = pallet_sudo::Call::sudo {
            call: Box::new(RuntimeCall::Domains(
                pallet_domains::Call::force_staking_epoch_transition {
                    domain_id: self.domain_id,
                },
            )),
        };
        self.submit_consensus_extrinsic(Some(nonce), call.into())
    }

    fn submit_consensus_extrinsic(
        &self,
        maybe_nonce: Option<Nonce>,
        call: RuntimeCall,
    ) -> Result<(), Box<dyn Error>> {
        let etx = match maybe_nonce {
            Some(nonce) => construct_signed_extrinsic(
                &self.consensus_keystore,
                self.consensus_client.info(),
                call.clone(),
                self.sudo_account.clone(),
                nonce,
            )?,
            None => {
                // for general unsigned, nonce does not matter.
                let extra =
                    get_singed_extra(self.consensus_client.info().best_number.into(), true, 0);
                UncheckedExtrinsic::new_transaction(call.clone(), extra)
            }
        };

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

fn get_singed_extra(best_number: u64, immortal: bool, nonce: Nonce) -> SignedExtra {
    let period = u64::from(<<Runtime as frame_system::Config>::BlockHashCount>::get())
        .checked_next_power_of_two()
        .map(|c| c / 2)
        .unwrap_or(2);
    (
        frame_system::CheckNonZeroSender::<Runtime>::new(),
        frame_system::CheckSpecVersion::<Runtime>::new(),
        frame_system::CheckTxVersion::<Runtime>::new(),
        frame_system::CheckGenesis::<Runtime>::new(),
        frame_system::CheckMortality::<Runtime>::from(if immortal {
            generic::Era::Immortal
        } else {
            generic::Era::mortal(period, best_number)
        }),
        frame_system::CheckNonce::<Runtime>::from(nonce.into()),
        frame_system::CheckWeight::<Runtime>::new(),
        pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(0u128),
        DisablePallets,
        pallet_subspace::extensions::SubspaceExtension::<Runtime>::new(),
        pallet_domains::extensions::DomainsExtension::<Runtime>::new(),
        pallet_messenger::extensions::MessengerExtension::<Runtime>::new(),
    )
}

pub fn construct_signed_extrinsic(
    consensus_keystore: &KeystorePtr,
    consensus_chain_info: Info<CBlock>,
    call: RuntimeCall,
    caller: AccountId,
    nonce: Nonce,
) -> Result<UncheckedExtrinsic, Box<dyn Error>> {
    let extra = get_singed_extra(consensus_chain_info.best_number.into(), false, nonce);
    let raw_payload = generic::SignedPayload::<RuntimeCall, SignedExtra>::from_raw(
        call.clone(),
        extra.clone(),
        (
            (),
            subspace_runtime::VERSION.spec_version,
            subspace_runtime::VERSION.transaction_version,
            consensus_chain_info.genesis_hash,
            consensus_chain_info.best_hash,
            (),
            (),
            (),
            (),
            (),
            (),
            (),
        ),
    );

    let signature = match Sr25519Keyring::from_account_id(&caller) {
        Some(keyring) => raw_payload.using_encoded(|e| keyring.sign(e)),
        None => {
            let public_key =
                sp_core::sr25519::Public::unchecked_from(<AccountId as Into<[u8; 32]>>::into(
                    caller.clone(),
                ));
            raw_payload
                .using_encoded(|e| {
                    consensus_keystore
                        .sr25519_sign(OperatorPublicKey::ID, &public_key, e)
                })?
                .ok_or(format!(
                    "Failed to sign extrinsic, sudo key pair missing from keystore?, public_key {:?}",
                    public_key
                ))?
        }
    };

    Ok(UncheckedExtrinsic::new_signed(
        call,
        sp_runtime::MultiAddress::Id(caller),
        signature.into(),
        extra,
    ))
}
