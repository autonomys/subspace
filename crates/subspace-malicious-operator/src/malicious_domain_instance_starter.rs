use crate::malicious_bundle_producer::MaliciousBundleProducer;
use cross_domain_message_gossip::{ChainTxPoolMsg, Message};
use domain_client_operator::{BootstrapResult, OperatorStreams};
use domain_eth_service::provider::EthProvider;
use domain_eth_service::DefaultEthConfig;
use domain_runtime_primitives::opaque::Block as DomainBlock;
use domain_service::{FullBackend, FullClient};
use evm_domain_runtime::ExecutorDispatch as EVMDomainExecutorDispatch;
use futures::StreamExt;
use sc_cli::CliConfiguration;
use sc_consensus_subspace::block_import::BlockImportingNotification;
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::slot_worker::NewSlotNotification;
use sc_network::NetworkPeers;
use sc_service::BasePath;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_utils::mpsc::{TracingUnboundedReceiver, TracingUnboundedSender};
use sp_core::traits::SpawnEssentialNamed;
use sp_domains::{DomainInstanceData, RuntimeType};
use sp_keystore::KeystorePtr;
use std::sync::Arc;
use subspace_node::domain::{create_configuration, evm_chain_spec, AccountId20, DomainCli};
use subspace_runtime::{ExecutorDispatch as CExecutorDispatch, RuntimeApi as CRuntimeApi};
use subspace_runtime_primitives::opaque::Block as CBlock;
use subspace_service::FullClient as CFullClient;

/// `DomainInstanceStarter` used to start a domain instance node based on the given
/// bootstrap result
pub struct DomainInstanceStarter<CNetwork> {
    pub domain_cli: DomainCli,
    pub tokio_handle: tokio::runtime::Handle,
    pub consensus_client: Arc<CFullClient<CRuntimeApi, CExecutorDispatch>>,
    pub consensus_keystore: KeystorePtr,
    pub consensus_offchain_tx_pool_factory: OffchainTransactionPoolFactory<CBlock>,
    pub block_importing_notification_stream:
        SubspaceNotificationStream<BlockImportingNotification<CBlock>>,
    pub new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    pub consensus_sync_service: Arc<sc_network_sync::SyncingService<CBlock>>,
    pub domain_message_receiver: TracingUnboundedReceiver<ChainTxPoolMsg>,
    pub gossip_message_sink: TracingUnboundedSender<Message>,
    pub consensus_network: Arc<CNetwork>,
}

impl<CNetwork> DomainInstanceStarter<CNetwork>
where
    CNetwork: NetworkPeers + Send + Sync + 'static,
{
    pub async fn start(
        self,
        bootstrap_result: BootstrapResult<CBlock>,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let BootstrapResult {
            domain_instance_data,
            domain_created_at,
            imported_block_notification_stream,
        } = bootstrap_result;

        let DomainInstanceData {
            runtime_type,
            raw_genesis,
        } = domain_instance_data;

        let DomainInstanceStarter {
            domain_cli,
            tokio_handle,
            consensus_client,
            consensus_keystore,
            consensus_offchain_tx_pool_factory,
            block_importing_notification_stream,
            new_slot_notification_stream,
            consensus_sync_service,
            domain_message_receiver,
            gossip_message_sink,
            consensus_network,
        } = self;

        let domain_id = domain_cli.domain_id;
        let domain_config = {
            let chain_id = domain_cli.chain_id(domain_cli.is_dev()?)?;

            let domain_spec = evm_chain_spec::create_domain_spec(chain_id.as_str(), raw_genesis)?;

            create_configuration::<_, DomainCli, DomainCli>(&domain_cli, domain_spec, tokio_handle)?
        };

        let block_importing_notification_stream = || {
            block_importing_notification_stream.subscribe().then(
                |block_importing_notification| async move {
                    (
                        block_importing_notification.block_number,
                        block_importing_notification.acknowledgement_sender,
                    )
                },
            )
        };

        let new_slot_notification_stream = || {
            new_slot_notification_stream
                .subscribe()
                .then(|slot_notification| async move {
                    (
                        slot_notification.new_slot_info.slot,
                        slot_notification.new_slot_info.global_randomness,
                    )
                })
        };

        let operator_streams = OperatorStreams {
            // TODO: proper value
            consensus_block_import_throttling_buffer_size: 10,
            block_importing_notification_stream: block_importing_notification_stream(),
            imported_block_notification_stream,
            new_slot_notification_stream: new_slot_notification_stream(),
            acknowledgement_sender_stream: futures::stream::empty(),
            _phantom: Default::default(),
        };

        match runtime_type {
            RuntimeType::Evm => {
                let evm_base_path = BasePath::new(
                    domain_config
                        .base_path
                        .config_dir(domain_config.chain_spec.id()),
                );

                let eth_provider =
                    EthProvider::<
                        evm_domain_runtime::TransactionConverter,
                        DefaultEthConfig<
                            FullClient<
                                DomainBlock,
                                evm_domain_runtime::RuntimeApi,
                                EVMDomainExecutorDispatch,
                            >,
                            FullBackend<DomainBlock>,
                        >,
                    >::new(Some(evm_base_path), domain_cli.additional_args());

                let domain_params = domain_service::DomainParams {
                    domain_id,
                    domain_config,
                    domain_created_at,
                    consensus_client: consensus_client.clone(),
                    consensus_offchain_tx_pool_factory: consensus_offchain_tx_pool_factory.clone(),
                    consensus_network,
                    consensus_network_sync_oracle: consensus_sync_service.clone(),
                    operator_streams,
                    gossip_message_sink,
                    domain_message_receiver,
                    provider: eth_provider,
                    skip_empty_bundle_production: true,
                    // Always set it to `None` to not running the normal bundle producer
                    maybe_operator_id: None,
                };

                let mut domain_node = domain_service::new_full::<
                    _,
                    _,
                    _,
                    _,
                    _,
                    _,
                    evm_domain_runtime::RuntimeApi,
                    EVMDomainExecutorDispatch,
                    AccountId20,
                    _,
                    _,
                >(domain_params)
                .await?;

                let malicious_bundle_producer = MaliciousBundleProducer::new(
                    domain_id,
                    domain_node.client.clone(),
                    consensus_client,
                    consensus_keystore,
                    consensus_offchain_tx_pool_factory,
                    domain_node.transaction_pool.clone(),
                );

                domain_node
                    .task_manager
                    .spawn_essential_handle()
                    .spawn_essential_blocking(
                        "malicious-bundle-producer",
                        None,
                        Box::pin(malicious_bundle_producer.start(new_slot_notification_stream())),
                    );

                domain_node.network_starter.start_network();

                domain_node.task_manager.future().await?;

                Ok(())
            }
        }
    }
}
