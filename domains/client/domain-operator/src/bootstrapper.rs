use futures::StreamExt;
use sc_client_api::{BlockchainEvents, ImportNotifications};
use sp_api::{HeaderT, NumberFor, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_domains::{DomainId, DomainInstanceData, DomainsApi, DomainsDigestItem};
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;
use std::sync::Arc;

pub struct BootstrapResult<CBlock: BlockT> {
    // The `DomainInstanceData` used by the domain instance starter to
    // construct `RuntimeGenesisConfig` of the domain instance
    pub domain_instance_data: DomainInstanceData,
    /// The consensus chain block number when the domain first instantiated.
    pub domain_created_at: NumberFor<CBlock>,
    // The `imported_block_notification_stream` used by the bootstrapper
    //
    // NOTE: the domain instance starter must reuse this stream instead of
    // create a new one from the consensus client to avoid missing imported
    // block notification.
    pub imported_block_notification_stream: ImportNotifications<CBlock>,
}

/// Domain instance bootstrapper
pub struct Bootstrapper<Block, CBlock, CClient> {
    consensus_client: Arc<CClient>,
    _phantom_data: PhantomData<(Block, CBlock)>,
}

impl<Block, CBlock, CClient> Bootstrapper<Block, CBlock, CClient>
where
    Block: BlockT,
    CBlock: BlockT,
    CClient: HeaderBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + BlockchainEvents<CBlock>
        + Send
        + Sync
        + 'static,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>,
{
    pub fn new(consensus_client: Arc<CClient>) -> Self {
        Bootstrapper {
            consensus_client,
            _phantom_data: Default::default(),
        }
    }

    pub async fn fetch_domain_bootstrap_info(
        self,
        self_domain_id: DomainId,
    ) -> std::result::Result<BootstrapResult<CBlock>, Box<dyn std::error::Error>> {
        let mut imported_block_notification_stream =
            self.consensus_client.every_import_notification_stream();

        // Check if the domain instance data already exist in the consensus chain's genesis state
        let best_hash = self.consensus_client.info().best_hash;
        if let Some((domain_instance_data, domain_created_at)) = self
            .consensus_client
            .runtime_api()
            .domain_instance_data(best_hash, self_domain_id)?
        {
            return Ok(BootstrapResult {
                domain_instance_data,
                domain_created_at,
                imported_block_notification_stream,
            });
        }

        // Check each imported consensus block to get the domain instance data
        let (domain_instance_data, domain_created_at) = 'outer: loop {
            if let Some(block_imported) = imported_block_notification_stream.next().await {
                let header = block_imported.header;
                for item in header.digest().logs.iter() {
                    if let Some(domain_id) = item.as_domain_instantiation() {
                        if domain_id == self_domain_id {
                            let res = self
                                .consensus_client
                                .runtime_api()
                                .domain_instance_data(header.hash(), domain_id)?;

                            match res {
                                Some(data) => break 'outer data,
                                None => {
                                    return Err(format!(
                                    "Failed to get domain instance data for domain {domain_id:?}"
                                )
                                    .into())
                                }
                            }
                        }
                    }
                }
            } else {
                return Err("Imported block notification stream end unexpectedly"
                    .to_string()
                    .into());
            }
        };

        Ok(BootstrapResult {
            domain_instance_data,
            domain_created_at,
            imported_block_notification_stream,
        })
    }
}
