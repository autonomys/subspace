use futures::StreamExt;
use sc_client_api::backend::Backend;
use sc_client_api::{BlockchainEvents, ImportNotifications};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_domains::{DomainId, DomainInstanceData, DomainsApi};
use sp_runtime::traits::{Block as BlockT, NumberFor, Zero};

#[derive(Debug)]
pub struct BootstrapResult<CBlock: BlockT> {
    // The [`DomainInstanceData`] used by the domain instance starter to
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

pub async fn fetch_domain_bootstrap_info<Block, CBlock, CClient, DomainBackend>(
    consensus_client: &CClient,
    domain_backend: &DomainBackend,
    self_domain_id: DomainId,
) -> Result<BootstrapResult<CBlock>, Box<dyn std::error::Error>>
where
    Block: BlockT,
    CBlock: BlockT,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + BlockchainEvents<CBlock>,
    CClient::Api: DomainsApi<CBlock, Block::Header>,
    DomainBackend: Backend<Block>,
{
    // The genesis block is finalized when the chain is initialized, if `finalized_state`
    // is non-empty meaning the domain chain is already started in the last run.
    let is_domain_started = domain_backend.blockchain().info().finalized_state.is_some();

    let mut imported_block_notification_stream =
        consensus_client.every_import_notification_stream();

    // Check if the domain instance data already exist in the consensus chain's state
    let best_hash = consensus_client.info().best_hash;
    if let Some((domain_instance_data, domain_created_at)) = consensus_client
        .runtime_api()
        .domain_instance_data(best_hash, self_domain_id)?
    {
        let domain_best_number = consensus_client
            .runtime_api()
            .domain_best_number(best_hash, self_domain_id)?
            .unwrap_or_default();

        // The `domain_best_number` is the expected best domain block after the operator has
        // processed the consensus block at `best_hash`. If `domain_best_number` is not zero
        // and the domain chain is not started, the domain block `0..domain_best_number` are
        // missed, we can not preceed running as a domain node because:
        //
        // - The consensus block and state that derive the domain block `0..domain_best_number`
        //    may not available anymore
        //
        // - There may be domain runtime upgrade in `0..domain_best_number` which will result
        //    in inconsistent `raw_genesis`
        if !is_domain_started && !domain_best_number.is_zero() {
            return Err(
                "An existing consensus node can't be restarted as a domain node, in order to
                proceed please wipe the `db` and `domains` folders"
                    .to_string()
                    .into(),
            );
        }

        return Ok(BootstrapResult {
            domain_instance_data,
            domain_created_at,
            imported_block_notification_stream,
        });
    }

    // The domain instance data is not found in the consensus chain while the domain chain
    // is already started meaning the domain chain is running ahead of the consensus chain,
    // which is unexpected as the domain chain is derived from the consensus chain.
    if is_domain_started {
        return Err(
            "The domain chain is ahead of the consensus chain, inconsistent `db` and `domains`
            folders from the last run"
                .to_string()
                .into(),
        );
    }

    // Check each imported consensus block to get the domain instance data
    let (domain_instance_data, domain_created_at) = loop {
        let Some(block_imported) = imported_block_notification_stream.next().await else {
            return Err("Imported block notification stream end unexpectedly"
                .to_string()
                .into());
        };
        let Some(data) = consensus_client
            .runtime_api()
            .domain_instance_data(block_imported.hash, self_domain_id)?
        else {
            continue;
        };
        break data;
    };

    Ok(BootstrapResult {
        domain_instance_data,
        domain_created_at,
        imported_block_notification_stream,
    })
}
