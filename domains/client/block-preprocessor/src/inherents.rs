//! Provides functionality of adding inherent extrinsics to the Domain.
//! Unlike Primary chain where inherent data is first derived the block author
//! and the data is verified by the on primary runtime, domains inherents
//! short circuit the derivation and verification of inherent data
//! as the inherent data is directly taken from the primary block from which
//! domain block is being built.
//!
//! One of the first use case for this is passing Timestamp data. Before building a
//! domain block using a primary block, we take the current time from the primary runtime
//! and then create an unsigned extrinsic that is put on top the bundle extrinsics.
//!
//! Deriving these extrinsics during fraud proof verification should be possible since
//! verification environment will have access to consensus chain.

use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_domains::{DomainId, DomainsApi, DomainsDigestItem};
use sp_inherents::{CreateInherentDataProviders, InherentData, InherentDataProvider};
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use sp_timestamp::InherentType;
use std::error::Error;
use std::sync::Arc;

pub async fn get_inherent_data<CClient, CBlock, Block>(
    consensus_client: Arc<CClient>,
    consensus_block_hash: CBlock::Hash,
    parent_hash: Block::Hash,
    domain_id: DomainId,
) -> Result<InherentData, sp_blockchain::Error>
where
    CBlock: BlockT,
    Block: BlockT,
    CClient: ProvideRuntimeApi<CBlock> + HeaderBackend<CBlock>,
    CClient::Api:
        DomainsApi<CBlock, Block::Header> + MessengerApi<CBlock, NumberFor<CBlock>, CBlock::Hash>,
{
    let create_inherent_data_providers =
        CreateInherentDataProvider::new(consensus_client, Some(consensus_block_hash), domain_id);
    let inherent_data_providers = <CreateInherentDataProvider<_, _> as CreateInherentDataProviders<
        Block,
        (),
    >>::create_inherent_data_providers(
        &create_inherent_data_providers, parent_hash, ()
    )
        .await?;
    let mut inherent_data = InherentData::new();
    inherent_data_providers
        .provide_inherent_data(&mut inherent_data)
        .await
        .map_err(|err| {
            sp_blockchain::Error::Application(Box::from(format!(
                "failed to provide inherent data: {err:?}"
            )))
        })?;

    Ok(inherent_data)
}

pub(crate) fn is_runtime_upgraded<CClient, CBlock, Block>(
    consensus_client: &Arc<CClient>,
    consensus_block_hash: CBlock::Hash,
    domain_id: DomainId,
) -> Result<bool, sp_blockchain::Error>
where
    CClient: ProvideRuntimeApi<CBlock> + HeaderBackend<CBlock>,
    CClient::Api: DomainsApi<CBlock, Block::Header>,
    CBlock: BlockT,
    Block: BlockT,
{
    let header = consensus_client.header(consensus_block_hash)?.ok_or(
        sp_blockchain::Error::MissingHeader(format!(
            "No header found for {consensus_block_hash:?}"
        )),
    )?;

    let runtime_api = consensus_client.runtime_api();
    let runtime_id = runtime_api
        .runtime_id(consensus_block_hash, domain_id)?
        .ok_or(sp_blockchain::Error::Application(Box::from(format!(
            "No RuntimeId found for {domain_id:?}"
        ))))?;

    Ok(header
        .digest()
        .logs
        .iter()
        .filter_map(|log| log.as_domain_runtime_upgrade())
        .any(|upgraded_runtime_id| upgraded_runtime_id == runtime_id))
}

/// Returns new upgraded runtime if upgraded did happen in the provided consensus block.
pub fn extract_domain_runtime_upgrade_code<CClient, CBlock, Block>(
    consensus_client: &Arc<CClient>,
    consensus_block_hash: CBlock::Hash,
    domain_id: DomainId,
) -> Result<Option<Vec<u8>>, sp_blockchain::Error>
where
    CClient: ProvideRuntimeApi<CBlock> + HeaderBackend<CBlock>,
    CClient::Api: DomainsApi<CBlock, Block::Header>,
    CBlock: BlockT,
    Block: BlockT,
{
    let header = consensus_client.header(consensus_block_hash)?.ok_or(
        sp_blockchain::Error::MissingHeader(format!(
            "No header found for {consensus_block_hash:?}"
        )),
    )?;

    let runtime_api = consensus_client.runtime_api();
    let runtime_id = runtime_api
        .runtime_id(consensus_block_hash, domain_id)?
        .ok_or(sp_blockchain::Error::Application(Box::from(format!(
            "No RuntimeId found for {domain_id:?}"
        ))))?;

    if header
        .digest()
        .logs
        .iter()
        .filter_map(|log| log.as_domain_runtime_upgrade())
        .any(|upgraded_runtime_id| upgraded_runtime_id == runtime_id)
    {
        let new_domain_runtime = runtime_api
            .domain_runtime_code(consensus_block_hash, domain_id)?
            .ok_or_else(|| {
                sp_blockchain::Error::Application(Box::from(format!(
                    "No new runtime code for {domain_id:?}"
                )))
            })?;

        Ok(Some(new_domain_runtime))
    } else {
        Ok(None)
    }
}

#[derive(Debug)]
pub struct CreateInherentDataProvider<CClient, CBlock: BlockT> {
    consensus_client: Arc<CClient>,
    maybe_consensus_block_hash: Option<CBlock::Hash>,
    domain_id: DomainId,
}

impl<CClient, CBlock: BlockT + Clone> Clone for CreateInherentDataProvider<CClient, CBlock> {
    fn clone(&self) -> Self {
        Self {
            consensus_client: self.consensus_client.clone(),
            maybe_consensus_block_hash: self.maybe_consensus_block_hash,
            domain_id: self.domain_id,
        }
    }
}

impl<CClient, CBlock: BlockT> CreateInherentDataProvider<CClient, CBlock> {
    pub fn new(
        consensus_client: Arc<CClient>,
        maybe_consensus_block_hash: Option<CBlock::Hash>,
        domain_id: DomainId,
    ) -> Self {
        Self {
            consensus_client,
            maybe_consensus_block_hash,
            domain_id,
        }
    }
}

#[async_trait::async_trait]
impl<CClient, CBlock, Block> CreateInherentDataProviders<Block, ()>
    for CreateInherentDataProvider<CClient, CBlock>
where
    Block: BlockT,
    CBlock: BlockT,
    CClient: ProvideRuntimeApi<CBlock> + HeaderBackend<CBlock>,
    CClient::Api:
        DomainsApi<CBlock, Block::Header> + MessengerApi<CBlock, NumberFor<CBlock>, CBlock::Hash>,
{
    type InherentDataProviders = (
        sp_timestamp::InherentDataProvider,
        sp_block_fees::InherentDataProvider,
        sp_executive::InherentDataProvider,
        sp_messenger::InherentDataProvider,
        sp_domain_sudo::InherentDataProvider,
    );

    async fn create_inherent_data_providers(
        &self,
        _parent: Block::Hash,
        _extra_args: (),
    ) -> Result<Self::InherentDataProviders, Box<dyn Error + Send + Sync>> {
        // always prefer the consensus block hash that was given but eth_rpc
        // uses this inherent provider to while fetching pending state
        // https://github.com/paritytech/frontier/blob/master/client/rpc/src/eth/pending.rs#L70
        // This is a non mutable call used by web3 api and using the best consensus block hash
        // here is completely ok.
        let consensus_block_hash = self
            .maybe_consensus_block_hash
            .unwrap_or(self.consensus_client.info().best_hash);
        let runtime_api = self.consensus_client.runtime_api();
        let timestamp = runtime_api.timestamp(consensus_block_hash)?;
        let timestamp_provider =
            sp_timestamp::InherentDataProvider::new(InherentType::new(timestamp));

        let maybe_runtime_upgrade_code = extract_domain_runtime_upgrade_code::<_, _, Block>(
            &self.consensus_client,
            consensus_block_hash,
            self.domain_id,
        )?;
        let runtime_upgrade_provider =
            sp_executive::InherentDataProvider::new(maybe_runtime_upgrade_code);

        let consensus_chain_byte_fee =
            runtime_api.consensus_chain_byte_fee(consensus_block_hash)?;
        let storage_price_provider =
            sp_block_fees::InherentDataProvider::new(consensus_chain_byte_fee);

        let domain_chains_allowlist_update =
            runtime_api.domain_chains_allowlist_update(consensus_block_hash, self.domain_id)?;
        let messenger_inherent_provider =
            sp_messenger::InherentDataProvider::new(sp_messenger::InherentType {
                maybe_updates: domain_chains_allowlist_update,
            });

        let maybe_domain_sudo_call =
            runtime_api.domain_sudo_call(consensus_block_hash, self.domain_id)?;
        let domain_sudo_call_inherent_provider =
            sp_domain_sudo::InherentDataProvider::new(maybe_domain_sudo_call);

        Ok((
            timestamp_provider,
            storage_price_provider,
            runtime_upgrade_provider,
            messenger_inherent_provider,
            domain_sudo_call_inherent_provider,
        ))
    }
}
