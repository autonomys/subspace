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

use crate::runtime_api::InherentExtrinsicConstructor;
use sp_api::ProvideRuntimeApi;
use sp_domains::DomainsApi;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::sync::Arc;

/// Returns required inherent extrinsics for the domain block based on the primary block.
/// Note: consensus block hash must be used to construct domain block.
// TODO: Remove once evm domain is supported.
#[allow(dead_code)]
pub fn construct_inherent_extrinsics<Block, DomainRuntimeApi, CBlock, CClient>(
    consensus_client: &Arc<CClient>,
    domain_runtime_api: &DomainRuntimeApi,
    consensus_block_hash: CBlock::Hash,
    domain_parent_hash: Block::Hash,
) -> Result<Vec<Block::Extrinsic>, sp_blockchain::Error>
where
    Block: BlockT,
    CBlock: BlockT,
    CClient: ProvideRuntimeApi<CBlock>,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>,
    DomainRuntimeApi: InherentExtrinsicConstructor<Block>,
{
    let moment = consensus_client
        .runtime_api()
        .timestamp(consensus_block_hash)?;

    let mut inherent_exts = vec![];
    if let Some(inherent_timestamp) =
        domain_runtime_api.construct_timestamp_inherent_extrinsic(domain_parent_hash, moment)?
    {
        inherent_exts.push(inherent_timestamp)
    }

    Ok(inherent_exts)
}
