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
//! verification environment will have access to primary chain.

use crate::runtime_api::InherentExtrinsicConstructor;
use sp_api::{CallApiAt, ProvideRuntimeApi};
use sp_domains::ExecutorApi;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

/// Returns required inherent extrinsics for the domain block based on the primary block.
/// Note: primary block hash must be used to construct domain block.
pub fn construct_inherent_extrinsics<Block, DomainRuntimeApi, PBlock, PClient>(
    primary_client: &Arc<PClient>,
    domain_runtime_api: &DomainRuntimeApi,
    primary_block_hash: PBlock::Hash,
    domain_parent_hash: Block::Hash,
) -> Result<Vec<Block::Extrinsic>, sp_blockchain::Error>
where
    Block: BlockT,
    PBlock: BlockT,
    PClient: ProvideRuntimeApi<PBlock> + CallApiAt<PBlock>,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    DomainRuntimeApi: InherentExtrinsicConstructor<Block>,
{
    let primary_api = primary_client.runtime_api();
    let runtime_version = primary_client.runtime_version_at(primary_block_hash)?;

    // we introduced timestamp at spec version 2
    // But since EVM will be expecting timestamp to be updated in each block.
    // We are just feeding it 0 if spec version is less than 2
    let mut moment = 0;
    if runtime_version.spec_version >= 2 {
        moment = primary_api.timestamp(primary_block_hash)?;
    }

    let mut inherent_exts = vec![];
    if let Some(inherent_timestamp) =
        domain_runtime_api.construct_timestamp_inherent_extrinsic(domain_parent_hash, moment)?
    {
        inherent_exts.push(inherent_timestamp)
    }

    Ok(inherent_exts)
}
