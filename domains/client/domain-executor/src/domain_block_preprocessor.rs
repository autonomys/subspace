use crate::utils::shuffle_extrinsics;
use codec::{Decode, Encode};
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use sc_client_api::BlockBackend;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_domains::{DomainId, ExecutorApi, OpaqueBundles, SignedOpaqueBundles};
use sp_runtime::generic::DigestItem;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use std::borrow::Cow;
use std::sync::Arc;
use subspace_core_primitives::Randomness;
use subspace_wasm_tools::read_core_domain_runtime_blob;

/// Domain-specific bundles extracted from the primary block.
pub enum DomainBundles<Block, PBlock>
where
    Block: BlockT,
    PBlock: BlockT,
{
    System(
        OpaqueBundles<PBlock, Block::Hash>,
        SignedOpaqueBundles<PBlock, Block::Hash>,
    ),
    Core(OpaqueBundles<PBlock, Block::Hash>),
}

pub type DomainBlockElements<Block, PBlock> = (
    DomainBundles<Block, PBlock>,
    Randomness,
    Option<Cow<'static, [u8]>>,
);

/// Extracts the necessary materials for building a new domain block from the primary block.
pub(crate) fn preprocess_primary_block<Block, PBlock, PClient>(
    domain_id: DomainId,
    primary_chain_client: &PClient,
    block_hash: PBlock::Hash,
) -> sp_blockchain::Result<DomainBlockElements<Block, PBlock>>
where
    Block: BlockT,
    PBlock: BlockT,
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock> + Send + Sync,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
{
    let extrinsics = primary_chain_client
        .block_body(block_hash)?
        .ok_or_else(|| {
            sp_blockchain::Error::Backend(format!("BlockBody of {block_hash:?} unavailable"))
        })?;

    let header = primary_chain_client.header(block_hash)?.ok_or_else(|| {
        sp_blockchain::Error::Backend(format!("BlockHeader of {block_hash:?} unavailable"))
    })?;

    let maybe_new_runtime = if header
        .digest()
        .logs
        .iter()
        .any(|item| *item == DigestItem::RuntimeEnvironmentUpdated)
    {
        let system_domain_runtime = primary_chain_client
            .runtime_api()
            .system_domain_wasm_bundle(block_hash)?;

        let new_runtime = match domain_id {
            DomainId::SYSTEM => system_domain_runtime,
            DomainId::CORE_PAYMENTS => {
                read_core_domain_runtime_blob(system_domain_runtime.as_ref(), domain_id)
                    .map_err(|err| sp_blockchain::Error::Application(Box::new(err)))?
                    .into()
            }
            _ => {
                return Err(sp_blockchain::Error::Application(Box::from(format!(
                    "No new runtime code for {domain_id:?}"
                ))));
            }
        };

        Some(new_runtime)
    } else {
        None
    };

    let shuffling_seed = primary_chain_client
        .runtime_api()
        .extrinsics_shuffling_seed(block_hash, header)?;

    let domain_bundles = if domain_id.is_system() {
        let (system_bundles, core_bundles) = primary_chain_client
            .runtime_api()
            .extract_system_bundles(block_hash, extrinsics)?;
        DomainBundles::System(system_bundles, core_bundles)
    } else if domain_id.is_core() {
        let core_bundles = primary_chain_client
            .runtime_api()
            .extract_core_bundles(block_hash, extrinsics, domain_id)?;
        DomainBundles::Core(core_bundles)
    } else {
        unreachable!("Open domains are unsupported")
    };

    Ok((domain_bundles, shuffling_seed, maybe_new_runtime))
}

pub(crate) fn compile_own_domain_bundles<Block, PBlock>(
    bundles: OpaqueBundles<PBlock, Block::Hash>,
) -> Vec<Block::Extrinsic>
where
    Block: BlockT,
    PBlock: BlockT,
{
    bundles
            .into_iter()
            .flat_map(|bundle| {
                bundle.extrinsics.into_iter().filter_map(|opaque_extrinsic| {
                    match <<Block as BlockT>::Extrinsic>::decode(
                        &mut opaque_extrinsic.encode().as_slice(),
                    ) {
                        Ok(uxt) => Some(uxt),
                        Err(e) => {
                            tracing::error!(
                                error = ?e,
                                "Failed to decode the opaque extrisic in bundle, this should not happen"
                            );
                            None
                        },
                    }
                })
            })
            .collect::<Vec<_>>()
}

pub(crate) fn deduplicate_and_shuffle_extrinsics<Block, Client>(
    client: &Arc<Client>,
    parent_hash: Block::Hash,
    mut extrinsics: Vec<Block::Extrinsic>,
    shuffling_seed: Randomness,
) -> Result<Vec<Block::Extrinsic>, sp_blockchain::Error>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: DomainCoreApi<Block, AccountId>,
{
    let mut seen = Vec::new();
    extrinsics.retain(|uxt| match seen.contains(uxt) {
        true => {
            tracing::trace!(extrinsic = ?uxt, "Duplicated extrinsic");
            false
        }
        false => {
            seen.push(uxt.clone());
            true
        }
    });
    drop(seen);

    tracing::trace!(?extrinsics, "Origin deduplicated extrinsics");

    let extrinsics: Vec<_> = match client.runtime_api().extract_signer(parent_hash, extrinsics) {
        Ok(res) => res,
        Err(e) => {
            tracing::error!(error = ?e, "Error at calling runtime api: extract_signer");
            return Err(e.into());
        }
    };

    let extrinsics = shuffle_extrinsics::<<Block as BlockT>::Extrinsic>(extrinsics, shuffling_seed);

    Ok(extrinsics)
}
