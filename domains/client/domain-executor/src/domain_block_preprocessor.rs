use crate::state_root_extractor::StateRootExtractorWithSystemDomainClient;
use crate::utils::shuffle_extrinsics;
use crate::xdm_verifier::{
    verify_xdm_with_primary_chain_client, verify_xdm_with_system_domain_client,
};
use codec::{Decode, Encode};
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use sc_client_api::BlockBackend;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_domains::{DomainId, ExecutorApi, OpaqueBundles, SignedOpaqueBundles};
use sp_messenger::MessengerApi;
use sp_runtime::generic::DigestItem;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};
use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::Randomness;
use subspace_wasm_tools::read_core_domain_runtime_blob;
use system_runtime_primitives::SystemDomainApi;

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

type MaybeNewRuntime = Option<Cow<'static, [u8]>>;

pub type DomainBlockElements<Block, PBlock> =
    (DomainBundles<Block, PBlock>, Randomness, MaybeNewRuntime);

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

pub struct SystemDomainBlockPreprocessor<Block, PBlock, Client, PClient> {
    client: Arc<Client>,
    primary_chain_client: Arc<PClient>,
    state_root_extractor: StateRootExtractorWithSystemDomainClient<Client>,
    _phantom_data: PhantomData<(Block, PBlock)>,
}

impl<Block, PBlock, Client, PClient> Clone
    for SystemDomainBlockPreprocessor<Block, PBlock, Client, PClient>
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            primary_chain_client: self.primary_chain_client.clone(),
            state_root_extractor: self.state_root_extractor.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, PBlock, Client, PClient> SystemDomainBlockPreprocessor<Block, PBlock, Client, PClient>
where
    Block: BlockT,
    PBlock: BlockT,
    PBlock::Hash: From<Block::Hash>,
    NumberFor<PBlock>: From<NumberFor<Block>>,
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: DomainCoreApi<Block, AccountId>
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>
        + MessengerApi<Block, NumberFor<Block>>,
    PClient: HeaderBackend<PBlock>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
{
    pub fn new(client: Arc<Client>, primary_chain_client: Arc<PClient>) -> Self {
        let state_root_extractor = StateRootExtractorWithSystemDomainClient::new(client.clone());
        Self {
            client,
            primary_chain_client,
            state_root_extractor,
            _phantom_data: Default::default(),
        }
    }

    pub fn preprocess_primary_block(
        &self,
        primary_hash: PBlock::Hash,
        domain_hash: Block::Hash,
    ) -> sp_blockchain::Result<(Vec<Block::Extrinsic>, MaybeNewRuntime)> {
        let (bundles, shuffling_seed, maybe_new_runtime) =
            preprocess_primary_block(DomainId::SYSTEM, &*self.primary_chain_client, primary_hash)?;

        let extrinsics = self
            .bundles_to_extrinsics(domain_hash, bundles, shuffling_seed)
            .map(|extrinsincs| self.filter_invalid_xdm_extrinsics(extrinsincs))?;

        Ok((extrinsics, maybe_new_runtime))
    }

    fn bundles_to_extrinsics(
        &self,
        parent_hash: Block::Hash,
        bundles: DomainBundles<Block, PBlock>,
        shuffling_seed: Randomness,
    ) -> Result<Vec<Block::Extrinsic>, sp_blockchain::Error> {
        let (system_bundles, core_bundles) = match bundles {
            DomainBundles::System(system_bundles, core_bundles) => (system_bundles, core_bundles),
            DomainBundles::Core(_) => {
                return Err(sp_blockchain::Error::Application(Box::from(
                    "System bundle processor can not process core bundles.",
                )));
            }
        };

        let origin_system_extrinsics = compile_own_domain_bundles::<Block, PBlock>(system_bundles);
        let extrinsics = self
            .client
            .runtime_api()
            .construct_submit_core_bundle_extrinsics(parent_hash, core_bundles)?
            .into_iter()
            .filter_map(
                |uxt| match <<Block as BlockT>::Extrinsic>::decode(&mut uxt.as_slice()) {
                    Ok(uxt) => Some(uxt),
                    Err(e) => {
                        tracing::error!(
                            error = ?e,
                            "Failed to decode the opaque extrisic in bundle, this should not happen"
                        );
                        None
                    }
                },
            )
            .chain(origin_system_extrinsics)
            .collect::<Vec<_>>();

        deduplicate_and_shuffle_extrinsics(&self.client, parent_hash, extrinsics, shuffling_seed)
    }

    fn filter_invalid_xdm_extrinsics(&self, exts: Vec<Block::Extrinsic>) -> Vec<Block::Extrinsic> {
        exts.into_iter()
            .filter(|ext| {
                match verify_xdm_with_primary_chain_client::<PClient, PBlock, Block, _>(
                    &self.primary_chain_client,
                    &self.state_root_extractor,
                    ext,
                ) {
                    Ok(valid) => valid,
                    Err(err) => {
                        tracing::error!(
                            target = "system_domain_xdm_filter",
                            "failed to verify extrinsic: {}",
                            err
                        );
                        false
                    }
                }
            })
            .collect()
    }
}

pub struct CoreDomainBlockPreprocessor<Block, PBlock, SBlock, Client, PClient, SClient> {
    domain_id: DomainId,
    client: Arc<Client>,
    system_domain_client: Arc<SClient>,
    primary_chain_client: Arc<PClient>,
    _phantom_data: PhantomData<(Block, PBlock, SBlock)>,
}

impl<Block, PBlock, SBlock, Client, PClient, SClient> Clone
    for CoreDomainBlockPreprocessor<Block, PBlock, SBlock, Client, PClient, SClient>
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            client: self.client.clone(),
            system_domain_client: self.system_domain_client.clone(),
            primary_chain_client: self.primary_chain_client.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, PBlock, SBlock, Client, PClient, SClient>
    CoreDomainBlockPreprocessor<Block, PBlock, SBlock, Client, PClient, SClient>
where
    Block: BlockT,
    PBlock: BlockT,
    SBlock: BlockT,
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: DomainCoreApi<Block, AccountId>,
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock> + Send + Sync,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api: SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>
        + MessengerApi<SBlock, NumberFor<SBlock>>,
    Block::Extrinsic: Into<SBlock::Extrinsic>,
{
    pub fn new(
        domain_id: DomainId,
        client: Arc<Client>,
        primary_chain_client: Arc<PClient>,
        system_domain_client: Arc<SClient>,
    ) -> Self {
        Self {
            domain_id,
            client,
            system_domain_client,
            primary_chain_client,
            _phantom_data: Default::default(),
        }
    }
    pub fn preprocess_primary_block(
        &self,
        primary_hash: PBlock::Hash,
        domain_hash: Block::Hash,
    ) -> sp_blockchain::Result<(Vec<Block::Extrinsic>, MaybeNewRuntime)> {
        let (bundles, shuffling_seed, maybe_new_runtime) =
            preprocess_primary_block(self.domain_id, &*self.primary_chain_client, primary_hash)?;

        let extrinsics = self
            .bundles_to_extrinsics(domain_hash, bundles, shuffling_seed)
            .map(|extrinsics| self.filter_invalid_xdm_extrinsics(extrinsics))?;

        Ok((extrinsics, maybe_new_runtime))
    }

    fn bundles_to_extrinsics(
        &self,
        parent_hash: Block::Hash,
        bundles: DomainBundles<Block, PBlock>,
        shuffling_seed: Randomness,
    ) -> Result<Vec<Block::Extrinsic>, sp_blockchain::Error> {
        let bundles = match bundles {
            DomainBundles::System(..) => {
                return Err(sp_blockchain::Error::Application(Box::from(
                    "Core bundle processor can not process system bundles.",
                )));
            }
            DomainBundles::Core(bundles) => bundles,
        };
        let extrinsics = compile_own_domain_bundles::<Block, PBlock>(bundles);
        deduplicate_and_shuffle_extrinsics(&self.client, parent_hash, extrinsics, shuffling_seed)
    }

    fn filter_invalid_xdm_extrinsics(&self, exts: Vec<Block::Extrinsic>) -> Vec<Block::Extrinsic> {
        exts.into_iter()
            .filter(|ext| {
                match verify_xdm_with_system_domain_client::<_, Block, SBlock, PBlock>(
                    &self.system_domain_client,
                    &(ext.clone().into()),
                ) {
                    Ok(valid) => valid,
                    Err(err) => {
                        tracing::error!(
                            target = "core_domain_xdm_filter",
                            "failed to verify extrinsic: {}",
                            err
                        );
                        false
                    }
                }
            })
            .collect()
    }
}
