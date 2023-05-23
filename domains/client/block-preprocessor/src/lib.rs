//! This crate provides a preprocessor for the domain block, which is used to construct
//! domain extrinsics from the primary block.
//!
//! The workflow is as follows:
//! 1. Extract domain-specific bundles from the primary block.
//! 2. Compile the domain bundles into a list of extrinsics.
//!     - System domain: Each core domain bundle in the primary block will be wrapped
//!     in an extrinsic and then joined with the extrinsics extracted from the system
//!     domain bundle.
//!     - Core domain: Extrinsics extracted from the core domain bundle.
//! 3. Shuffle the extrisnics using the seed from the primary chain.
//! 4. Filter out the invalid xdm extrinsics.
//! 5. Push back the potential new domain runtime extrisnic.

#![warn(rust_2018_idioms)]

mod inherents;
pub mod runtime_api;
pub mod runtime_api_full;
pub mod runtime_api_light;
mod utils;
pub mod xdm_verifier;

use crate::inherents::construct_inherent_extrinsics;
use crate::runtime_api::{
    CoreBundleConstructor, InherentExtrinsicConstructor, SetCodeConstructor, SignerExtractor,
    StateRootExtractor,
};
use crate::xdm_verifier::{
    verify_xdm_with_primary_chain_client, verify_xdm_with_system_domain_client,
};
use codec::{Decode, Encode};
use domain_runtime_primitives::opaque::AccountId;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sc_client_api::BlockBackend;
use sp_api::{CallApiAt, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_domains::{DomainId, ExecutorApi, OpaqueBundles};
use sp_messenger::MessengerApi;
use sp_runtime::generic::DigestItem;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};
use std::borrow::Cow;
use std::collections::{BTreeMap, VecDeque};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::Randomness;
use subspace_wasm_tools::read_core_domain_runtime_blob;
use system_runtime_primitives::SystemDomainApi;

type MaybeNewRuntime = Option<Cow<'static, [u8]>>;

type DomainBlockElements<PBlock> = (
    Vec<<PBlock as BlockT>::Extrinsic>,
    Randomness,
    MaybeNewRuntime,
);

/// Extracts the raw materials for building a new domain block from the primary block.
fn prepare_domain_block_elements<Block, PBlock, PClient>(
    domain_id: DomainId,
    primary_chain_client: &PClient,
    block_hash: PBlock::Hash,
) -> sp_blockchain::Result<DomainBlockElements<PBlock>>
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

        let new_runtime = {
            if domain_id.is_system() {
                system_domain_runtime
            } else if domain_id.is_core() {
                read_core_domain_runtime_blob(system_domain_runtime.as_ref(), domain_id)
                    .map_err(|err| sp_blockchain::Error::Application(Box::new(err)))?
                    .into()
            } else {
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

    Ok((extrinsics, shuffling_seed, maybe_new_runtime))
}

fn compile_own_domain_bundles<Block, PBlock>(
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
                    }
                }
            })
        })
        .collect::<Vec<_>>()
}

fn deduplicate_and_shuffle_extrinsics<Block, SE>(
    parent_hash: Block::Hash,
    signer_extractor: &SE,
    mut extrinsics: Vec<Block::Extrinsic>,
    shuffling_seed: Randomness,
) -> Result<Vec<Block::Extrinsic>, sp_blockchain::Error>
where
    Block: BlockT,
    SE: SignerExtractor<Block>,
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

    let extrinsics: Vec<_> = match signer_extractor.extract_signer(parent_hash, extrinsics) {
        Ok(res) => res,
        Err(e) => {
            tracing::error!(error = ?e, "Error at calling runtime api: extract_signer");
            return Err(e.into());
        }
    };

    let extrinsics =
        shuffle_extrinsics::<<Block as BlockT>::Extrinsic, AccountId>(extrinsics, shuffling_seed);

    Ok(extrinsics)
}

/// Shuffles the extrinsics in a deterministic way.
///
/// The extrinsics are grouped by the signer. The extrinsics without a signer, i.e., unsigned
/// extrinsics, are considered as a special group. The items in different groups are cross shuffled,
/// while the order of items inside the same group is still maintained.
fn shuffle_extrinsics<Extrinsic: Debug, AccountId: Ord + Clone>(
    extrinsics: Vec<(Option<AccountId>, Extrinsic)>,
    shuffling_seed: Randomness,
) -> Vec<Extrinsic> {
    let mut rng = ChaCha8Rng::from_seed(shuffling_seed);

    let mut positions = extrinsics
        .iter()
        .map(|(maybe_signer, _)| maybe_signer)
        .cloned()
        .collect::<Vec<_>>();

    // Shuffles the positions using Fisher–Yates algorithm.
    positions.shuffle(&mut rng);

    let mut grouped_extrinsics: BTreeMap<Option<AccountId>, VecDeque<_>> = extrinsics
        .into_iter()
        .fold(BTreeMap::new(), |mut groups, (maybe_signer, tx)| {
            groups
                .entry(maybe_signer)
                .or_insert_with(VecDeque::new)
                .push_back(tx);
            groups
        });

    // The relative ordering for the items in the same group does not change.
    let shuffled_extrinsics = positions
        .into_iter()
        .map(|maybe_signer| {
            grouped_extrinsics
                .get_mut(&maybe_signer)
                .expect("Extrinsics are grouped correctly; qed")
                .pop_front()
                .expect("Extrinsic definitely exists as it's correctly grouped above; qed")
        })
        .collect::<Vec<_>>();

    tracing::trace!(?shuffled_extrinsics, "Shuffled extrinsics");

    shuffled_extrinsics
}

pub struct SystemDomainBlockPreprocessor<Block, PBlock, PClient, RuntimeApi> {
    primary_chain_client: Arc<PClient>,
    runtime_api: RuntimeApi,
    _phantom_data: PhantomData<(Block, PBlock)>,
}

impl<Block, PBlock, PClient, RuntimeApi: Clone> Clone
    for SystemDomainBlockPreprocessor<Block, PBlock, PClient, RuntimeApi>
{
    fn clone(&self) -> Self {
        Self {
            primary_chain_client: self.primary_chain_client.clone(),
            runtime_api: self.runtime_api.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, PBlock, PClient, RuntimeApi>
    SystemDomainBlockPreprocessor<Block, PBlock, PClient, RuntimeApi>
where
    Block: BlockT,
    PBlock: BlockT,
    PBlock::Hash: From<Block::Hash>,
    NumberFor<PBlock>: From<NumberFor<Block>>,
    RuntimeApi: CoreBundleConstructor<PBlock, Block>
        + SignerExtractor<Block>
        + StateRootExtractor<Block>
        + SetCodeConstructor<Block>,
    PClient: HeaderBackend<PBlock>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
{
    pub fn new(primary_chain_client: Arc<PClient>, runtime_api: RuntimeApi) -> Self {
        Self {
            primary_chain_client,
            runtime_api,
            _phantom_data: Default::default(),
        }
    }

    pub fn preprocess_primary_block_for_verifier(
        &self,
        primary_hash: PBlock::Hash,
    ) -> sp_blockchain::Result<Vec<Vec<u8>>> {
        // `domain_hash` is unused in `preprocess_primary_block` when using stateless runtime api.
        let domain_hash = Default::default();
        Ok(self
            .preprocess_primary_block(primary_hash, domain_hash)?
            .into_iter()
            .map(|ext| ext.encode())
            .collect())
    }

    pub fn preprocess_primary_block(
        &self,
        primary_hash: PBlock::Hash,
        domain_hash: Block::Hash,
    ) -> sp_blockchain::Result<Vec<Block::Extrinsic>> {
        let (primary_extrinsics, shuffling_seed, maybe_new_runtime) =
            prepare_domain_block_elements::<Block, PBlock, _>(
                DomainId::SYSTEM,
                &*self.primary_chain_client,
                primary_hash,
            )?;

        let (system_bundles, core_bundles) = self
            .primary_chain_client
            .runtime_api()
            .extract_system_bundles(primary_hash, primary_extrinsics)?;

        let origin_system_extrinsics = compile_own_domain_bundles::<Block, PBlock>(system_bundles);

        let extrinsics = self
            .runtime_api
            .construct_submit_core_bundle_extrinsics(domain_hash, core_bundles)?
            .into_iter()
            .map(|uxt| {
                <<Block as BlockT>::Extrinsic>::decode(&mut uxt.as_slice())
                    .expect("Internally constructed extrinsic must be valid; qed")
            })
            .chain(origin_system_extrinsics)
            .collect::<Vec<_>>();

        let mut extrinsics = deduplicate_and_shuffle_extrinsics(
            domain_hash,
            &self.runtime_api,
            extrinsics,
            shuffling_seed,
        )
        .map(|exts| self.filter_invalid_xdm_extrinsics(domain_hash, exts))?;

        if let Some(new_runtime) = maybe_new_runtime {
            let encoded_set_code = self
                .runtime_api
                .construct_set_code_extrinsic(domain_hash, new_runtime.to_vec())?;
            let set_code_extrinsic = Block::Extrinsic::decode(&mut encoded_set_code.as_slice())
                .map_err(|err| {
                    sp_blockchain::Error::Application(Box::from(format!(
                        "Failed to decode `set_code` extrinsic: {err}"
                    )))
                })?;
            extrinsics.push(set_code_extrinsic);
        }

        Ok(extrinsics)
    }

    fn filter_invalid_xdm_extrinsics(
        &self,
        at: Block::Hash,
        exts: Vec<Block::Extrinsic>,
    ) -> Vec<Block::Extrinsic> {
        exts.into_iter()
            .filter(|ext| {
                match verify_xdm_with_primary_chain_client::<PClient, PBlock, Block, _>(
                    &self.primary_chain_client,
                    at,
                    &self.runtime_api,
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

pub struct CoreDomainBlockPreprocessor<Block, PBlock, SBlock, PClient, SClient, RuntimeApi> {
    domain_id: DomainId,
    runtime_api: RuntimeApi,
    system_domain_client: Arc<SClient>,
    primary_chain_client: Arc<PClient>,
    _phantom_data: PhantomData<(Block, PBlock, SBlock)>,
}

impl<Block, PBlock, SBlock, PClient, SClient, RuntimeApi: Clone> Clone
    for CoreDomainBlockPreprocessor<Block, PBlock, SBlock, PClient, SClient, RuntimeApi>
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            runtime_api: self.runtime_api.clone(),
            system_domain_client: self.system_domain_client.clone(),
            primary_chain_client: self.primary_chain_client.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, PBlock, SBlock, PClient, SClient, RuntimeApi>
    CoreDomainBlockPreprocessor<Block, PBlock, SBlock, PClient, SClient, RuntimeApi>
where
    Block: BlockT,
    PBlock: BlockT,
    SBlock: BlockT,
    SBlock::Hash: From<Block::Hash>,
    NumberFor<SBlock>: From<NumberFor<Block>>,
    RuntimeApi: SignerExtractor<Block>
        + SetCodeConstructor<Block>
        + StateRootExtractor<Block>
        + InherentExtrinsicConstructor<Block>,
    PClient: HeaderBackend<PBlock>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + CallApiAt<PBlock>
        + Send
        + Sync,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api: SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>
        + MessengerApi<SBlock, NumberFor<SBlock>>,
{
    pub fn new(
        domain_id: DomainId,
        runtime_api: RuntimeApi,
        primary_chain_client: Arc<PClient>,
        system_domain_client: Arc<SClient>,
    ) -> Self {
        Self {
            domain_id,
            runtime_api,
            system_domain_client,
            primary_chain_client,
            _phantom_data: Default::default(),
        }
    }

    pub fn preprocess_primary_block_for_verifier(
        &self,
        primary_hash: PBlock::Hash,
    ) -> sp_blockchain::Result<Vec<Vec<u8>>> {
        // `domain_hash` is unused in `preprocess_primary_block` when using stateless runtime api.
        let domain_hash = Default::default();
        Ok(self
            .preprocess_primary_block(primary_hash, domain_hash)?
            .into_iter()
            .map(|ext| ext.encode())
            .collect())
    }

    pub fn preprocess_primary_block(
        &self,
        primary_hash: PBlock::Hash,
        domain_hash: Block::Hash,
    ) -> sp_blockchain::Result<Vec<Block::Extrinsic>> {
        let (primary_extrinsics, shuffling_seed, maybe_new_runtime) =
            prepare_domain_block_elements::<Block, PBlock, _>(
                self.domain_id,
                &*self.primary_chain_client,
                primary_hash,
            )?;

        let core_bundles = self
            .primary_chain_client
            .runtime_api()
            .extract_core_bundles(primary_hash, primary_extrinsics, self.domain_id)?;

        let extrinsics = compile_own_domain_bundles::<Block, PBlock>(core_bundles);

        let extrinsics = deduplicate_and_shuffle_extrinsics(
            domain_hash,
            &self.runtime_api,
            extrinsics,
            shuffling_seed,
        )
        .map(|extrinsics| self.filter_invalid_xdm_extrinsics(domain_hash, extrinsics))?;

        // fetch inherent extrinsics
        let inherent_extrinsics = construct_inherent_extrinsics(
            &self.primary_chain_client,
            &self.runtime_api,
            primary_hash,
            domain_hash,
        )?;

        let mut extrinsics: Vec<Block::Extrinsic> = inherent_extrinsics
            .into_iter()
            .chain(extrinsics.into_iter())
            .collect();

        if let Some(new_runtime) = maybe_new_runtime {
            let encoded_set_code = self
                .runtime_api
                .construct_set_code_extrinsic(domain_hash, new_runtime.to_vec())?;
            let set_code_extrinsic = Block::Extrinsic::decode(&mut encoded_set_code.as_slice())
                .map_err(|err| {
                    sp_blockchain::Error::Application(Box::from(format!(
                        "Failed to decode `set_code` extrinsic: {err}"
                    )))
                })?;
            extrinsics.push(set_code_extrinsic);
        }

        Ok(extrinsics)
    }

    fn filter_invalid_xdm_extrinsics(
        &self,
        at: Block::Hash,
        exts: Vec<Block::Extrinsic>,
    ) -> Vec<Block::Extrinsic> {
        exts.into_iter()
            .filter(|ext| {
                match verify_xdm_with_system_domain_client::<_, Block, SBlock, PBlock, _>(
                    &self.system_domain_client,
                    at,
                    ext,
                    &self.runtime_api,
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

#[cfg(test)]
mod tests {
    use super::shuffle_extrinsics;
    use sp_keyring::sr25519::Keyring;
    use sp_runtime::traits::{BlakeTwo256, Hash as HashT};

    #[test]
    fn shuffle_extrinsics_should_work() {
        let alice = Keyring::Alice.to_account_id();
        let bob = Keyring::Bob.to_account_id();
        let charlie = Keyring::Charlie.to_account_id();

        let extrinsics = vec![
            (Some(alice.clone()), 10),
            (None, 100),
            (Some(bob.clone()), 1),
            (Some(bob), 2),
            (Some(charlie.clone()), 30),
            (Some(alice.clone()), 11),
            (Some(charlie), 31),
            (None, 101),
            (None, 102),
            (Some(alice), 12),
        ];

        let dummy_seed = BlakeTwo256::hash_of(&[1u8; 64]).into();
        let shuffled_extrinsics = shuffle_extrinsics(extrinsics, dummy_seed);

        assert_eq!(
            shuffled_extrinsics,
            vec![100, 30, 10, 1, 11, 101, 31, 12, 102, 2]
        );
    }
}
