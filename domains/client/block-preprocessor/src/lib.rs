//! This crate provides a preprocessor for the domain block, which is used to construct
//! domain extrinsics from the consensus block.
//!
//! The workflow is as follows:
//! 1. Extract domain-specific bundles from the consensus block.
//! 2. Compile the domain bundles into a list of extrinsics.
//! 3. Shuffle the extrisnics using the seed from the consensus chain.
//! 4. Filter out the invalid xdm extrinsics.
//! 5. Push back the potential new domain runtime extrisnic.

#![warn(rust_2018_idioms)]

mod inherents;
pub mod runtime_api;
pub mod runtime_api_full;
pub mod runtime_api_light;
pub mod xdm_verifier;

use crate::inherents::construct_inherent_extrinsics;
use crate::runtime_api::{SetCodeConstructor, SignerExtractor, StateRootExtractor};
use crate::xdm_verifier::verify_xdm_with_consensus_client;
use codec::{Decode, Encode};
use domain_runtime_primitives::opaque::AccountId;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use runtime_api::InherentExtrinsicConstructor;
use sc_client_api::BlockBackend;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_domains::{DomainId, DomainsApi, OpaqueBundles};
use sp_runtime::generic::DigestItem;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};
use std::borrow::Cow;
use std::collections::{BTreeMap, VecDeque};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::Randomness;

type MaybeNewRuntime = Option<Cow<'static, [u8]>>;

type DomainBlockElements<CBlock> = (
    Vec<<CBlock as BlockT>::Extrinsic>,
    Randomness,
    MaybeNewRuntime,
);

/// Extracts the raw materials for building a new domain block from the primary block.
fn prepare_domain_block_elements<Block, CBlock, CClient>(
    domain_id: DomainId,
    consensus_client: &CClient,
    block_hash: CBlock::Hash,
) -> sp_blockchain::Result<DomainBlockElements<CBlock>>
where
    Block: BlockT,
    CBlock: BlockT,
    CClient: HeaderBackend<CBlock> + BlockBackend<CBlock> + ProvideRuntimeApi<CBlock> + Send + Sync,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>,
{
    let extrinsics = consensus_client.block_body(block_hash)?.ok_or_else(|| {
        sp_blockchain::Error::Backend(format!("BlockBody of {block_hash:?} unavailable"))
    })?;

    let header = consensus_client.header(block_hash)?.ok_or_else(|| {
        sp_blockchain::Error::Backend(format!("BlockHeader of {block_hash:?} unavailable"))
    })?;

    // TODO: Upgrade the domain runtime properly.
    // This works under the assumption that the consensus chain runtime upgrade triggers a domain
    // runtime upgrade, which is no longer valid.
    let maybe_new_runtime = if header
        .digest()
        .logs
        .iter()
        .any(|item| *item == DigestItem::RuntimeEnvironmentUpdated)
    {
        let new_domain_runtime = consensus_client
            .runtime_api()
            .domain_runtime_code(block_hash, domain_id)?
            .ok_or_else(|| {
                sp_blockchain::Error::Application(Box::from(format!(
                    "No new runtime code for {domain_id:?}"
                )))
            })?;

        Some(new_domain_runtime.into())
    } else {
        None
    };

    let shuffling_seed = consensus_client
        .runtime_api()
        .extrinsics_shuffling_seed(block_hash, header)?;

    Ok((extrinsics, shuffling_seed, maybe_new_runtime))
}

fn compile_own_domain_bundles<Block, CBlock>(
    bundles: OpaqueBundles<CBlock, NumberFor<Block>, Block::Hash>,
) -> Vec<Block::Extrinsic>
where
    Block: BlockT,
    CBlock: BlockT,
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
    let mut rng = ChaCha8Rng::from_seed(*shuffling_seed);

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

pub struct DomainBlockPreprocessor<Block, CBlock, CClient, RuntimeApi> {
    domain_id: DomainId,
    consensus_client: Arc<CClient>,
    runtime_api: RuntimeApi,
    _phantom_data: PhantomData<(Block, CBlock)>,
}

impl<Block, CBlock, CClient, RuntimeApi: Clone> Clone
    for DomainBlockPreprocessor<Block, CBlock, CClient, RuntimeApi>
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            consensus_client: self.consensus_client.clone(),
            runtime_api: self.runtime_api.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, CBlock, CClient, RuntimeApi> DomainBlockPreprocessor<Block, CBlock, CClient, RuntimeApi>
where
    Block: BlockT,
    CBlock: BlockT,
    CBlock::Hash: From<Block::Hash>,
    NumberFor<CBlock>: From<NumberFor<Block>>,
    RuntimeApi: SignerExtractor<Block>
        + StateRootExtractor<Block>
        + SetCodeConstructor<Block>
        + InherentExtrinsicConstructor<Block>,
    CClient: HeaderBackend<CBlock>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + Send
        + Sync
        + 'static,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>,
{
    pub fn new(
        domain_id: DomainId,
        consensus_client: Arc<CClient>,
        runtime_api: RuntimeApi,
    ) -> Self {
        Self {
            domain_id,
            consensus_client,
            runtime_api,
            _phantom_data: Default::default(),
        }
    }

    pub fn preprocess_consensus_block_for_verifier(
        &self,
        consensus_block_hash: CBlock::Hash,
    ) -> sp_blockchain::Result<Vec<Vec<u8>>> {
        // `domain_hash` is unused in `preprocess_primary_block` when using stateless runtime api.
        let domain_hash = Default::default();
        match self.preprocess_consensus_block(consensus_block_hash, domain_hash)? {
            Some(extrinsics) => Ok(extrinsics.into_iter().map(|ext| ext.encode()).collect()),
            None => Ok(Vec::new()),
        }
    }

    pub fn preprocess_consensus_block(
        &self,
        consensus_block_hash: CBlock::Hash,
        domain_hash: Block::Hash,
    ) -> sp_blockchain::Result<Option<Vec<Block::Extrinsic>>> {
        let (primary_extrinsics, shuffling_seed, maybe_new_runtime) =
            prepare_domain_block_elements::<Block, CBlock, _>(
                self.domain_id,
                &*self.consensus_client,
                consensus_block_hash,
            )?;

        let bundles = self
            .consensus_client
            .runtime_api()
            .extract_successful_bundles(consensus_block_hash, self.domain_id, primary_extrinsics)?;

        if bundles.is_empty() && maybe_new_runtime.is_none() {
            return Ok(None);
        }

        let extrinsics = compile_own_domain_bundles::<Block, CBlock>(bundles);

        let extrinsics_in_bundle = deduplicate_and_shuffle_extrinsics(
            domain_hash,
            &self.runtime_api,
            extrinsics,
            shuffling_seed,
        )
        .map(|exts| self.filter_invalid_xdm_extrinsics(domain_hash, exts))?;

        // Fetch inherent extrinsics
        let mut extrinsics = construct_inherent_extrinsics(
            &self.consensus_client,
            &self.runtime_api,
            consensus_block_hash,
            domain_hash,
        )?;

        extrinsics.extend(extrinsics_in_bundle);

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

        Ok(Some(extrinsics))
    }

    fn filter_invalid_xdm_extrinsics(
        &self,
        at: Block::Hash,
        exts: Vec<Block::Extrinsic>,
    ) -> Vec<Block::Extrinsic> {
        exts.into_iter()
            .filter(|ext| {
                match verify_xdm_with_consensus_client::<CClient, CBlock, Block, _>(
                    self.domain_id,
                    &self.consensus_client,
                    at,
                    &self.runtime_api,
                    ext,
                ) {
                    Ok(valid) => valid,
                    Err(err) => {
                        tracing::error!("failed to verify extrinsic: {err}",);
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
    use subspace_core_primitives::Randomness;

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

        let dummy_seed = Randomness::from(BlakeTwo256::hash_of(&[1u8; 64]).to_fixed_bytes());
        let shuffled_extrinsics = shuffle_extrinsics(extrinsics, dummy_seed);

        assert_eq!(
            shuffled_extrinsics,
            vec![100, 30, 10, 1, 11, 101, 31, 12, 102, 2]
        );
    }
}
