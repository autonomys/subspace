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
use crate::xdm_verifier::verify_xdm;
use codec::{Decode, Encode};
use domain_runtime_primitives::opaque::AccountId;
use domain_runtime_primitives::DomainCoreApi;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use runtime_api::InherentExtrinsicConstructor;
use sc_client_api::BlockBackend;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_domains::{
    BundleValidity, DomainId, DomainsApi, DomainsDigestItem, ExecutionReceipt, ExtrinsicsRoot,
    InvalidBundle, InvalidBundleType, OpaqueBundle, OpaqueBundles, ReceiptValidity,
};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};
use std::borrow::Cow;
use std::collections::{BTreeMap, VecDeque};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::{Randomness, U256};
use subspace_runtime_primitives::Balance;

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

    let runtime_id = consensus_client
        .runtime_api()
        .runtime_id(block_hash, domain_id)?
        .ok_or_else(|| {
            sp_blockchain::Error::Application(Box::from(format!(
                "Runtime id not found for {domain_id:?}"
            )))
        })?;

    let maybe_new_runtime = if header
        .digest()
        .logs
        .iter()
        .filter_map(|log| log.as_domain_runtime_upgrade())
        .any(|upgraded_runtime_id| upgraded_runtime_id == runtime_id)
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

pub struct PreprocessResult<Block: BlockT> {
    pub extrinsics: Vec<Block::Extrinsic>,
    pub extrinsics_roots: Vec<ExtrinsicsRoot>,
    pub invalid_bundles: Vec<InvalidBundle>,
}

pub struct DomainBlockPreprocessor<Block, CBlock, Client, CClient, RuntimeApi, ReceiptValidator> {
    domain_id: DomainId,
    client: Arc<Client>,
    consensus_client: Arc<CClient>,
    runtime_api: RuntimeApi,
    receipt_validator: ReceiptValidator,
    _phantom_data: PhantomData<(Block, CBlock)>,
}

impl<Block, CBlock, Client, CClient, RuntimeApi: Clone, ReceiptValidator: Clone> Clone
    for DomainBlockPreprocessor<Block, CBlock, Client, CClient, RuntimeApi, ReceiptValidator>
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            client: self.client.clone(),
            consensus_client: self.consensus_client.clone(),
            runtime_api: self.runtime_api.clone(),
            receipt_validator: self.receipt_validator.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

pub trait ValidateReceipt<Block, CBlock>
where
    Block: BlockT,
    CBlock: BlockT,
{
    fn validate_receipt(
        &self,
        receipt: &ExecutionReceipt<
            NumberFor<CBlock>,
            CBlock::Hash,
            NumberFor<Block>,
            Block::Hash,
            Balance,
        >,
    ) -> sp_blockchain::Result<ReceiptValidity>;
}

impl<Block, CBlock, Client, CClient, RuntimeApi, ReceiptValidator>
    DomainBlockPreprocessor<Block, CBlock, Client, CClient, RuntimeApi, ReceiptValidator>
where
    Block: BlockT,
    CBlock: BlockT,
    CBlock::Hash: From<Block::Hash>,
    NumberFor<CBlock>: From<NumberFor<Block>>,
    RuntimeApi: SignerExtractor<Block>
        + StateRootExtractor<Block>
        + SetCodeConstructor<Block>
        + InherentExtrinsicConstructor<Block>,
    Client: ProvideRuntimeApi<Block> + 'static,
    Client::Api: DomainCoreApi<Block>,
    CClient: HeaderBackend<CBlock>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + Send
        + Sync
        + 'static,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>,
    ReceiptValidator: ValidateReceipt<Block, CBlock>,
{
    pub fn new(
        domain_id: DomainId,
        client: Arc<Client>,
        consensus_client: Arc<CClient>,
        runtime_api: RuntimeApi,
        receipt_validator: ReceiptValidator,
    ) -> Self {
        Self {
            domain_id,
            client,
            consensus_client,
            runtime_api,
            receipt_validator,
            _phantom_data: Default::default(),
        }
    }

    pub fn preprocess_consensus_block(
        &self,
        consensus_block_hash: CBlock::Hash,
        domain_hash: Block::Hash,
    ) -> sp_blockchain::Result<Option<PreprocessResult<Block>>> {
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

        let extrinsics_roots = bundles
            .iter()
            .map(|bundle| bundle.extrinsics_root())
            .collect();

        let tx_range = self
            .consensus_client
            .runtime_api()
            .domain_tx_range(consensus_block_hash, self.domain_id)?;

        let (invalid_bundles, extrinsics) =
            self.compile_bundles_to_extrinsics(bundles, tx_range, domain_hash)?;

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
        Ok(Some(PreprocessResult {
            extrinsics,
            extrinsics_roots,
            invalid_bundles,
        }))
    }

    /// Filter out the invalid bundles first and then convert the remaining valid ones to
    /// a list of extrinsics.
    fn compile_bundles_to_extrinsics(
        &self,
        bundles: OpaqueBundles<CBlock, NumberFor<Block>, Block::Hash, Balance>,
        tx_range: U256,
        at: Block::Hash,
    ) -> sp_blockchain::Result<(Vec<InvalidBundle>, Vec<Block::Extrinsic>)> {
        let mut invalid_bundles = Vec::with_capacity(bundles.len());
        let mut valid_extrinsics = Vec::new();

        for (index, bundle) in bundles.into_iter().enumerate() {
            match self.check_bundle_validity(&bundle, &tx_range, at)? {
                BundleValidity::Valid(extrinsics) => valid_extrinsics.extend(extrinsics),
                BundleValidity::Invalid(invalid_bundle_type) => {
                    invalid_bundles.push(InvalidBundle {
                        bundle_index: index as u32,
                        invalid_bundle_type,
                    });
                }
            }
        }

        Ok((invalid_bundles, valid_extrinsics))
    }

    fn check_bundle_validity(
        &self,
        bundle: &OpaqueBundle<
            NumberFor<CBlock>,
            CBlock::Hash,
            NumberFor<Block>,
            Block::Hash,
            Balance,
        >,
        tx_range: &U256,
        at: Block::Hash,
    ) -> sp_blockchain::Result<BundleValidity<Block::Extrinsic>> {
        // Bundles with incorrect ER are considered invalid.
        if let ReceiptValidity::Invalid(invalid_receipt) =
            self.receipt_validator.validate_receipt(bundle.receipt())?
        {
            return Ok(BundleValidity::Invalid(InvalidBundleType::InvalidReceipt(
                invalid_receipt,
            )));
        }

        let bundle_vrf_hash =
            U256::from_be_bytes(bundle.sealed_header.header.proof_of_election.vrf_hash());

        let mut extrinsics = Vec::with_capacity(bundle.extrinsics.len());

        for opaque_extrinsic in &bundle.extrinsics {
            let Ok(extrinsic) =
                <<Block as BlockT>::Extrinsic>::decode(&mut opaque_extrinsic.encode().as_slice())
            else {
                tracing::error!(
                    ?opaque_extrinsic,
                    "Undecodable extrinsic in bundle({})",
                    bundle.hash()
                );
                return Ok(BundleValidity::Invalid(InvalidBundleType::UndecodableTx));
            };

            let is_within_tx_range = self.client.runtime_api().is_within_tx_range(
                at,
                &extrinsic,
                &bundle_vrf_hash,
                tx_range,
            )?;

            if !is_within_tx_range {
                // TODO: Generate a fraud proof for this invalid bundle
                return Ok(BundleValidity::Invalid(InvalidBundleType::OutOfRangeTx));
            }

            // TODO: the `check_transaction_validity` is unimplemented
            let is_legal_tx = self
                .client
                .runtime_api()
                .check_transaction_validity(at, &extrinsic, at)?
                .is_ok();

            if !is_legal_tx {
                // TODO: Generate a fraud proof for this invalid bundle
                return Ok(BundleValidity::Invalid(InvalidBundleType::IllegalTx));
            }

            extrinsics.push(extrinsic);
        }

        Ok(BundleValidity::Valid(extrinsics))
    }

    fn filter_invalid_xdm_extrinsics(
        &self,
        at: Block::Hash,
        exts: Vec<Block::Extrinsic>,
    ) -> Vec<Block::Extrinsic> {
        exts.into_iter()
            .filter(|ext| {
                match verify_xdm::<CClient, CBlock, Block, _>(
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
