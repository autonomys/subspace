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

pub mod inherents;
pub mod runtime_api;
pub mod runtime_api_full;
pub mod runtime_api_light;
pub mod xdm_verifier;

use crate::inherents::has_runtime_upgrade;
use crate::runtime_api::{SetCodeConstructor, SignerExtractor, StateRootExtractor};
use crate::xdm_verifier::is_valid_xdm;
use codec::{Decode, Encode};
use domain_runtime_primitives::opaque::AccountId;
use domain_runtime_primitives::DomainCoreApi;
use runtime_api::TimestampExtrinsicConstructor;
use sc_client_api::BlockBackend;
use sp_api::{HashT, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_domains::verification::deduplicate_and_shuffle_extrinsics;
use sp_domains::{
    DomainId, DomainsApi, ExecutionReceipt, InboxedBundle, InvalidBundleType, OpaqueBundle,
    OpaqueBundles, ReceiptValidity,
};
use sp_messenger::MessengerApi;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, NumberFor};
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::{Randomness, U256};
use subspace_runtime_primitives::Balance;

type DomainBlockElements<CBlock> = (Vec<<CBlock as BlockT>::Extrinsic>, Randomness);

enum BundleValidity<Extrinsic> {
    Valid(Vec<Extrinsic>),
    Invalid(InvalidBundleType),
}

/// Extracts the raw materials for building a new domain block from the primary block.
fn prepare_domain_block_elements<Block, CBlock, CClient>(
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

    let shuffling_seed = consensus_client
        .runtime_api()
        .extrinsics_shuffling_seed(block_hash)?;

    Ok((extrinsics, shuffling_seed))
}

pub struct PreprocessResult<Block: BlockT> {
    pub extrinsics: VecDeque<Block::Extrinsic>,
    pub bundles: Vec<InboxedBundle>,
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
        + TimestampExtrinsicConstructor<Block>,
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block> + 'static,
    Client::Api: DomainCoreApi<Block>,
    CClient: HeaderBackend<CBlock>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + Send
        + Sync
        + 'static,
    CClient::Api:
        DomainsApi<CBlock, NumberFor<Block>, Block::Hash> + MessengerApi<CBlock, NumberFor<CBlock>>,
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
        let (primary_extrinsics, shuffling_seed) = prepare_domain_block_elements::<Block, CBlock, _>(
            &*self.consensus_client,
            consensus_block_hash,
        )?;

        let bundles = self
            .consensus_client
            .runtime_api()
            .extract_successful_bundles(consensus_block_hash, self.domain_id, primary_extrinsics)?;

        if bundles.is_empty()
            && !has_runtime_upgrade::<_, _, Block>(
                &self.consensus_client,
                consensus_block_hash,
                self.domain_id,
            )?
        {
            return Ok(None);
        }

        let tx_range = self
            .consensus_client
            .runtime_api()
            .domain_tx_range(consensus_block_hash, self.domain_id)?;

        let (inboxed_bundles, extrinsics) =
            self.compile_bundles_to_extrinsics(bundles, tx_range, domain_hash)?;

        let extrinsics = deduplicate_and_shuffle_extrinsics::<<Block as BlockT>::Extrinsic>(
            extrinsics,
            shuffling_seed,
        );

        Ok(Some(PreprocessResult {
            extrinsics,
            bundles: inboxed_bundles,
        }))
    }

    /// Filter out the invalid bundles first and then convert the remaining valid ones to
    /// a list of extrinsics.
    #[allow(clippy::type_complexity)]
    fn compile_bundles_to_extrinsics(
        &self,
        bundles: OpaqueBundles<CBlock, NumberFor<Block>, Block::Hash, Balance>,
        tx_range: U256,
        at: Block::Hash,
    ) -> sp_blockchain::Result<(
        Vec<InboxedBundle>,
        Vec<(Option<AccountId>, Block::Extrinsic)>,
    )> {
        let mut inboxed_bundles = Vec::with_capacity(bundles.len());
        let mut valid_extrinsics = Vec::new();

        for bundle in bundles {
            let extrinsic_root = bundle.extrinsics_root();
            match self.check_bundle_validity(&bundle, &tx_range, at)? {
                BundleValidity::Valid(extrinsics) => {
                    let extrinsics: Vec<_> = match self.runtime_api.extract_signer(at, extrinsics) {
                        Ok(res) => res,
                        Err(e) => {
                            tracing::error!(error = ?e, "Error at calling runtime api: extract_signer");
                            return Err(e.into());
                        }
                    };
                    let bundle_digest: Vec<_> = extrinsics
                        .iter()
                        .map(|(signer, tx)| (signer.clone(), BlakeTwo256::hash_of(tx)))
                        .collect();
                    inboxed_bundles.push(InboxedBundle::valid(
                        BlakeTwo256::hash_of(&bundle_digest),
                        extrinsic_root,
                    ));
                    valid_extrinsics.extend(extrinsics);
                }
                BundleValidity::Invalid(invalid_bundle_type) => {
                    inboxed_bundles
                        .push(InboxedBundle::invalid(invalid_bundle_type, extrinsic_root));
                }
            }
        }

        Ok((inboxed_bundles, valid_extrinsics))
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
        let bundle_vrf_hash =
            U256::from_be_bytes(bundle.sealed_header.header.proof_of_election.vrf_hash());

        let mut extrinsics = Vec::with_capacity(bundle.extrinsics.len());

        let domain_block_number = self
            .client
            .number(at)?
            .ok_or(sp_blockchain::Error::MissingHeader(at.to_string()))?;

        // Check the validity of each extrinsic
        //
        // NOTE: for each extrinsic the checking order must follow `InvalidBundleType::checking_order`
        let runtime_api = self.client.runtime_api();
        for (index, opaque_extrinsic) in bundle.extrinsics.iter().enumerate() {
            let Ok(extrinsic) =
                <<Block as BlockT>::Extrinsic>::decode(&mut opaque_extrinsic.encode().as_slice())
            else {
                tracing::error!(
                    ?opaque_extrinsic,
                    "Undecodable extrinsic in bundle({})",
                    bundle.hash()
                );
                return Ok(BundleValidity::Invalid(InvalidBundleType::UndecodableTx(
                    index as u32,
                )));
            };

            let is_within_tx_range =
                runtime_api.is_within_tx_range(at, &extrinsic, &bundle_vrf_hash, tx_range)?;

            if !is_within_tx_range {
                // TODO: Generate a fraud proof for this invalid bundle
                return Ok(BundleValidity::Invalid(InvalidBundleType::OutOfRangeTx(
                    index as u32,
                )));
            }

            let is_legal_tx = self
                .client
                .runtime_api()
                .check_transaction_validity(at, &extrinsic, domain_block_number, at)?
                .is_ok();

            if !is_legal_tx {
                // TODO: Generate a fraud proof for this invalid bundle
                return Ok(BundleValidity::Invalid(InvalidBundleType::IllegalTx(
                    index as u32,
                )));
            }

            // Check if this extrinsic is an inherent extrinsic.
            // If so, this is an invalid bundle since these extrinsics should not be included in the
            // bundle. Extrinsic is always decodable due to the check above.
            if runtime_api.is_inherent_extrinsic(at, &extrinsic)? {
                return Ok(BundleValidity::Invalid(
                    InvalidBundleType::InherentExtrinsic(index as u32),
                ));
            }

            // TODO: the behavior is changed, as before invalid XDM will be dropped silently,
            // and the other extrinsic of the bundle will be continue processed, now the whole
            // bundle is considered as invalid and excluded from further processing.
            if !is_valid_xdm::<CClient, CBlock, Block, _>(
                &self.consensus_client,
                at,
                &self.runtime_api,
                &extrinsic,
            )? {
                // TODO: Generate a fraud proof for this invalid bundle
                return Ok(BundleValidity::Invalid(InvalidBundleType::InvalidXDM(
                    index as u32,
                )));
            }

            extrinsics.push(extrinsic);
        }

        Ok(BundleValidity::Valid(extrinsics))
    }
}

#[cfg(test)]
mod tests {
    use sp_domains::verification::shuffle_extrinsics;
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
