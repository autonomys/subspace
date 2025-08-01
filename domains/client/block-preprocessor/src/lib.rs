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
pub mod stateless_runtime;

use crate::inherents::is_runtime_upgraded;
use crate::stateless_runtime::StatelessRuntime;
use domain_runtime_primitives::opaque::AccountId;
use domain_runtime_primitives::{CheckExtrinsicsValidityError, opaque};
use parity_scale_codec::Encode;
use sc_client_api::{BlockBackend, backend};
use sc_executor::RuntimeVersionOf;
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::H256;
use sp_core::traits::{CodeExecutor, FetchRuntimeCode};
use sp_domains::bundle::{InboxedBundle, InvalidBundleType, OpaqueBundle, OpaqueBundles};
use sp_domains::core_api::DomainCoreApi;
use sp_domains::execution_receipt::ExecutionReceipt;
use sp_domains::extrinsics::deduplicate_and_shuffle_extrinsics;
use sp_domains::{DomainId, DomainsApi, ExtrinsicDigest, HeaderHashingFor, ReceiptValidity};
use sp_messenger::MessengerApi;
use sp_mmr_primitives::MmrApi;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, NumberFor};
use sp_state_machine::LayoutV1;
use sp_state_machine::backend::AsTrieBackend;
use sp_subspace_mmr::ConsensusChainMmrLeafProof;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::{Randomness, U256};
use subspace_runtime_primitives::{Balance, ExtrinsicFor};

type DomainBlockElements<CBlock> = (Vec<ExtrinsicFor<CBlock>>, Randomness);

/// A wrapper indicating a valid bundle contents, or an invalid bundle reason.
enum BundleValidity<Extrinsic> {
    /// A valid bundle contents with signer of each extrinsic.
    ValidWithSigner(Vec<(Option<opaque::AccountId>, Extrinsic)>),
    /// An invalid bundle reason.
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
    CClient::Api: DomainsApi<CBlock, Block::Header>,
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
    pub bundles: Vec<InboxedBundle<Block::Hash>>,
}

pub struct DomainBlockPreprocessor<Block, CBlock, Client, CClient, Exec, Backend, ReceiptValidator>
{
    domain_id: DomainId,
    client: Arc<Client>,
    consensus_client: Arc<CClient>,
    executor: Arc<Exec>,
    backend: Arc<Backend>,
    receipt_validator: ReceiptValidator,
    _phantom_data: PhantomData<(Block, CBlock)>,
}

impl<Block, CBlock, Client, CClient, Exec, Backend, ReceiptValidator: Clone> Clone
    for DomainBlockPreprocessor<Block, CBlock, Client, CClient, Exec, Backend, ReceiptValidator>
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            client: self.client.clone(),
            consensus_client: self.consensus_client.clone(),
            executor: self.executor.clone(),
            backend: self.backend.clone(),
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

impl<Block, CBlock, Client, CClient, Exec, Backend, ReceiptValidator>
    DomainBlockPreprocessor<Block, CBlock, Client, CClient, Exec, Backend, ReceiptValidator>
where
    Block: BlockT,
    Block::Hash: Into<H256>,
    CBlock: BlockT,
    CBlock::Hash: From<Block::Hash>,
    NumberFor<CBlock>: From<NumberFor<Block>>,
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block> + 'static,
    Client::Api: DomainCoreApi<Block> + MessengerApi<Block, NumberFor<CBlock>, CBlock::Hash>,
    CClient: HeaderBackend<CBlock>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + Send
        + Sync
        + 'static,
    CClient::Api: DomainsApi<CBlock, Block::Header>
        + MessengerApi<CBlock, NumberFor<CBlock>, CBlock::Hash>
        + MmrApi<CBlock, H256, NumberFor<CBlock>>,
    Backend: backend::Backend<Block>,
    Exec: CodeExecutor + RuntimeVersionOf,
    ReceiptValidator: ValidateReceipt<Block, CBlock>,
{
    pub fn new(
        domain_id: DomainId,
        client: Arc<Client>,
        consensus_client: Arc<CClient>,
        executor: Arc<Exec>,
        backend: Arc<Backend>,
        receipt_validator: ReceiptValidator,
    ) -> Self {
        Self {
            domain_id,
            client,
            consensus_client,
            executor,
            backend,
            receipt_validator,
            _phantom_data: Default::default(),
        }
    }

    pub fn preprocess_consensus_block(
        &self,
        consensus_block_hash: CBlock::Hash,
        parent_domain_block: (Block::Hash, NumberFor<Block>),
    ) -> sp_blockchain::Result<Option<PreprocessResult<Block>>> {
        let (primary_extrinsics, shuffling_seed) = prepare_domain_block_elements::<Block, CBlock, _>(
            &*self.consensus_client,
            consensus_block_hash,
        )?;

        let runtime_api = self.consensus_client.runtime_api();

        let bundles = runtime_api.extract_successful_bundles(
            consensus_block_hash,
            self.domain_id,
            primary_extrinsics,
        )?;

        if bundles.is_empty()
            && !is_runtime_upgraded::<_, _, Block>(
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

        let (inboxed_bundles, extrinsics) = self.compile_bundles_to_extrinsics(
            bundles,
            tx_range,
            parent_domain_block,
            consensus_block_hash,
        )?;

        let extrinsics =
            deduplicate_and_shuffle_extrinsics::<Block::Extrinsic>(extrinsics, shuffling_seed);

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
        bundles: OpaqueBundles<CBlock, Block::Header, Balance>,
        tx_range: U256,
        (parent_domain_hash, parent_domain_number): (Block::Hash, NumberFor<Block>),
        at_consensus_hash: CBlock::Hash,
    ) -> sp_blockchain::Result<(
        Vec<InboxedBundle<Block::Hash>>,
        Vec<(Option<AccountId>, Block::Extrinsic)>,
    )> {
        let mut inboxed_bundles = Vec::with_capacity(bundles.len());
        let mut valid_extrinsics = Vec::new();

        for bundle in bundles {
            // For the honest operator the validity of the extrinsic of the bundle is committed
            // to (or say verified against) the receipt that is submitted with the bundle, the
            // consensus runtime should only accept the bundle if the receipt is derived from
            // the parent domain block. If it is not then either there is a bug in the consensus
            // runtime (for validating the bundle) or in the domain client (for finding the parent
            // domain block).
            //
            // NOTE: The receipt's `domain_block_number` is verified by the consensus runtime while
            // the `domain_block_hash` is not (which is take care of by the fraud proof) so we can't
            // check the parent domain block hash here.
            if *bundle.receipt_domain_block_number() != parent_domain_number {
                return Err(sp_blockchain::Error::RuntimeApiError(
                    ApiError::Application(
                        format!(
                            "Unexpected bundle in consensus block: {at_consensus_hash:?}, something must be wrong"
                        )
                        .into(),
                    ),
                ));
            }

            let extrinsic_root = bundle.extrinsics_root();
            let bundle_validity = self.batch_check_bundle_validity(
                bundle,
                &tx_range,
                (parent_domain_hash, parent_domain_number),
                at_consensus_hash,
            )?;
            match bundle_validity {
                BundleValidity::ValidWithSigner(signer_and_extrinsics) => {
                    let bundle_digest: Vec<_> = signer_and_extrinsics
                        .iter()
                        .map(|(signer, tx)| {
                            (
                                signer.clone(),
                                ExtrinsicDigest::new::<LayoutV1<HeaderHashingFor<Block::Header>>>(
                                    tx.encode(),
                                ),
                            )
                        })
                        .collect();
                    inboxed_bundles.push(InboxedBundle::valid(
                        HeaderHashingFor::<Block::Header>::hash_of(&bundle_digest),
                        extrinsic_root,
                    ));
                    valid_extrinsics.extend(signer_and_extrinsics);
                }
                BundleValidity::Invalid(invalid_bundle_type) => {
                    inboxed_bundles
                        .push(InboxedBundle::invalid(invalid_bundle_type, extrinsic_root));
                }
            }
        }

        Ok((inboxed_bundles, valid_extrinsics))
    }

    fn stateless_runtime_api(
        &self,
        parent_domain_hash: Block::Hash,
    ) -> sp_blockchain::Result<StatelessRuntime<CBlock, Block, Exec>> {
        let state = self.backend.state_at(parent_domain_hash)?;
        let trie_backend = state.as_trie_backend();
        let state_runtime_code = sp_state_machine::backend::BackendRuntimeCode::new(trie_backend);
        let runtime_code = state_runtime_code
            .runtime_code()
            .map_err(sp_blockchain::Error::RuntimeCode)?
            .fetch_runtime_code()
            .ok_or(sp_blockchain::Error::RuntimeCode("missing runtime code"))?
            .into_owned();

        Ok(StatelessRuntime::<CBlock, Block, _>::new(
            self.executor.clone(),
            runtime_code.into(),
        ))
    }

    fn batch_check_bundle_validity(
        &self,
        bundle: OpaqueBundle<NumberFor<CBlock>, CBlock::Hash, Block::Header, Balance>,
        tx_range: &U256,
        (parent_domain_hash, parent_domain_number): (Block::Hash, NumberFor<Block>),
        at_consensus_hash: CBlock::Hash,
    ) -> sp_blockchain::Result<BundleValidity<Block::Extrinsic>> {
        let bundle_vrf_hash = U256::from_be_bytes(*bundle.proof_of_election().vrf_hash());
        let bundle_length = bundle.body_length();
        let bundle_estimated_weight = bundle.estimated_weight();
        let mut maybe_invalid_bundle_type = None;

        // Note: It is okay to use stateless here since all the bundle checks currently do not
        // require state. But of any checks in the future requires a state read that was part of the
        // genesis ex: `SelfChainId`, stateless runtime will panic.
        // So ideal to set the genesis storage as fraud proof already have access to that and would be
        // no different in terms of verification on both the sides
        let stateless_runtime_api = self.stateless_runtime_api(parent_domain_hash)?;
        let consensus_runtime_api = self.consensus_client.runtime_api();

        // Check the validity of extrinsic inside the bundle, the goal is trying to find the first
        // invalid tx and the first check it failed to pass, thus even an invalid tx that failed to
        // pass a given check is found we still continue the following check for other txs that before
        // it.
        //
        // NOTE: the checking order must follow `InvalidBundleType::checking_order`

        let mut extrinsics =
            stateless_runtime_api.decode_extrinsics_prefix(bundle.into_extrinsics())?;
        if extrinsics.len() != bundle_length {
            // If the length changed meaning there is undecodable tx at index `extrinsics.len()`
            maybe_invalid_bundle_type
                .replace(InvalidBundleType::UndecodableTx(extrinsics.len() as u32));
        }

        let signers = match stateless_runtime_api.extract_signer_if_all_within_tx_range(
            &extrinsics,
            &bundle_vrf_hash,
            tx_range,
        )? {
            Err(index) => {
                maybe_invalid_bundle_type.replace(InvalidBundleType::OutOfRangeTx(index));
                extrinsics.truncate(index as usize);

                // This will never used since there is an invalid tx
                Vec::default()
            }
            Ok(signers) => signers,
        };

        // Check if this extrinsic is an inherent extrinsic.
        // If so, this is an invalid bundle since these extrinsics should not be included in the
        // bundle. Extrinsic is always decodable due to the check above.
        if let Some(index) = stateless_runtime_api.find_first_inherent_extrinsic(&extrinsics)? {
            maybe_invalid_bundle_type.replace(InvalidBundleType::InherentExtrinsic(index));
            extrinsics.truncate(index as usize);
        }

        let batch_xdm_mmr_proof =
            stateless_runtime_api.batch_extract_native_xdm_mmr_proof(&extrinsics)?;
        for (index, xdm_mmr_proof) in batch_xdm_mmr_proof {
            let ConsensusChainMmrLeafProof {
                opaque_mmr_leaf,
                proof,
                ..
            } = xdm_mmr_proof;

            if consensus_runtime_api
                .verify_proof(at_consensus_hash, vec![opaque_mmr_leaf], proof)?
                .is_err()
            {
                maybe_invalid_bundle_type.replace(InvalidBundleType::InvalidXDM(index));
                extrinsics.truncate(index as usize);
                break;
            }
        }

        // Using `check_extrinsics_and_do_pre_dispatch` instead of `check_transaction_validity`
        // to maintain side-effect between tx in the storage buffer.
        if let Err(CheckExtrinsicsValidityError {
            extrinsic_index, ..
        }) = self
            .client
            .runtime_api()
            .check_extrinsics_and_do_pre_dispatch(
                parent_domain_hash,
                extrinsics.clone(),
                parent_domain_number,
                parent_domain_hash,
            )?
        {
            maybe_invalid_bundle_type.replace(InvalidBundleType::IllegalTx(extrinsic_index));
        }

        // If there is any invalid tx then return the error before checking the bundle weight,
        // which is a check of the whole bundle and should only perform when all tx are valid.
        if let Some(invalid_bundle_type) = maybe_invalid_bundle_type {
            return Ok(BundleValidity::Invalid(invalid_bundle_type));
        }

        if bundle_estimated_weight != stateless_runtime_api.extrinsics_weight(&extrinsics)? {
            return Ok(BundleValidity::Invalid(
                InvalidBundleType::InvalidBundleWeight,
            ));
        }

        let signer_and_extrinsics = signers.into_iter().zip(extrinsics).collect();
        Ok(BundleValidity::ValidWithSigner(signer_and_extrinsics))
    }
}

#[cfg(test)]
mod tests {
    use sp_domains::extrinsics::shuffle_extrinsics;
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
