use crate::domain_block_processor::{
    DomainBlockProcessor, PendingConsensusBlocks, ReceiptsChecker,
};
use crate::{DomainParentChain, ExecutionReceiptFor};
use domain_block_preprocessor::runtime_api_full::RuntimeApiFull;
use domain_block_preprocessor::DomainBlockPreprocessor;
use domain_runtime_primitives::{DomainCoreApi, InherentExtrinsicApi};
use sc_client_api::{AuxStore, BlockBackend, Finalizer, ProofProvider};
use sc_consensus::{BlockImport, BlockImportParams, ForkChoiceStrategy, StateAction};
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_consensus::BlockOrigin;
use sp_core::traits::CodeExecutor;
use sp_domain_digests::AsPredigest;
use sp_domains::fraud_proof::{
    InvalidBundlesFraudProof, MissingInvalidBundleEntryFraudProof,
    ValidAsInvalidBundleEntryFraudProof,
};
use sp_domains::{DomainId, DomainsApi, InvalidReceipt, ReceiptValidity};
use sp_keystore::KeystorePtr;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, Zero};
use sp_runtime::{Digest, DigestItem};
use std::cmp::Ordering;
use std::marker::PhantomData;
use std::sync::Arc;

type DomainReceiptsChecker<Block, CBlock, Client, CClient, Backend, E> = ReceiptsChecker<
    Block,
    Client,
    CBlock,
    CClient,
    Backend,
    E,
    DomainParentChain<Block, CBlock, CClient>,
    CBlock,
>;

type DomainBlockPreProcessor<Block, CBlock, Client, CClient> = DomainBlockPreprocessor<
    Block,
    CBlock,
    Client,
    CClient,
    RuntimeApiFull<Client>,
    ReceiptValidator<Client, Block, CBlock>,
>;

pub(crate) struct BundleProcessor<Block, CBlock, Client, CClient, Backend, E, BI>
where
    Block: BlockT,
    CBlock: BlockT,
{
    domain_id: DomainId,
    consensus_client: Arc<CClient>,
    client: Arc<Client>,
    backend: Arc<Backend>,
    keystore: KeystorePtr,
    domain_receipts_checker: DomainReceiptsChecker<Block, CBlock, Client, CClient, Backend, E>,
    domain_block_preprocessor: DomainBlockPreProcessor<Block, CBlock, Client, CClient>,
    domain_block_processor: DomainBlockProcessor<Block, CBlock, Client, CClient, Backend, BI>,
}

impl<Block, CBlock, Client, CClient, Backend, E, BI> Clone
    for BundleProcessor<Block, CBlock, Client, CClient, Backend, E, BI>
where
    Block: BlockT,
    CBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            consensus_client: self.consensus_client.clone(),
            client: self.client.clone(),
            backend: self.backend.clone(),
            keystore: self.keystore.clone(),
            domain_receipts_checker: self.domain_receipts_checker.clone(),
            domain_block_preprocessor: self.domain_block_preprocessor.clone(),
            domain_block_processor: self.domain_block_processor.clone(),
        }
    }
}

// TODO: Remove PhantomData once fraud proof generator and parent chain are added
struct ReceiptValidator<Client, Block, CBlock> {
    domain_id: DomainId,
    client: Arc<Client>,
    _phantom_block: PhantomData<Block>,
    _phantom_cblock: PhantomData<CBlock>,
}

impl<Client, Block, CBlock> Clone for ReceiptValidator<Client, Block, CBlock> {
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            client: self.client.clone(),
            _phantom_block: self._phantom_block,
            _phantom_cblock: self._phantom_cblock,
        }
    }
}

impl<Client, Block, CBlock> ReceiptValidator<Client, Block, CBlock> {
    pub fn new(domain_id: DomainId, client: Arc<Client>) -> Self {
        Self {
            domain_id,
            client,
            _phantom_block: PhantomData,
            _phantom_cblock: PhantomData,
        }
    }
}

/// Verifies invalid_bundle field in the ER and generates fraud proof in case the field
/// is incorrect. Fraud proof refers to the first mismatch.
/// CONTRACT: It will return None if the field is valid, otherwise it will return `Some` with fraud proof
/// pointing to first mismatch in invalid bundles array.
pub fn verify_and_generate_fraud_proof_for_invalid_bundles<Block, CBlock>(
    domain_id: DomainId,
    local_receipt: &ExecutionReceiptFor<Block, CBlock>,
    external_receipt: &ExecutionReceiptFor<Block, CBlock>,
) -> Option<InvalidBundlesFraudProof>
where
    Block: BlockT,
    CBlock: BlockT,
{
    if local_receipt.invalid_bundles == external_receipt.invalid_bundles {
        return None;
    }
    for (local_invalid_bundle, external_invalid_bundle) in local_receipt
        .invalid_bundles
        .iter()
        .zip(external_receipt.invalid_bundles.iter())
    {
        if local_invalid_bundle != external_invalid_bundle {
            if local_invalid_bundle.invalid_bundle_type
                != external_invalid_bundle.invalid_bundle_type
            {
                // Missing invalid bundle entry fraud proof can work for invalid bundle type mismatch
                // as the proof can prove that particular bundle is invalid as well as type of invalidation.
                return Some(InvalidBundlesFraudProof::MissingInvalidBundleEntry(
                    MissingInvalidBundleEntryFraudProof::new(
                        domain_id,
                        local_invalid_bundle.bundle_index,
                    ),
                ));
            }
            // FIXME: we need to add a check to the consensus chain runtime to ensure for all the ER included in the consensus block
            // the `bundle_index` field of `ER.invalid_bundles` must be strictly increasing
            match local_invalid_bundle
                .bundle_index
                .cmp(&external_invalid_bundle.bundle_index)
            {
                Ordering::Greater => {
                    return Some(InvalidBundlesFraudProof::ValidAsInvalid(
                        ValidAsInvalidBundleEntryFraudProof::new(
                            domain_id,
                            external_invalid_bundle.bundle_index,
                        ),
                    ));
                }
                Ordering::Less => {
                    return Some(InvalidBundlesFraudProof::MissingInvalidBundleEntry(
                        MissingInvalidBundleEntryFraudProof::new(
                            domain_id,
                            local_invalid_bundle.bundle_index,
                        ),
                    ));
                }
                Ordering::Equal => unreachable!("checked in this block's if condition; qed"),
            }
        }
    }
    match local_receipt
        .invalid_bundles
        .len()
        .cmp(&external_receipt.invalid_bundles.len())
    {
        Ordering::Greater => {
            let invalid_bundle =
                &local_receipt.invalid_bundles[external_receipt.invalid_bundles.len()];
            Some(InvalidBundlesFraudProof::MissingInvalidBundleEntry(
                MissingInvalidBundleEntryFraudProof::new(domain_id, invalid_bundle.bundle_index),
            ))
        }
        Ordering::Less => {
            let valid_bundle =
                &external_receipt.invalid_bundles[local_receipt.invalid_bundles.len()];
            Some(InvalidBundlesFraudProof::ValidAsInvalid(
                ValidAsInvalidBundleEntryFraudProof::new(domain_id, valid_bundle.bundle_index),
            ))
        }
        Ordering::Equal => unreachable!("already checked for vector equality and since the zipped elements are equal, length cannot be equal; qed"),
    }
}

impl<Client, Block, CBlock> ReceiptValidator<Client, Block, CBlock>
where
    Block: BlockT,
    CBlock: BlockT,
    Client:
        HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block> + 'static,
    Client::Api: sp_block_builder::BlockBuilder<Block> + sp_api::ApiExt<Block>,
{
    pub fn check_receipt_validity(
        &self,
        local_receipt: &ExecutionReceiptFor<Block, CBlock>,
        external_receipt: &ExecutionReceiptFor<Block, CBlock>,
    ) -> bool {
        let maybe_invalid_bundles_fraud_proof = verify_and_generate_fraud_proof_for_invalid_bundles::<
            Block,
            CBlock,
        >(
            self.domain_id, local_receipt, external_receipt
        );
        if let Some(_invalid_bundles_fraud_proof) = maybe_invalid_bundles_fraud_proof {
            // TODO: Submit the fraud proof
            return false;
        }

        true
    }
}

impl<Client, Block, CBlock> domain_block_preprocessor::ValidateReceipt<Block, CBlock>
    for ReceiptValidator<Client, Block, CBlock>
where
    Block: BlockT,
    CBlock: BlockT,
    Client:
        HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block> + 'static,
    Client::Api: sp_block_builder::BlockBuilder<Block> + sp_api::ApiExt<Block>,
{
    fn validate_receipt(
        &self,
        receipt: &ExecutionReceiptFor<Block, CBlock>,
    ) -> sp_blockchain::Result<ReceiptValidity> {
        // Skip genesis receipt as it has been already verified by the consensus chain.
        if receipt.domain_block_number.is_zero() {
            return Ok(ReceiptValidity::Valid);
        }

        let consensus_block_hash = receipt.consensus_block_hash;
        let local_receipt = crate::aux_schema::load_execution_receipt::<_, Block, CBlock>(
            &*self.client,
            consensus_block_hash,
        )?
        .ok_or_else(|| {
            sp_blockchain::Error::Backend(format!(
                "Receipt for consensus block {consensus_block_hash} not found"
            ))
        })?;

        if !self.check_receipt_validity(&local_receipt, receipt) {
            return Ok(ReceiptValidity::Invalid(InvalidReceipt::InvalidBundles));
        }

        Ok(ReceiptValidity::Valid)
    }
}

impl<Block, CBlock, Client, CClient, Backend, E, BI>
    BundleProcessor<Block, CBlock, Client, CClient, Backend, E, BI>
where
    Block: BlockT,
    CBlock: BlockT,
    NumberFor<CBlock>: From<NumberFor<Block>> + Into<NumberFor<Block>>,
    CBlock::Hash: From<Block::Hash>,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + Finalizer<Block, Backend>
        + 'static,
    Client::Api: DomainCoreApi<Block>
        + MessengerApi<Block, NumberFor<Block>>
        + InherentExtrinsicApi<Block>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block>,
    for<'b> &'b BI: BlockImport<Block, Error = sp_consensus::Error>,
    CClient: HeaderBackend<CBlock>
        + HeaderMetadata<CBlock, Error = sp_blockchain::Error>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + 'static,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>
        + MessengerApi<CBlock, NumberFor<CBlock>>
        + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    E: CodeExecutor,
{
    pub(crate) fn new(
        domain_id: DomainId,
        consensus_client: Arc<CClient>,
        client: Arc<Client>,
        backend: Arc<Backend>,
        keystore: KeystorePtr,
        domain_receipts_checker: DomainReceiptsChecker<Block, CBlock, Client, CClient, Backend, E>,
        domain_block_processor: DomainBlockProcessor<Block, CBlock, Client, CClient, Backend, BI>,
    ) -> Self {
        let domain_block_preprocessor = DomainBlockPreprocessor::new(
            domain_id,
            client.clone(),
            consensus_client.clone(),
            RuntimeApiFull::new(client.clone()),
            ReceiptValidator::new(domain_id, client.clone()),
        );
        Self {
            domain_id,
            consensus_client,
            client,
            backend,
            keystore,
            domain_receipts_checker,
            domain_block_preprocessor,
            domain_block_processor,
        }
    }

    // TODO: Handle the returned error properly, ref to https://github.com/subspace/subspace/pull/695#discussion_r926721185
    pub(crate) async fn process_bundles(
        self,
        consensus_block_info: (CBlock::Hash, NumberFor<CBlock>, bool),
    ) -> sp_blockchain::Result<()> {
        let (consensus_block_hash, consensus_block_number, is_new_best) = consensus_block_info;

        tracing::debug!(
            "Processing consensus block #{consensus_block_number},{consensus_block_hash}"
        );

        let maybe_pending_consensus_blocks = self
            .domain_block_processor
            .pending_imported_consensus_blocks(consensus_block_hash, consensus_block_number)?;

        if let Some(PendingConsensusBlocks {
            initial_parent,
            consensus_imports,
        }) = maybe_pending_consensus_blocks
        {
            tracing::trace!(
                ?initial_parent,
                ?consensus_imports,
                "Pending consensus blocks to process"
            );

            let mut domain_parent = initial_parent;

            for consensus_info in consensus_imports {
                if let Some(next_domain_parent) = self
                    .process_bundles_at((consensus_info.hash, consensus_info.number), domain_parent)
                    .await?
                {
                    domain_parent = next_domain_parent;
                }
            }

            // The domain branch driving from the best consensus branch should also be the best domain branch even
            // if it is no the longest domain branch. Thus re-import the tip of the best domain branch to make it
            // the new best block if it isn't.
            //
            // Note: this may cause the best domain fork switch to a shorter fork or in some case the best domain
            // block become the ancestor block of the current best block.
            let domain_tip = domain_parent.0;
            if is_new_best && self.client.info().best_hash != domain_tip {
                let header = self.client.header(domain_tip)?.ok_or_else(|| {
                    sp_blockchain::Error::Backend(format!("Header for #{:?} not found", domain_tip))
                })?;
                let block_import_params = {
                    let mut import_block = BlockImportParams::new(BlockOrigin::Own, header);
                    import_block.import_existing = true;
                    import_block.fork_choice = Some(ForkChoiceStrategy::Custom(true));
                    import_block.state_action = StateAction::Skip;
                    import_block
                };
                self.domain_block_processor
                    .import_domain_block(block_import_params)
                    .await?;
                assert_eq!(domain_tip, self.client.info().best_hash);
            }
        }

        Ok(())
    }

    async fn process_bundles_at(
        &self,
        consensus_block_info: (CBlock::Hash, NumberFor<CBlock>),
        parent_info: (Block::Hash, NumberFor<Block>),
    ) -> sp_blockchain::Result<Option<(Block::Hash, NumberFor<Block>)>> {
        let (consensus_block_hash, consensus_block_number) = consensus_block_info;
        let (parent_hash, parent_number) = parent_info;

        tracing::debug!(
            "Building a new domain block from consensus block #{consensus_block_number},{consensus_block_hash} \
            on top of parent block #{parent_number},{parent_hash}"
        );

        let head_receipt_number = self
            .consensus_client
            .runtime_api()
            .head_receipt_number(consensus_block_hash, self.domain_id)?
            .into();

        let Some(preprocess_result) = self
            .domain_block_preprocessor
            .preprocess_consensus_block(consensus_block_hash, parent_hash)?
        else {
            tracing::debug!(
                "Skip building new domain block, no bundles and runtime upgrade for this domain \
                    in consensus block #{consensus_block_number:?},{consensus_block_hash}"
            );
            self.domain_block_processor.on_consensus_block_processed(
                consensus_block_hash,
                None,
                head_receipt_number,
            )?;

            return Ok(None);
        };

        let digest = Digest {
            logs: vec![DigestItem::consensus_block_info(consensus_block_hash)],
        };

        let domain_block_result = self
            .domain_block_processor
            .process_domain_block(
                (consensus_block_hash, consensus_block_number),
                (parent_hash, parent_number),
                preprocess_result,
                digest,
            )
            .await?;

        assert!(
            domain_block_result.header_number > head_receipt_number,
            "Domain chain number must larger than the head number of the receipt chain \
            (which is maintained on the consensus chain) by at least 1"
        );

        let built_block_info = (
            domain_block_result.header_hash,
            domain_block_result.header_number,
        );

        self.domain_block_processor.on_consensus_block_processed(
            consensus_block_hash,
            Some(domain_block_result),
            head_receipt_number,
        )?;

        // TODO: Remove as ReceiptsChecker has been superseded by ReceiptValidator in block-preprocessor.
        self.domain_receipts_checker
            .check_state_transition(consensus_block_hash)?;

        self.domain_receipts_checker
            .submit_fraud_proof(consensus_block_hash)?;

        Ok(Some(built_block_info))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain_test_service::evm_domain_test_runtime::Block;
    use sp_core::sp_std;
    use sp_domains::fraud_proof::InvalidBundlesFraudProof::{
        MissingInvalidBundleEntry, ValidAsInvalid,
    };
    use sp_domains::{ExecutionReceipt, InvalidBundle, InvalidBundleType};
    use subspace_test_runtime::Block as CBlock;

    fn create_test_execution_receipt(
        invalid_bundles: Vec<InvalidBundle>,
    ) -> ExecutionReceiptFor<Block, CBlock>
    where
        Block: BlockT,
        CBlock: BlockT,
    {
        ExecutionReceipt {
            domain_block_number: Zero::zero(),
            domain_block_hash: Default::default(),
            domain_block_extrinsic_root: Default::default(),
            parent_domain_block_receipt_hash: Default::default(),
            consensus_block_hash: Default::default(),
            consensus_block_number: Zero::zero(),
            invalid_bundles,
            block_extrinsics_roots: sp_std::vec![],
            final_state_root: Default::default(),
            execution_trace: sp_std::vec![],
            execution_trace_root: Default::default(),
            total_rewards: Zero::zero(),
            valid_bundles: vec![],
        }
    }

    #[test]
    fn invalid_bundles_fraud_proof_detection() {
        // If empty invalid receipt field on both should result in no fraud proof
        assert_eq!(
            verify_and_generate_fraud_proof_for_invalid_bundles::<Block, CBlock>(
                DomainId::new(1),
                &create_test_execution_receipt(vec![]),
                &create_test_execution_receipt(vec![]),
            ),
            None
        );

        assert_eq!(
            verify_and_generate_fraud_proof_for_invalid_bundles::<Block, CBlock>(
                DomainId::new(1),
                &create_test_execution_receipt(vec![InvalidBundle {
                    bundle_index: 3,
                    invalid_bundle_type: InvalidBundleType::UndecodableTx
                }]),
                &create_test_execution_receipt(vec![InvalidBundle {
                    bundle_index: 3,
                    invalid_bundle_type: InvalidBundleType::UndecodableTx
                }]),
            ),
            None
        );

        // Mismatch in invalid bundle type
        assert_eq!(
            verify_and_generate_fraud_proof_for_invalid_bundles::<Block, CBlock>(
                DomainId::new(1),
                &create_test_execution_receipt(vec![
                    InvalidBundle {
                        bundle_index: 3,
                        invalid_bundle_type: InvalidBundleType::UndecodableTx
                    },
                    InvalidBundle {
                        bundle_index: 4,
                        invalid_bundle_type: InvalidBundleType::UndecodableTx
                    }
                ]),
                &create_test_execution_receipt(vec![
                    InvalidBundle {
                        bundle_index: 3,
                        invalid_bundle_type: InvalidBundleType::UndecodableTx
                    },
                    InvalidBundle {
                        bundle_index: 4,
                        invalid_bundle_type: InvalidBundleType::IllegalTx
                    }
                ]),
            ),
            Some(MissingInvalidBundleEntry(
                MissingInvalidBundleEntryFraudProof::new(DomainId::new(1), 4)
            ))
        );

        // Only first mismatch is detected
        assert_eq!(
            verify_and_generate_fraud_proof_for_invalid_bundles::<Block, CBlock>(
                DomainId::new(2),
                &create_test_execution_receipt(vec![
                    InvalidBundle {
                        bundle_index: 1,
                        invalid_bundle_type: InvalidBundleType::UndecodableTx
                    },
                    InvalidBundle {
                        bundle_index: 4,
                        invalid_bundle_type: InvalidBundleType::UndecodableTx
                    }
                ]),
                &create_test_execution_receipt(vec![
                    InvalidBundle {
                        bundle_index: 3,
                        invalid_bundle_type: InvalidBundleType::UndecodableTx
                    },
                    InvalidBundle {
                        bundle_index: 4,
                        invalid_bundle_type: InvalidBundleType::IllegalTx
                    }
                ]),
            ),
            Some(MissingInvalidBundleEntry(
                MissingInvalidBundleEntryFraudProof::new(DomainId::new(2), 1)
            ))
        );

        // Valid bundle as invalid
        assert_eq!(
            verify_and_generate_fraud_proof_for_invalid_bundles::<Block, CBlock>(
                DomainId::new(2),
                &create_test_execution_receipt(vec![
                    InvalidBundle {
                        bundle_index: 5,
                        invalid_bundle_type: InvalidBundleType::UndecodableTx
                    },
                    InvalidBundle {
                        bundle_index: 6,
                        invalid_bundle_type: InvalidBundleType::UndecodableTx
                    }
                ]),
                &create_test_execution_receipt(vec![
                    InvalidBundle {
                        bundle_index: 3,
                        invalid_bundle_type: InvalidBundleType::UndecodableTx
                    },
                    InvalidBundle {
                        bundle_index: 4,
                        invalid_bundle_type: InvalidBundleType::IllegalTx
                    }
                ]),
            ),
            Some(ValidAsInvalid(ValidAsInvalidBundleEntryFraudProof::new(
                DomainId::new(2),
                3
            )))
        );
    }
}
