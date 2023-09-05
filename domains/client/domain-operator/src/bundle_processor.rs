use crate::domain_block_processor::{
    DomainBlockProcessor, PendingConsensusBlocks, ReceiptsChecker,
};
use crate::fraud_proof::FraudProofGenerator;
use crate::parent_chain::ParentChainInterface;
use crate::{DomainParentChain, ExecutionReceiptFor, TransactionFor};
use domain_block_preprocessor::runtime_api_full::RuntimeApiFull;
use domain_block_preprocessor::{DomainBlockPreprocessor, PreprocessResult};
use domain_runtime_primitives::{DomainCoreApi, InherentExtrinsicApi};
use sc_client_api::{AuxStore, BlockBackend, Finalizer, StateBackendFor};
use sc_consensus::{BlockImport, BlockImportParams, ForkChoiceStrategy, StateAction};
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_consensus::BlockOrigin;
use sp_core::traits::CodeExecutor;
use sp_domain_digests::AsPredigest;
use sp_domains::fraud_proof::{
    AdditionalInvalidBundleEntryFraudProof, FraudProof, IncorrectSortitionFraudProof,
    InvalidBundlesFraudProof, MisclassifiedInvalidBundleFraudProof,
    MissingInvalidBundleEntryFraudProof,
};
use sp_domains::{DomainId, DomainsApi, InvalidReceipt, ReceiptValidity};
use sp_keystore::KeystorePtr;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, HashFor, Zero};
use sp_runtime::{Digest, DigestItem};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
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

type DomainReceiptsValidator<Block, CBlock, Client, CClient, Backend, E> = ReceiptValidator<
    Client,
    Block,
    CBlock,
    CClient,
    Backend,
    E,
    DomainParentChain<Block, CBlock, CClient>,
    CBlock,
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
    domain_block_preprocessor: DomainBlockPreprocessor<
        Block,
        CBlock,
        Client,
        CClient,
        RuntimeApiFull<Client>,
        DomainReceiptsValidator<Block, CBlock, Client, CClient, Backend, E>,
    >,
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

struct ReceiptValidator<Client, Block, CBlock, CClient, Backend, E, ParentChain, ParentChainBlock> {
    domain_id: DomainId,
    client: Arc<Client>,
    fraud_proof_generator: FraudProofGenerator<Block, CBlock, Client, CClient, Backend, E>,
    parent_chain: ParentChain,
    _phantom: std::marker::PhantomData<ParentChainBlock>,
}

impl<Client, Block, CBlock, CClient, Backend, E, ParentChain, ParentChainBlock> Clone
    for ReceiptValidator<Client, Block, CBlock, CClient, Backend, E, ParentChain, ParentChainBlock>
where
    ParentChain: Clone,
    ParentChainBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            client: self.client.clone(),
            fraud_proof_generator: self.fraud_proof_generator.clone(),
            parent_chain: self.parent_chain.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<Client, Block, CBlock, CClient, Backend, E, ParentChain, ParentChainBlock>
    ReceiptValidator<Client, Block, CBlock, CClient, Backend, E, ParentChain, ParentChainBlock>
{
    pub fn new(
        domain_id: DomainId,
        client: Arc<Client>,
        fraud_proof_generator: FraudProofGenerator<Block, CBlock, Client, CClient, Backend, E>,
        parent_chain: ParentChain,
    ) -> Self {
        Self {
            domain_id,
            client,
            fraud_proof_generator,
            parent_chain,
            _phantom: PhantomData,
        }
    }
}

impl<Client, Block, CBlock, CClient, Backend, E, ParentChain, ParentChainBlock>
    ReceiptValidator<Client, Block, CBlock, CClient, Backend, E, ParentChain, ParentChainBlock>
where
    Block: BlockT,
    CBlock: BlockT,
    Client:
        HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block> + 'static,
    Client::Api: sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    CClient: HeaderBackend<CBlock> + 'static,
    Backend: sc_client_api::Backend<Block> + Send + Sync + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    E: CodeExecutor,
    ParentChainBlock: BlockT,
    ParentChain: ParentChainInterface<Block, ParentChainBlock>,
{
    fn check_invalid_bundles_field(
        &self,
        local_receipt: &ExecutionReceiptFor<Block, CBlock>,
        user_receipt: &ExecutionReceiptFor<Block, CBlock>,
    ) -> bool {
        let mut local_invalid_bundles_map = HashMap::new();
        let mut fraud_proofs: Vec<FraudProof<NumberFor<Block>, Block::Hash>> = vec![];
        if local_receipt.invalid_bundles != user_receipt.invalid_bundles {
            for invalid_bundle in &local_receipt.invalid_bundles {
                local_invalid_bundles_map.insert(
                    invalid_bundle.bundle_index,
                    (invalid_bundle.invalid_bundle_type.clone(), false),
                );
            }

            for invalid_bundle in &user_receipt.invalid_bundles {
                let entry = local_invalid_bundles_map.entry(invalid_bundle.bundle_index);
                match entry {
                    Entry::Occupied(mut occupied_entry) => {
                        if occupied_entry.get().0 != invalid_bundle.invalid_bundle_type {
                            fraud_proofs.push(FraudProof::InvalidBundles(
                                InvalidBundlesFraudProof::MisclassifiedInvalidBundleEntry(
                                    MisclassifiedInvalidBundleFraudProof::new(
                                        self.domain_id,
                                        invalid_bundle.bundle_index,
                                    ),
                                ),
                            ));
                        } else {
                            *occupied_entry.get_mut() =
                                (invalid_bundle.invalid_bundle_type.clone(), true);
                        }
                    }
                    Entry::Vacant(_) => {
                        fraud_proofs.push(FraudProof::InvalidBundles(
                            InvalidBundlesFraudProof::AdditionalInvalidBundleEntry(
                                AdditionalInvalidBundleEntryFraudProof::new(
                                    self.domain_id,
                                    invalid_bundle.bundle_index,
                                ),
                            ),
                        ));
                    }
                }
            }

            for (bundle_index, v) in local_invalid_bundles_map.iter() {
                // This bundle is missing from the input receipt's invalid bundles vector
                if !v.1 {
                    fraud_proofs.push(FraudProof::InvalidBundles(
                        InvalidBundlesFraudProof::MissingInvalidBundleEntry(
                            MissingInvalidBundleEntryFraudProof::new(self.domain_id, *bundle_index),
                        ),
                    ));
                }
            }

            if fraud_proofs.is_empty() {
                fraud_proofs.push(FraudProof::InvalidBundles(
                    InvalidBundlesFraudProof::IncorrectSortition(
                        IncorrectSortitionFraudProof::new(self.domain_id),
                    ),
                ));
            }
        }

        // TODO: Submit the fraud proofs to parent chain, once we have proper proof data in place

        fraud_proofs.is_empty()
    }
}

impl<Client, Block, CBlock, CClient, Backend, E, ParentChain, ParentChainBlock>
    domain_block_preprocessor::ValidateReceipt<Block, CBlock>
    for ReceiptValidator<Client, Block, CBlock, CClient, Backend, E, ParentChain, ParentChainBlock>
where
    Block: BlockT,
    CBlock: BlockT,
    Client:
        HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block> + 'static,
    Client::Api: sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    CClient: HeaderBackend<CBlock> + 'static,
    Backend: sc_client_api::Backend<Block> + Send + Sync + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    E: CodeExecutor,
    ParentChainBlock: BlockT,
    ParentChain: ParentChainInterface<Block, ParentChainBlock>,
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

        if !self.check_invalid_bundles_field(&local_receipt, receipt) {
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
        + Finalizer<Block, Backend>
        + 'static,
    Client::Api: DomainCoreApi<Block>
        + MessengerApi<Block, NumberFor<Block>>
        + InherentExtrinsicApi<Block>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    for<'b> &'b BI: BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    CClient: HeaderBackend<CBlock>
        + HeaderMetadata<CBlock, Error = sp_blockchain::Error>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + 'static,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>
        + MessengerApi<CBlock, NumberFor<CBlock>>
        + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
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
            ReceiptValidator::new(
                domain_id,
                client.clone(),
                domain_receipts_checker.fraud_proof_generator.clone(),
                domain_receipts_checker.parent_chain.clone(),
            ),
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

        let Some(PreprocessResult {
            extrinsics,
            extrinsics_roots,
            invalid_bundles,
        }) = self
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
                extrinsics,
                invalid_bundles,
                extrinsics_roots,
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

        Ok(Some(built_block_info))
    }
}
