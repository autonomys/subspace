use crate::fraud_proof::{find_trace_mismatch, FraudProofGenerator};
use crate::parent_chain::ParentChainInterface;
use crate::utils::{DomainBlockImportNotification, DomainImportNotificationSinks};
use crate::ExecutionReceiptFor;
use codec::{Decode, Encode};
use domain_block_builder::{BlockBuilder, BuiltBlock, RecordProof};
use domain_runtime_primitives::DomainCoreApi;
use sc_client_api::{AuxStore, BlockBackend, Finalizer, StateBackendFor, TransactionFor};
use sc_consensus::{
    BlockImport, BlockImportParams, ForkChoiceStrategy, ImportResult, StateAction, StorageChanges,
};
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::{HashAndNumber, HeaderBackend, HeaderMetadata};
use sp_consensus::{BlockOrigin, SyncOracle};
use sp_core::traits::CodeExecutor;
use sp_domains::fraud_proof::FraudProof;
use sp_domains::merkle_tree::MerkleTree;
use sp_domains::{DomainId, DomainsApi, ExecutionReceipt};
use sp_runtime::traits::{Block as BlockT, CheckedSub, HashFor, Header as HeaderT, One, Zero};
use sp_runtime::Digest;
use std::sync::Arc;

pub(crate) struct DomainBlockResult<Block, CBlock>
where
    Block: BlockT,
    CBlock: BlockT,
{
    pub header_hash: Block::Hash,
    pub header_number: NumberFor<Block>,
    pub execution_receipt: ExecutionReceiptFor<Block, CBlock>,
}

/// An abstracted domain block processor.
pub(crate) struct DomainBlockProcessor<Block, CBlock, Client, CClient, Backend, BI>
where
    Block: BlockT,
    CBlock: BlockT,
{
    pub(crate) domain_id: DomainId,
    pub(crate) client: Arc<Client>,
    pub(crate) consensus_client: Arc<CClient>,
    pub(crate) backend: Arc<Backend>,
    pub(crate) domain_confirmation_depth: NumberFor<Block>,
    pub(crate) block_import: Arc<BI>,
    pub(crate) import_notification_sinks: DomainImportNotificationSinks<Block, CBlock>,
}

impl<Block, CBlock, Client, CClient, Backend, BI> Clone
    for DomainBlockProcessor<Block, CBlock, Client, CClient, Backend, BI>
where
    Block: BlockT,
    CBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            client: self.client.clone(),
            consensus_client: self.consensus_client.clone(),
            backend: self.backend.clone(),
            domain_confirmation_depth: self.domain_confirmation_depth,
            block_import: self.block_import.clone(),
            import_notification_sinks: self.import_notification_sinks.clone(),
        }
    }
}

/// A list of consensus blocks waiting to be processed by executor on each imported consensus block
/// notification.
///
/// Usually, each new domain block is built on top of the current best domain block, with the block
/// content extracted from the incoming consensus block. However, an incoming imported consensus block
/// notification can also imply multiple pending consensus blocks in case of the consensus chain re-org.
#[derive(Debug)]
pub(crate) struct PendingConsensusBlocks<Block: BlockT, CBlock: BlockT> {
    /// Base block used to build new domain blocks derived from the consensus blocks below.
    pub initial_parent: (Block::Hash, NumberFor<Block>),
    /// Pending consensus blocks that need to be processed sequentially.
    pub consensus_imports: Vec<HashAndNumber<CBlock>>,
}

impl<Block, CBlock, Client, CClient, Backend, BI>
    DomainBlockProcessor<Block, CBlock, Client, CClient, Backend, BI>
where
    Block: BlockT,
    CBlock: BlockT,
    NumberFor<CBlock>: Into<NumberFor<Block>>,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + Finalizer<Block, Backend>
        + 'static,
    Client::Api: DomainCoreApi<Block>
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
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
{
    /// Returns a list of consensus blocks waiting to be processed if any.
    ///
    /// It's possible to have multiple pending consensus blocks that need to be processed in case
    /// the consensus chain re-org occurs.
    pub(crate) fn pending_imported_consensus_blocks(
        &self,
        consensus_block_hash: CBlock::Hash,
        consensus_block_number: NumberFor<CBlock>,
    ) -> sp_blockchain::Result<Option<PendingConsensusBlocks<Block, CBlock>>> {
        if consensus_block_number == One::one() {
            return Ok(Some(PendingConsensusBlocks {
                initial_parent: (self.client.info().genesis_hash, Zero::zero()),
                consensus_imports: vec![HashAndNumber {
                    hash: consensus_block_hash,
                    number: consensus_block_number,
                }],
            }));
        }

        let best_hash = self.client.info().best_hash;
        let best_number = self.client.info().best_number;

        let consensus_block_hash_for_best_domain_hash =
            crate::aux_schema::latest_consensus_block_hash_for(&*self.backend, &best_hash)?
                .ok_or_else(|| {
                    sp_blockchain::Error::Backend(format!(
                        "Consensus hash for domain hash #{best_number},{best_hash} not found"
                    ))
                })?;

        let consensus_from = consensus_block_hash_for_best_domain_hash;
        let consensus_to = consensus_block_hash;

        if consensus_from == consensus_to {
            return Err(sp_blockchain::Error::Application(Box::from(
                "Consensus block {consensus_block_hash:?} has already been processed.",
            )));
        }

        let route =
            sp_blockchain::tree_route(&*self.consensus_client, consensus_from, consensus_to)?;

        let retracted = route.retracted();
        let enacted = route.enacted();

        tracing::trace!(
            ?retracted,
            ?enacted,
            common_block = ?route.common_block(),
            "Calculating PendingConsensusBlocks on #{best_number},{best_hash:?}"
        );

        match (retracted.is_empty(), enacted.is_empty()) {
            (true, false) => {
                // New tip, A -> B
                Ok(Some(PendingConsensusBlocks {
                    initial_parent: (best_hash, best_number),
                    consensus_imports: enacted.to_vec(),
                }))
            }
            (false, true) => {
                tracing::debug!("Consensus blocks {retracted:?} have been already processed");
                Ok(None)
            }
            (true, true) => {
                unreachable!(
                    "Tree route is not empty as `consensus_from` and `consensus_to` in tree_route() \
                    are checked above to be not the same; qed",
                );
            }
            (false, false) => {
                let (common_block_number, common_block_hash) =
                    (route.common_block().number, route.common_block().hash);

                // Get the domain block that is derived from the common primary block and use it as
                // the initial domain parent block
                let domain_block_hash: Block::Hash = crate::aux_schema::best_domain_hash_for(
                    &*self.client,
                    &common_block_hash,
                )?
                .ok_or_else(
                    || {
                        sp_blockchain::Error::Backend(format!(
                            "Hash of domain block derived from primary block #{common_block_number},{common_block_hash} not found"
                        ))
                    },
                )?;
                let parent_header = self.client.header(domain_block_hash)?.ok_or_else(|| {
                    sp_blockchain::Error::Backend(format!(
                        "Domain block header for #{:?} not found",
                        domain_block_hash
                    ))
                })?;

                Ok(Some(PendingConsensusBlocks {
                    initial_parent: (parent_header.hash(), *parent_header.number()),
                    consensus_imports: enacted.to_vec(),
                }))
            }
        }
    }

    pub(crate) async fn process_domain_block(
        &self,
        (consensus_block_hash, consensus_block_number): (CBlock::Hash, NumberFor<CBlock>),
        (parent_hash, parent_number): (Block::Hash, NumberFor<Block>),
        extrinsics: Vec<Block::Extrinsic>,
        digests: Digest,
    ) -> Result<DomainBlockResult<Block, CBlock>, sp_blockchain::Error> {
        // Although the domain block intuitively ought to use the same fork choice
        // from the corresponding primary block, it's fine to forcibly always use
        // the longest chain for simplicity as we manually build the domain branches
        // by following the primary chain branches. Due to the possibility of domain
        // branch transitioning to a lower fork caused by the change that a primary block
        // can possibility produce no domain block, it's important to note that now we
        // need to ensure the domain block built from the latest primary block is the
        // new best domain block after processing each imported primary block.
        let fork_choice = ForkChoiceStrategy::LongestChain;

        let (header_hash, header_number, state_root) = self
            .build_and_import_block(parent_hash, parent_number, extrinsics, fork_choice, digests)
            .await?;

        tracing::debug!(
            "Built new domain block #{header_number},{header_hash} from consensus block #{consensus_block_number},{consensus_block_hash} \
            on top of parent block #{parent_number},{parent_hash}"
        );

        if let Some(to_finalize_block_number) = consensus_block_number
            .into()
            .checked_sub(&self.domain_confirmation_depth)
        {
            if to_finalize_block_number > self.client.info().finalized_number {
                let to_finalize_block_hash =
                    self.client.hash(to_finalize_block_number)?.ok_or_else(|| {
                        sp_blockchain::Error::Backend(format!(
                            "Header for #{to_finalize_block_number} not found"
                        ))
                    })?;
                self.client
                    .finalize_block(to_finalize_block_hash, None, true)?;
                tracing::debug!("Successfully finalized block: #{to_finalize_block_number},{to_finalize_block_hash}");
            }
        }

        let mut roots = self.client.runtime_api().intermediate_roots(header_hash)?;

        let state_root = state_root
            .encode()
            .try_into()
            .expect("State root uses the same Block hash type which must fit into [u8; 32]; qed");

        roots.push(state_root);

        let trace_root = MerkleTree::from_leaves(&roots).root().ok_or_else(|| {
            sp_blockchain::Error::Application(Box::from("Failed to get merkle root of trace"))
        })?;
        let trace = roots
            .into_iter()
            .map(|r| {
                Block::Hash::decode(&mut r.as_slice())
                    .expect("Storage root uses the same Block hash type; qed")
            })
            .collect();

        tracing::trace!(
            ?trace,
            ?trace_root,
            "Trace root calculated for #{header_number},{header_hash}"
        );

        let execution_receipt = ExecutionReceipt {
            consensus_block_number,
            consensus_block_hash,
            domain_block_number: header_number,
            domain_hash: header_hash,
            trace,
            trace_root,
        };

        Ok(DomainBlockResult {
            header_hash,
            header_number,
            execution_receipt,
        })
    }

    async fn build_and_import_block(
        &self,
        parent_hash: Block::Hash,
        parent_number: NumberFor<Block>,
        extrinsics: Vec<Block::Extrinsic>,
        fork_choice: ForkChoiceStrategy,
        digests: Digest,
    ) -> Result<(Block::Hash, NumberFor<Block>, Block::Hash), sp_blockchain::Error> {
        let block_builder = BlockBuilder::new(
            &*self.client,
            parent_hash,
            parent_number,
            RecordProof::No,
            digests,
            &*self.backend,
            extrinsics,
        )?;

        let BuiltBlock {
            block,
            storage_changes,
            proof: _,
        } = block_builder.build()?;

        let (header, body) = block.deconstruct();
        let state_root = *header.state_root();
        let header_hash = header.hash();
        let header_number = *header.number();

        let block_import_params = {
            let mut import_block = BlockImportParams::new(BlockOrigin::Own, header);
            import_block.body = Some(body);
            import_block.state_action =
                StateAction::ApplyChanges(StorageChanges::Changes(storage_changes));
            // Follow the consensus block's fork choice.
            import_block.fork_choice = Some(fork_choice);
            import_block
        };
        self.import_domain_block(block_import_params).await?;

        Ok((header_hash, header_number, state_root))
    }

    pub(crate) async fn import_domain_block(
        &self,
        block_import_params: BlockImportParams<Block, sp_api::TransactionFor<Client, Block>>,
    ) -> Result<(), sp_blockchain::Error> {
        let (header_number, header_hash, parent_hash) = (
            *block_import_params.header.number(),
            block_import_params.header.hash(),
            *block_import_params.header.parent_hash(),
        );

        let import_result = (&*self.block_import)
            .import_block(block_import_params)
            .await?;

        match import_result {
            ImportResult::Imported(..) => {}
            ImportResult::AlreadyInChain => {
                tracing::debug!("Block #{header_number},{header_hash:?} is already in chain");
            }
            ImportResult::KnownBad => {
                return Err(sp_consensus::Error::ClientImport(format!(
                    "Bad block #{header_number}({header_hash:?})"
                ))
                .into());
            }
            ImportResult::UnknownParent => {
                return Err(sp_consensus::Error::ClientImport(format!(
                    "Block #{header_number}({header_hash:?}) has an unknown parent: {parent_hash:?}"
                ))
                .into());
            }
            ImportResult::MissingState => {
                return Err(sp_consensus::Error::ClientImport(format!(
                    "Parent state of block #{header_number}({header_hash:?}) is missing, parent: {parent_hash:?}"
                ))
                    .into());
            }
        }

        Ok(())
    }

    pub(crate) fn on_consensus_block_processed(
        &self,
        consensus_block_hash: CBlock::Hash,
        domain_block_result: Option<DomainBlockResult<Block, CBlock>>,
        head_receipt_number: NumberFor<Block>,
    ) -> sp_blockchain::Result<()> {
        let domain_hash = match domain_block_result {
            Some(DomainBlockResult {
                header_hash,
                header_number: _,
                execution_receipt,
            }) => {
                crate::aux_schema::write_execution_receipt::<_, Block, CBlock>(
                    &*self.client,
                    head_receipt_number,
                    &execution_receipt,
                )?;

                // Notify the imported domain block when the receipt processing is done.
                let domain_import_notification = DomainBlockImportNotification {
                    domain_block_hash: header_hash,
                    consensus_block_hash,
                };

                self.import_notification_sinks.lock().retain(|sink| {
                    sink.unbounded_send(domain_import_notification.clone())
                        .is_ok()
                });

                header_hash
            }
            None => {
                // No new domain block produced, thus this primary block should map to the same
                // domain block as its parent block
                let primary_header = self
                    .consensus_client
                    .header(consensus_block_hash)?
                    .ok_or_else(|| {
                        sp_blockchain::Error::Backend(format!(
                            "Primary block header for #{consensus_block_hash:?} not found"
                        ))
                    })?;
                if !primary_header.number().is_one() {
                    crate::aux_schema::best_domain_hash_for(
                        &*self.client,
                        primary_header.parent_hash(),
                    )?
                    .ok_or_else(|| {
                        sp_blockchain::Error::Backend(format!(
                            "Domain hash for #{:?} not found",
                            primary_header.parent_hash()
                        ))
                    })?
                } else {
                    self.client.info().genesis_hash
                }
            }
        };

        crate::aux_schema::track_domain_hash_and_consensus_hash(
            &*self.client,
            domain_hash,
            consensus_block_hash,
        )?;

        Ok(())
    }
}

pub(crate) struct ReceiptsChecker<
    Block,
    Client,
    CBlock,
    CClient,
    Backend,
    E,
    ParentChain,
    ParentChainBlock,
> {
    pub(crate) domain_id: DomainId,
    pub(crate) client: Arc<Client>,
    pub(crate) consensus_client: Arc<CClient>,
    pub(crate) consensus_network_sync_oracle: Arc<dyn SyncOracle + Send + Sync>,
    pub(crate) fraud_proof_generator:
        FraudProofGenerator<Block, CBlock, Client, CClient, Backend, E>,
    pub(crate) parent_chain: ParentChain,
    pub(crate) _phantom: std::marker::PhantomData<ParentChainBlock>,
}

impl<Block, CBlock, Client, CClient, Backend, E, ParentChain, ParentChainBlock> Clone
    for ReceiptsChecker<Block, CBlock, Client, CClient, Backend, E, ParentChain, ParentChainBlock>
where
    Block: BlockT,
    ParentChain: Clone,
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            client: self.client.clone(),
            consensus_client: self.consensus_client.clone(),
            consensus_network_sync_oracle: self.consensus_network_sync_oracle.clone(),
            fraud_proof_generator: self.fraud_proof_generator.clone(),
            parent_chain: self.parent_chain.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<Block, Client, CBlock, CClient, Backend, E, ParentChain, ParentChainBlock>
    ReceiptsChecker<Block, Client, CBlock, CClient, Backend, E, ParentChain, ParentChainBlock>
where
    Block: BlockT,
    CBlock: BlockT,
    ParentChainBlock: BlockT,
    NumberFor<CBlock>: Into<NumberFor<Block>>,
    Client:
        HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block> + 'static,
    Client::Api: DomainCoreApi<Block>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    CClient: HeaderBackend<CBlock> + BlockBackend<CBlock> + ProvideRuntimeApi<CBlock> + 'static,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    E: CodeExecutor,
    ParentChain: ParentChainInterface<Block, ParentChainBlock>,
{
    pub(crate) fn check_state_transition(
        &self,
        parent_chain_block_hash: ParentChainBlock::Hash,
    ) -> sp_blockchain::Result<()> {
        let extrinsics = self.parent_chain.block_body(parent_chain_block_hash)?;

        let receipts = self
            .parent_chain
            .extract_receipts(parent_chain_block_hash, extrinsics.clone())?;

        let fraud_proofs = self
            .parent_chain
            .extract_fraud_proofs(parent_chain_block_hash, extrinsics)?;

        self.check_receipts(receipts, fraud_proofs)?;

        if self.consensus_network_sync_oracle.is_major_syncing() {
            tracing::debug!(
                "Skip reporting unconfirmed bad receipt as the consensus node is still major syncing..."
            );
            return Ok(());
        }

        // Submit fraud proof for the first unconfirmed incorrent ER.
        let oldest_receipt_number = self
            .parent_chain
            .oldest_receipt_number(parent_chain_block_hash)?;
        crate::aux_schema::prune_expired_bad_receipts(&*self.client, oldest_receipt_number)?;

        if let Some(fraud_proof) = self.create_fraud_proof_for_first_unconfirmed_bad_receipt()? {
            self.parent_chain.submit_fraud_proof_unsigned(fraud_proof)?;
        }

        Ok(())
    }

    fn check_receipts(
        &self,
        receipts: Vec<ExecutionReceiptFor<Block, ParentChainBlock>>,
        fraud_proofs: Vec<FraudProof<NumberFor<ParentChainBlock>, ParentChainBlock::Hash>>,
    ) -> Result<(), sp_blockchain::Error> {
        let mut bad_receipts_to_write = vec![];

        for execution_receipt in receipts.iter() {
            // Skip check for genesis receipt as it is generated on the domain instantiation by
            // the consensus chain.
            if execution_receipt.domain_block_number.is_zero() {
                continue;
            }

            let consensus_block_hash = execution_receipt.consensus_block_hash;

            let local_receipt = crate::aux_schema::load_execution_receipt::<
                _,
                Block,
                ParentChainBlock,
            >(&*self.client, consensus_block_hash)?
            .ok_or(sp_blockchain::Error::Backend(format!(
                "Receipt for consensus block #{},{consensus_block_hash} not found",
                execution_receipt.consensus_block_number
            )))?;

            if let Some(trace_mismatch_index) =
                find_trace_mismatch(&local_receipt.trace, &execution_receipt.trace)
            {
                bad_receipts_to_write.push((
                    execution_receipt.consensus_block_number,
                    execution_receipt.hash(),
                    (trace_mismatch_index, consensus_block_hash),
                ));
            }
        }

        let bad_receipts_to_delete = fraud_proofs
            .into_iter()
            .filter_map(|fraud_proof| {
                match fraud_proof {
                    FraudProof::InvalidStateTransition(fraud_proof) => {
                        let bad_receipt_number = fraud_proof.parent_number + 1;
                        let bad_receipt_hash = fraud_proof.bad_receipt_hash;

                        // In order to not delete a receipt which was just inserted, accumulate the write&delete operations
                        // in case the bad receipt and corresponding farud proof are included in the same block.
                        if let Some(index) = bad_receipts_to_write
                            .iter()
                            .map(|(_, receipt_hash, _)| receipt_hash)
                            .position(|v| *v == bad_receipt_hash)
                        {
                            bad_receipts_to_write.swap_remove(index);
                            None
                        } else {
                            Some((bad_receipt_number, bad_receipt_hash))
                        }
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>();

        for (bad_receipt_number, bad_receipt_hash, mismatch_info) in bad_receipts_to_write {
            crate::aux_schema::write_bad_receipt::<_, ParentChainBlock>(
                &*self.client,
                bad_receipt_number,
                bad_receipt_hash,
                mismatch_info,
            )?;
        }

        for (bad_receipt_number, bad_receipt_hash) in bad_receipts_to_delete {
            if let Err(e) = crate::aux_schema::delete_bad_receipt(
                &*self.client,
                bad_receipt_number,
                bad_receipt_hash,
            ) {
                tracing::error!(
                    error = ?e,
                    ?bad_receipt_number,
                    ?bad_receipt_hash,
                    "Failed to delete bad receipt"
                );
            }
        }

        Ok(())
    }

    fn create_fraud_proof_for_first_unconfirmed_bad_receipt(
        &self,
    ) -> sp_blockchain::Result<
        Option<FraudProof<NumberFor<ParentChainBlock>, ParentChainBlock::Hash>>,
    > {
        if let Some((bad_receipt_hash, trace_mismatch_index, consensus_block_hash)) =
            crate::aux_schema::find_first_unconfirmed_bad_receipt_info::<_, Block, CBlock, _>(
                &*self.client,
                |height| {
                    self.consensus_client.hash(height)?.ok_or_else(|| {
                        sp_blockchain::Error::Backend(format!(
                            "Consensus block hash for #{height} not found",
                        ))
                    })
                },
            )?
        {
            let local_receipt = crate::aux_schema::load_execution_receipt::<_, Block, CBlock>(
                &*self.client,
                consensus_block_hash,
            )?
            .ok_or_else(|| {
                sp_blockchain::Error::Backend(format!(
                    "Receipt for consensus block {consensus_block_hash} not found"
                ))
            })?;

            let fraud_proof = self
                .fraud_proof_generator
                .generate_invalid_state_transition_proof::<ParentChainBlock>(
                    self.domain_id,
                    trace_mismatch_index,
                    &local_receipt,
                    bad_receipt_hash,
                )
                .map_err(|err| {
                    sp_blockchain::Error::Application(Box::from(format!(
                        "Failed to generate fraud proof: {err}"
                    )))
                })?;

            return Ok(Some(fraud_proof));
        }

        Ok(None)
    }
}
