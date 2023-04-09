use crate::fraud_proof::{find_trace_mismatch, FraudProofGenerator};
use crate::utils::{to_number_primitive, translate_number_type};
use crate::{ExecutionReceiptFor, TransactionFor};
use codec::{Decode, Encode};
use domain_block_builder::{BlockBuilder, BuiltBlock, RecordProof};
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use sc_client_api::{AuxStore, BlockBackend, StateBackendFor};
use sc_consensus::{
    BlockImport, BlockImportParams, ForkChoiceStrategy, ImportResult, StateAction, StorageChanges,
};
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::{HashAndNumber, HeaderBackend, HeaderMetadata};
use sp_consensus::{BlockOrigin, SyncOracle};
use sp_core::traits::CodeExecutor;
use sp_domains::fraud_proof::FraudProof;
use sp_domains::merkle_tree::MerkleTree;
use sp_domains::{DomainId, ExecutionReceipt, ExecutorApi};
use sp_runtime::traits::{Block as BlockT, HashFor, Header as HeaderT, One, Zero};
use sp_runtime::Digest;
use std::sync::Arc;

pub(crate) struct DomainBlockResult<Block, PBlock>
where
    Block: BlockT,
    PBlock: BlockT,
{
    pub header_hash: Block::Hash,
    pub header_number: NumberFor<Block>,
    pub execution_receipt: ExecutionReceiptFor<PBlock, Block::Hash>,
}

/// A common component shared between the system and core domain bundle processor.
pub(crate) struct DomainBlockProcessor<Block, PBlock, Client, PClient, Backend, E>
where
    PBlock: BlockT,
{
    domain_id: DomainId,
    client: Arc<Client>,
    primary_chain_client: Arc<PClient>,
    primary_network_sync_oracle: Arc<dyn SyncOracle + Send + Sync>,
    backend: Arc<Backend>,
    fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, PClient, Backend, E>,
}

impl<Block, PBlock, Client, PClient, Backend, E> Clone
    for DomainBlockProcessor<Block, PBlock, Client, PClient, Backend, E>
where
    PBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            client: self.client.clone(),
            primary_chain_client: self.primary_chain_client.clone(),
            primary_network_sync_oracle: self.primary_network_sync_oracle.clone(),
            backend: self.backend.clone(),
            fraud_proof_generator: self.fraud_proof_generator.clone(),
        }
    }
}

/// A list of primary blocks waiting to be processed by executor on each imported primary block
/// notification.
///
/// Usually, each new domain block is built on top of the current best domain block, with the block
/// content extracted from the incoming primary block. However, an incoming imported primary block
/// notification can also imply multiple pending primary blocks in case of the primary chain re-org.
#[derive(Debug)]
pub(crate) struct PendingPrimaryBlocks<Block: BlockT, PBlock: BlockT> {
    /// Base block used to build new domain blocks derived from the primary blocks below.
    pub initial_parent: (Block::Hash, NumberFor<Block>),
    /// Pending primary blocks that need to be processed sequentially.
    pub primary_imports: Vec<HashAndNumber<PBlock>>,
}

impl<Block, PBlock, Client, PClient, Backend, E>
    DomainBlockProcessor<Block, PBlock, Client, PClient, Backend, E>
where
    Block: BlockT,
    PBlock: BlockT,
    Client:
        HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block> + 'static,
    Client::Api: DomainCoreApi<Block, AccountId>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    for<'b> &'b Client: BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    PClient: HeaderBackend<PBlock>
        + HeaderMetadata<PBlock, Error = sp_blockchain::Error>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    E: CodeExecutor,
{
    pub(crate) fn new(
        domain_id: DomainId,
        client: Arc<Client>,
        primary_chain_client: Arc<PClient>,
        primary_network_sync_oracle: Arc<dyn SyncOracle + Send + Sync>,
        backend: Arc<Backend>,
        fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, PClient, Backend, E>,
    ) -> Self {
        Self {
            domain_id,
            client,
            primary_chain_client,
            primary_network_sync_oracle,
            backend,
            fraud_proof_generator,
        }
    }

    /// Returns a list of primary blocks waiting to be processed if any.
    ///
    /// It's possible to have multiple pending primary blocks that need to be processed in case
    /// the primary chain re-org occurs.
    pub(crate) fn pending_imported_primary_blocks(
        &self,
        primary_hash: PBlock::Hash,
        primary_number: NumberFor<PBlock>,
    ) -> sp_blockchain::Result<Option<PendingPrimaryBlocks<Block, PBlock>>> {
        if primary_number == One::one() {
            return Ok(Some(PendingPrimaryBlocks {
                initial_parent: (self.client.info().genesis_hash, Zero::zero()),
                primary_imports: vec![HashAndNumber {
                    hash: primary_hash,
                    number: primary_number,
                }],
            }));
        }

        let best_hash = self.client.info().best_hash;
        let best_number = self.client.info().best_number;
        let best_receipt = crate::aux_schema::load_execution_receipt::<
            _,
            Block::Hash,
            NumberFor<PBlock>,
            PBlock::Hash,
        >(&*self.client, best_hash)?
        .ok_or_else(|| {
            sp_blockchain::Error::Backend(format!(
                "Receipt for #{best_number},{best_hash:?} not found"
            ))
        })?;

        let primary_from = best_receipt.primary_hash;
        let primary_to = primary_hash;

        if primary_from == primary_to {
            return Err(sp_blockchain::Error::Application(Box::from(
                "Primary block {primary_hash:?} has already been processed.",
            )));
        }

        let route =
            sp_blockchain::tree_route(&*self.primary_chain_client, primary_from, primary_to)?;

        let retracted = route.retracted();
        let enacted = route.enacted();

        tracing::trace!(
            ?retracted,
            ?enacted,
            common_block = ?route.common_block(),
            "Calculating PendingPrimaryBlocks on #{best_number},{best_hash:?}"
        );

        match (retracted.is_empty(), enacted.is_empty()) {
            (true, false) => {
                // New tip, A -> B
                Ok(Some(PendingPrimaryBlocks {
                    initial_parent: (self.client.info().best_hash, self.client.info().best_number),
                    primary_imports: enacted.to_vec(),
                }))
            }
            (false, true) => {
                tracing::debug!("Primary blocks {retracted:?} have been already processed");
                Ok(None)
            }
            (true, true) => {
                unreachable!(
                    "Tree route is not empty as `primary_from` and `primary_to` in tree_route() \
                    are checked above to be not the same; qed",
                );
            }
            (false, false) => {
                let common_block_number = translate_number_type(route.common_block().number);
                let parent_header = self
                    .client
                    .header(self.client.hash(common_block_number)?.ok_or_else(|| {
                        sp_blockchain::Error::Backend(format!(
                            "Header for #{common_block_number} not found"
                        ))
                    })?)?
                    .ok_or_else(|| {
                        sp_blockchain::Error::Backend(format!(
                            "Header for #{common_block_number} not found"
                        ))
                    })?;

                Ok(Some(PendingPrimaryBlocks {
                    initial_parent: (parent_header.hash(), *parent_header.number()),
                    primary_imports: enacted.to_vec(),
                }))
            }
        }
    }

    pub(crate) async fn process_domain_block(
        &self,
        (primary_hash, primary_number): (PBlock::Hash, NumberFor<PBlock>),
        (parent_hash, parent_number): (Block::Hash, NumberFor<Block>),
        extrinsics: Vec<Block::Extrinsic>,
        digests: Digest,
    ) -> Result<DomainBlockResult<Block, PBlock>, sp_blockchain::Error> {
        let primary_number = to_number_primitive(primary_number);

        if to_number_primitive(parent_number) + 1 != primary_number {
            return Err(sp_blockchain::Error::Application(Box::from(format!(
                "Wrong domain parent block #{parent_number},{parent_hash:?} for \
                primary block #{primary_number},{primary_hash:?}, the number of new \
                domain block must match the number of corresponding primary block."
            ))));
        }

        // Although the domain block intuitively ought to use the same fork choice
        // from the corresponding primary block, it's fine to forcibly always use
        // the longest chain for simplicity as we manually build all the domain
        // branches by literally following the primary chain branches anyway.
        let fork_choice = ForkChoiceStrategy::LongestChain;

        let (header_hash, header_number, state_root) = self
            .build_and_import_block(parent_hash, parent_number, extrinsics, fork_choice, digests)
            .await?;

        tracing::debug!(
            "Built new domain block #{header_number},{header_hash} \
            from primary block #{primary_number},{primary_hash}",
        );

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
            primary_number: primary_number.into(),
            primary_hash,
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
            // Follow the primary block's fork choice.
            import_block.fork_choice = Some(fork_choice);
            import_block
        };

        let import_result = (&*self.client).import_block(block_import_params).await?;

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

        Ok((header_hash, header_number, state_root))
    }

    // TODO: remove once fraud-proof is enabled again.
    #[allow(unreachable_code, unused_variables)]
    pub(crate) fn on_domain_block_processed<PCB>(
        &self,
        primary_hash: PBlock::Hash,
        domain_block_result: DomainBlockResult<Block, PBlock>,
        head_receipt_number: NumberFor<Block>,
        oldest_receipt_number: NumberFor<Block>,
    ) -> sp_blockchain::Result<Option<FraudProof<NumberFor<PCB>, PCB::Hash>>>
    where
        PCB: BlockT,
    {
        let DomainBlockResult {
            header_hash,
            header_number,
            execution_receipt,
        } = domain_block_result;

        crate::aux_schema::write_execution_receipt::<_, Block, PBlock>(
            &*self.client,
            (header_hash, header_number),
            head_receipt_number,
            &execution_receipt,
        )?;

        // TODO: The applied txs can be fully removed from the transaction pool

        // TODO: Skip fraud-proof processing until
        // https://github.com/subspace/subspace/issues/1020 is resolved.
        return Ok(None);

        self.check_receipts_in_primary_block(primary_hash)?;

        if self.primary_network_sync_oracle.is_major_syncing() {
            tracing::debug!(
                "Skip checking the receipts as the primary node is still major syncing..."
            );
            return Ok(None);
        }

        // Submit fraud proof for the first unconfirmed incorrent ER.
        crate::aux_schema::prune_expired_bad_receipts(&*self.client, oldest_receipt_number)?;

        self.create_fraud_proof_for_first_unconfirmed_bad_receipt::<PCB>()
    }

    fn check_receipts_in_primary_block(
        &self,
        primary_hash: PBlock::Hash,
    ) -> Result<(), sp_blockchain::Error> {
        let extrinsics = self
            .primary_chain_client
            .block_body(primary_hash)?
            .ok_or_else(|| {
                sp_blockchain::Error::Backend(format!(
                    "Primary block body for {primary_hash:?} not found",
                ))
            })?;

        let receipts = self.primary_chain_client.runtime_api().extract_receipts(
            primary_hash,
            extrinsics.clone(),
            self.domain_id,
        )?;

        let mut bad_receipts_to_write = vec![];

        for execution_receipt in receipts.iter() {
            let block_hash = execution_receipt.domain_hash;
            match crate::aux_schema::load_execution_receipt::<
                _,
                Block::Hash,
                NumberFor<PBlock>,
                PBlock::Hash,
            >(&*self.client, block_hash)?
            {
                Some(local_receipt) => {
                    if let Some(trace_mismatch_index) =
                        find_trace_mismatch(&local_receipt, execution_receipt)
                    {
                        bad_receipts_to_write.push((
                            execution_receipt.primary_number,
                            execution_receipt.hash(),
                            (trace_mismatch_index, block_hash),
                        ));
                    }
                }
                None => {
                    let block_number = to_number_primitive(execution_receipt.primary_number);

                    // TODO: Ensure the `block_hash` aligns with the one returned in
                    // `aux_schema::find_first_unconfirmed_bad_receipt_info`. Assuming there are
                    // multiple forks at present, `block_hash` is on one of them, but another fork
                    // becomes the canonical chain later.
                    let block_hash = self.client.hash(block_number.into())?.ok_or_else(|| {
                        sp_blockchain::Error::Backend(format!(
                            "Header hash for #{block_number} not found"
                        ))
                    })?;

                    // The receipt of a prior block must exist, otherwise it means the receipt included
                    // on the primary chain points to an invalid domain block.
                    bad_receipts_to_write.push((
                        execution_receipt.primary_number,
                        execution_receipt.hash(),
                        (0u32, block_hash),
                    ));
                }
            }
        }

        let fraud_proofs = self
            .primary_chain_client
            .runtime_api()
            .extract_fraud_proofs(primary_hash, extrinsics, self.domain_id)?;

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
            crate::aux_schema::write_bad_receipt::<_, PBlock, _>(
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

    fn create_fraud_proof_for_first_unconfirmed_bad_receipt<PCB>(
        &self,
    ) -> sp_blockchain::Result<Option<FraudProof<NumberFor<PCB>, PCB::Hash>>>
    where
        PCB: BlockT,
    {
        if let Some((bad_receipt_hash, trace_mismatch_index, block_hash)) =
            crate::aux_schema::find_first_unconfirmed_bad_receipt_info::<_, Block, NumberFor<PBlock>>(
                &*self.client,
            )?
        {
            let local_receipt = crate::aux_schema::load_execution_receipt(
                &*self.client,
                block_hash,
            )?
            .ok_or_else(|| {
                sp_blockchain::Error::Backend(format!("Receipt for {block_hash:?} not found"))
            })?;

            let fraud_proof = self
                .fraud_proof_generator
                .generate_proof::<PCB>(
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
