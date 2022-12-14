use crate::fraud_proof::{find_trace_mismatch, FraudProofGenerator};
use crate::utils::{shuffle_extrinsics, to_number_primitive};
use crate::{ExecutionReceiptFor, TransactionFor};
use codec::{Decode, Encode};
use domain_block_builder::{BlockBuilder, BuiltBlock, RecordProof};
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use sc_client_api::{AuxStore, BlockBackend, StateBackendFor};
use sc_consensus::{
    BlockImport, BlockImportParams, ForkChoiceStrategy, ImportResult, StateAction, StorageChanges,
};
use sc_network::NetworkService;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus::{BlockOrigin, SyncOracle};
use sp_core::traits::CodeExecutor;
use sp_domains::fraud_proof::FraudProof;
use sp_domains::{DomainId, ExecutionReceipt, ExecutorApi, OpaqueBundles};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, HashFor, Header as HeaderT};
use sp_runtime::Digest;
use std::borrow::Cow;
use std::sync::Arc;
use subspace_core_primitives::Randomness;

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
    primary_network: Arc<NetworkService<PBlock, PBlock::Hash>>,
    backend: Arc<Backend>,
    fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, Backend, E>,
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
            primary_network: self.primary_network.clone(),
            backend: self.backend.clone(),
            fraud_proof_generator: self.fraud_proof_generator.clone(),
        }
    }
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
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    E: CodeExecutor,
{
    pub(crate) fn new(
        domain_id: DomainId,
        client: Arc<Client>,
        primary_chain_client: Arc<PClient>,
        primary_network: Arc<NetworkService<PBlock, PBlock::Hash>>,
        backend: Arc<Backend>,
        fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, Backend, E>,
    ) -> Self {
        Self {
            domain_id,
            client,
            primary_chain_client,
            primary_network,
            backend,
            fraud_proof_generator,
        }
    }

    pub(crate) fn compile_own_domain_bundles(
        &self,
        bundles: OpaqueBundles<PBlock, Block::Hash>,
    ) -> Vec<Block::Extrinsic> {
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

    pub(crate) fn deduplicate_and_shuffle_extrinsics(
        &self,
        parent_hash: Block::Hash,
        mut extrinsics: Vec<Block::Extrinsic>,
        shuffling_seed: Randomness,
    ) -> Result<Vec<Block::Extrinsic>, sp_blockchain::Error> {
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

        let extrinsics: Vec<_> = match self
            .client
            .runtime_api()
            .extract_signer(&BlockId::Hash(parent_hash), extrinsics)
        {
            Ok(res) => res,
            Err(e) => {
                tracing::error!(error = ?e, "Error at calling runtime api: extract_signer");
                return Err(e.into());
            }
        };

        let extrinsics =
            shuffle_extrinsics::<<Block as BlockT>::Extrinsic>(extrinsics, shuffling_seed);

        Ok(extrinsics)
    }

    pub(crate) async fn process_domain_block(
        &self,
        (primary_hash, primary_number): (PBlock::Hash, NumberFor<PBlock>),
        (parent_hash, parent_number): (Block::Hash, NumberFor<Block>),
        extrinsics: Vec<Block::Extrinsic>,
        maybe_new_runtime: Option<Cow<'static, [u8]>>,
        fork_choice: ForkChoiceStrategy,
        digests: Digest,
    ) -> Result<DomainBlockResult<Block, PBlock>, sp_blockchain::Error> {
        let primary_number = to_number_primitive(primary_number);

        let (header_hash, header_number, state_root) = self
            .build_and_import_block(
                parent_hash,
                parent_number,
                extrinsics,
                maybe_new_runtime,
                fork_choice,
                digests,
            )
            .await?;

        let mut roots = self
            .client
            .runtime_api()
            .intermediate_roots(&BlockId::Hash(header_hash))?;

        let state_root = state_root
            .encode()
            .try_into()
            .expect("State root uses the same Block hash type which must fit into [u8; 32]; qed");

        roots.push(state_root);

        let trace_root = crate::merkle_tree::construct_trace_merkle_tree(roots.clone())?.root();
        let trace = roots
            .into_iter()
            .map(|r| {
                Block::Hash::decode(&mut r.as_slice())
                    .expect("Storage root uses the same Block hash type; qed")
            })
            .collect();

        tracing::debug!(
            ?trace,
            ?trace_root,
            "Trace root calculated for #{header_hash}"
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
        mut extrinsics: Vec<Block::Extrinsic>,
        maybe_new_runtime: Option<Cow<'static, [u8]>>,
        fork_choice: ForkChoiceStrategy,
        digests: Digest,
    ) -> Result<(Block::Hash, NumberFor<Block>, Block::Hash), sp_blockchain::Error> {
        if let Some(new_runtime) = maybe_new_runtime {
            let encoded_set_code = self
                .client
                .runtime_api()
                .construct_set_code_extrinsic(&BlockId::Hash(parent_hash), new_runtime.to_vec())?;
            let set_code_extrinsic =
                Block::Extrinsic::decode(&mut encoded_set_code.as_slice()).unwrap();
            extrinsics.push(set_code_extrinsic);
        }

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

        let import_result = (&*self.client)
            .import_block(block_import_params, Default::default())
            .await?;

        match import_result {
            ImportResult::Imported(..) => {}
            ImportResult::AlreadyInChain => {}
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

    pub(crate) fn on_domain_block_processed(
        &self,
        primary_hash: PBlock::Hash,
        domain_block_result: DomainBlockResult<Block, PBlock>,
        head_receipt_number: NumberFor<Block>,
        oldest_receipt_number: NumberFor<Block>,
    ) -> Result<Option<FraudProof>, sp_blockchain::Error> {
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

        self.check_receipts_in_primary_block(primary_hash)?;

        if self.primary_network.is_major_syncing() {
            tracing::debug!(
                "Skip checking the receipts as the primary node is still major syncing..."
            );
            return Ok(None);
        }

        // Submit fraud proof for the first unconfirmed incorrent ER.
        crate::aux_schema::prune_expired_bad_receipts(&*self.client, oldest_receipt_number)?;

        self.create_fraud_proof_for_first_unconfirmed_bad_receipt()
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
            &BlockId::Hash(primary_hash),
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
                            "Header hash not found for number {block_number}"
                        ))
                    })?;

                    // The receipt of a prior block must exist, otherwise it means the receipt included
                    // on the primary chain points to an invalid secondary block.
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
            .extract_fraud_proofs(&BlockId::Hash(primary_hash), extrinsics)?;

        let bad_receipts_to_delete = fraud_proofs
            .into_iter()
            .filter_map(|fraud_proof| {
                let bad_receipt_number = fraud_proof.parent_number + 1;
                let bad_bundle_hash = fraud_proof.bad_signed_bundle_hash;

                // In order to not delete a receipt which was just inserted, accumulate the write&delete operations
                // in case the bad receipt and corresponding farud proof are included in the same block.
                if let Some(index) = bad_receipts_to_write
                    .iter()
                    .map(|(_, hash, _)| hash)
                    .position(|v| *v == bad_bundle_hash)
                {
                    bad_receipts_to_write.swap_remove(index);
                    None
                } else {
                    Some((bad_receipt_number, bad_bundle_hash))
                }
            })
            .collect::<Vec<_>>();

        for (bad_receipt_number, bad_signed_bundle_hash, mismatch_info) in bad_receipts_to_write {
            crate::aux_schema::write_bad_receipt::<_, PBlock, _>(
                &*self.client,
                bad_receipt_number,
                bad_signed_bundle_hash,
                mismatch_info,
            )?;
        }

        for (bad_receipt_number, bad_signed_bundle_hash) in bad_receipts_to_delete {
            if let Err(e) = crate::aux_schema::delete_bad_receipt(
                &*self.client,
                bad_receipt_number,
                bad_signed_bundle_hash,
            ) {
                tracing::error!(
                    error = ?e,
                    ?bad_receipt_number,
                    ?bad_signed_bundle_hash,
                    "Failed to delete bad receipt"
                );
            }
        }

        Ok(())
    }

    fn create_fraud_proof_for_first_unconfirmed_bad_receipt(
        &self,
    ) -> Result<Option<FraudProof>, sp_blockchain::Error> {
        if let Some((bad_signed_bundle_hash, trace_mismatch_index, block_hash)) =
            crate::aux_schema::find_first_unconfirmed_bad_receipt_info::<_, Block, NumberFor<PBlock>>(
                &*self.client,
            )?
        {
            let local_receipt =
                crate::aux_schema::load_execution_receipt(&*self.client, block_hash)?.ok_or_else(
                    || {
                        sp_blockchain::Error::Backend(format!(
                            "Execution receipt not found for {block_hash:?}"
                        ))
                    },
                )?;

            let fraud_proof = self
                .fraud_proof_generator
                .generate_proof(trace_mismatch_index, &local_receipt, bad_signed_bundle_hash)
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
