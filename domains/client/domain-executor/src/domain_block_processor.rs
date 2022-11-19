use crate::utils::shuffle_extrinsics;
use crate::{ExecutionReceiptFor, LOG_TARGET};
use codec::{Decode, Encode};
use domain_block_builder::{BlockBuilder, BuiltBlock, RecordProof};
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use sc_client_api::{AuxStore, BlockBackend};
use sc_consensus::{
    BlockImport, BlockImportParams, ForkChoiceStrategy, ImportResult, StateAction, StorageChanges,
};
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockOrigin;
use sp_domains::{ExecutionReceipt, ExecutorApi, OpaqueBundles};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, One};
use sp_runtime::Digest;
use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::{BlockNumber, Randomness};

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
pub(crate) struct DomainBlockProcessor<Block, PBlock, Client, PClient, Backend> {
    client: Arc<Client>,
    primary_chain_client: Arc<PClient>,
    backend: Arc<Backend>,
    _phantom_data: PhantomData<(Block, PBlock)>,
}

impl<Block, PBlock, Client, PClient, Backend> Clone
    for DomainBlockProcessor<Block, PBlock, Client, PClient, Backend>
where
    Block: BlockT,
    PBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            primary_chain_client: self.primary_chain_client.clone(),
            backend: self.backend.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, PBlock, Client, PClient, Backend>
    DomainBlockProcessor<Block, PBlock, Client, PClient, Backend>
where
    Block: BlockT,
    PBlock: BlockT,
    Client:
        HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block> + 'static,
    Client::Api: DomainCoreApi<Block, AccountId>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<
            Block,
            StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
        >,
    for<'b> &'b Client: BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
{
    pub(crate) fn new(
        client: Arc<Client>,
        primary_chain_client: Arc<PClient>,
        backend: Arc<Backend>,
    ) -> Self {
        Self {
            client,
            primary_chain_client,
            backend,
            _phantom_data: PhantomData::default(),
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
                                target: LOG_TARGET,
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
        // TODO: or just Vec::new()?
        // Ideally there should be only a few duplicated transactions.
        let mut seen = Vec::with_capacity(extrinsics.len());
        extrinsics.retain(|uxt| match seen.contains(uxt) {
            true => {
                tracing::trace!(target: LOG_TARGET, extrinsic = ?uxt, "Duplicated extrinsic");
                false
            }
            false => {
                seen.push(uxt.clone());
                true
            }
        });
        drop(seen);

        tracing::trace!(
            target: LOG_TARGET,
            ?extrinsics,
            "Origin deduplicated extrinsics"
        );

        let extrinsics: Vec<_> = match self
            .client
            .runtime_api()
            .extract_signer(&BlockId::Hash(parent_hash), extrinsics)
        {
            Ok(res) => res,
            Err(e) => {
                tracing::error!(
                    target: LOG_TARGET,
                    error = ?e,
                    "Error at calling runtime api: extract_signer"
                );
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
        let primary_number: BlockNumber = primary_number
            .try_into()
            .unwrap_or_else(|_| panic!("Primary number must fit into u32; qed"));

        assert_eq!(
            Into::<NumberFor<Block>>::into(primary_number),
            parent_number + One::one(),
            "New secondary best number must be equal to the primary number"
        );

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
            target: LOG_TARGET,
            ?trace,
            ?trace_root,
            "Trace root calculated for #{}",
            header_hash
        );

        let execution_receipt = ExecutionReceipt {
            primary_number: primary_number.into(),
            primary_hash,
            secondary_hash: header_hash,
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
}
