use crate::fraud_proof::{find_trace_mismatch, FraudProofGenerator};
use crate::TransactionFor;
use codec::{Decode, Encode};
use domain_block_builder::{BlockBuilder, BuiltBlock, RecordProof};
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sc_client_api::{AuxStore, BlockBackend};
use sc_consensus::{
    BlockImport, BlockImportParams, ForkChoiceStrategy, ImportResult, StateAction, StorageChanges,
};
use sc_network::NetworkService;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus::{BlockOrigin, SyncOracle};
use sp_core::traits::{CodeExecutor, SpawnNamed};
use sp_domain_digests::AsPredigest;
use sp_domain_tracker::StateRootUpdate;
use sp_domains::{DomainId, ExecutionReceipt, ExecutorApi, OpaqueBundle};
use sp_keystore::SyncCryptoStorePtr;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, HashFor, Header as HeaderT, One};
use sp_runtime::Digest;
use std::borrow::Cow;
use std::collections::{BTreeMap, VecDeque};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::{BlockNumber, Randomness};
use system_runtime_primitives::SystemDomainApi;

const LOG_TARGET: &str = "bundle-processor";

/// Shuffles the extrinsics in a deterministic way.
///
/// The extrinsics are grouped by the signer. The extrinsics without a signer, i.e., unsigned
/// extrinsics, are considered as a special group. The items in different groups are cross shuffled,
/// while the order of items inside the same group is still maintained.
fn shuffle_extrinsics<Extrinsic: Debug>(
    extrinsics: Vec<(Option<AccountId>, Extrinsic)>,
    shuffling_seed: Randomness,
) -> Vec<Extrinsic> {
    let mut rng = ChaCha8Rng::from_seed(shuffling_seed);

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

    tracing::trace!(
        target: LOG_TARGET,
        ?shuffled_extrinsics,
        "Shuffled extrinsics"
    );

    shuffled_extrinsics
}

pub(crate) struct CoreBundleProcessor<Block, SBlock, PBlock, Client, SClient, PClient, Backend, E>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
{
    domain_id: DomainId,
    primary_chain_client: Arc<PClient>,
    primary_network: Arc<NetworkService<PBlock, PBlock::Hash>>,
    system_domain_client: Arc<SClient>,
    client: Arc<Client>,
    backend: Arc<Backend>,
    is_authority: bool,
    keystore: SyncCryptoStorePtr,
    spawner: Box<dyn SpawnNamed + Send + Sync>,
    fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, Backend, E>,
    _phantom_data: PhantomData<(SBlock, PBlock)>,
}

impl<Block, SBlock, PBlock, Client, SClient, PClient, Backend, E> Clone
    for CoreBundleProcessor<Block, SBlock, PBlock, SClient, Client, PClient, Backend, E>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            primary_chain_client: self.primary_chain_client.clone(),
            primary_network: self.primary_network.clone(),
            system_domain_client: self.system_domain_client.clone(),
            client: self.client.clone(),
            backend: self.backend.clone(),
            is_authority: self.is_authority,
            keystore: self.keystore.clone(),
            spawner: self.spawner.clone(),
            fraud_proof_generator: self.fraud_proof_generator.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

type CoreBundles<Block, PBlock> =
    Vec<OpaqueBundle<NumberFor<PBlock>, <PBlock as BlockT>::Hash, <Block as BlockT>::Hash>>;

impl<Block, SBlock, PBlock, Client, SClient, PClient, Backend, E>
    CoreBundleProcessor<Block, SBlock, PBlock, Client, SClient, PClient, Backend, E>
where
    Block: BlockT,
    SBlock: BlockT,
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
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api:
        DomainCoreApi<SBlock, AccountId> + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    PClient: HeaderBackend<PBlock> + BlockBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash> + 'static,
    Backend: sc_client_api::Backend<Block> + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    E: CodeExecutor,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        domain_id: DomainId,
        primary_chain_client: Arc<PClient>,
        primary_network: Arc<NetworkService<PBlock, PBlock::Hash>>,
        system_domain_client: Arc<SClient>,
        client: Arc<Client>,
        backend: Arc<Backend>,
        is_authority: bool,
        keystore: SyncCryptoStorePtr,
        spawner: Box<dyn SpawnNamed + Send + Sync>,
        fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, Backend, E>,
    ) -> Self {
        Self {
            domain_id,
            primary_chain_client,
            primary_network,
            system_domain_client,
            client,
            backend,
            is_authority,
            keystore,
            spawner,
            fraud_proof_generator,
            _phantom_data: PhantomData::default(),
        }
    }

    // TODO: Handle the returned error properly, ref to https://github.com/subspace/subspace/pull/695#discussion_r926721185
    pub(crate) async fn process_bundles(
        self,
        (primary_hash, primary_number, fork_choice): (
            PBlock::Hash,
            NumberFor<PBlock>,
            ForkChoiceStrategy,
        ),
        bundles: CoreBundles<Block, PBlock>,
        shuffling_seed: Randomness,
        maybe_new_runtime: Option<Cow<'static, [u8]>>,
    ) -> Result<(), sp_blockchain::Error> {
        let parent_hash = self.client.info().best_hash;
        let parent_number = self.client.info().best_number;

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
                bundles,
                shuffling_seed,
                maybe_new_runtime,
                fork_choice,
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

        // TODO: just make it compile for now, likely wrong, rethink about it.
        let system_domain_hash = self.system_domain_client.info().best_hash;

        let best_execution_chain_number = self
            .system_domain_client
            .runtime_api()
            .best_execution_chain_number(&BlockId::Hash(system_domain_hash), self.domain_id)?;

        let best_execution_chain_number: BlockNumber = best_execution_chain_number
            .try_into()
            .unwrap_or_else(|_| panic!("Primary number must fit into u32; qed"));

        let best_execution_chain_number = best_execution_chain_number.into();

        assert!(
            header_number > best_execution_chain_number,
            "Consensus chain number must larger than execution chain number by at least 1"
        );

        crate::aux_schema::write_execution_receipt::<_, Block, PBlock>(
            &*self.client,
            (header_hash, header_number),
            best_execution_chain_number,
            &execution_receipt,
        )?;

        // TODO: The applied txs can be fully removed from the transaction pool

        self.check_receipts_in_primary_block(primary_hash)?;

        if self.primary_network.is_major_syncing() {
            tracing::debug!(
                target: LOG_TARGET,
                "Skip checking the receipts as the primary node is still major syncing..."
            );
            return Ok(());
        }

        // Submit fraud proof for the first unconfirmed incorrent ER.
        let oldest_receipt_number = self
            .system_domain_client
            .runtime_api()
            .oldest_receipt_number(&BlockId::Hash(system_domain_hash), self.domain_id)?;
        crate::aux_schema::prune_expired_bad_receipts(&*self.client, oldest_receipt_number)?;

        self.try_submit_fraud_proof_for_first_unconfirmed_bad_receipt()?;

        Ok(())
    }

    async fn build_and_import_block(
        &self,
        parent_hash: Block::Hash,
        parent_number: NumberFor<Block>,
        bundles: CoreBundles<Block, PBlock>,
        shuffling_seed: Randomness,
        maybe_new_runtime: Option<Cow<'static, [u8]>>,
        fork_choice: ForkChoiceStrategy,
    ) -> Result<(Block::Hash, NumberFor<Block>, Block::Hash), sp_blockchain::Error> {
        let mut extrinsics = self.bundles_to_extrinsics(parent_hash, bundles, shuffling_seed)?;

        if let Some(new_runtime) = maybe_new_runtime {
            let encoded_set_code = self
                .client
                .runtime_api()
                .construct_set_code_extrinsic(&BlockId::Hash(parent_hash), new_runtime.to_vec())?;
            let set_code_extrinsic =
                Block::Extrinsic::decode(&mut encoded_set_code.as_slice()).unwrap();
            extrinsics.push(set_code_extrinsic);
        }

        // include the latest state root of the system domain
        let system_domain_hash = self.system_domain_client.info().best_hash;
        let digests = self
            .system_domain_client
            .header(BlockId::Hash(system_domain_hash))?
            .map(|header| {
                let item = AsPredigest::system_domain_state_root_update(StateRootUpdate {
                    number: *header.number(),
                    state_root: *header.state_root(),
                });

                Digest { logs: vec![item] }
            })
            .unwrap_or_default();

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

    fn bundles_to_extrinsics(
        &self,
        parent_hash: Block::Hash,
        bundles: CoreBundles<Block, PBlock>,
        shuffling_seed: Randomness,
    ) -> Result<Vec<Block::Extrinsic>, sp_blockchain::Error> {
        let mut extrinsics = bundles
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
            .collect::<Vec<_>>();

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

    fn check_receipts_in_primary_block(
        &self,
        primary_hash: PBlock::Hash,
    ) -> Result<(), sp_blockchain::Error> {
        let extrinsics = self
            .primary_chain_client
            .block_body(primary_hash)?
            .ok_or_else(|| {
                sp_blockchain::Error::Backend(format!(
                    "Primary block body for {:?} not found",
                    primary_hash
                ))
            })?;

        // TODO: extract the receipts specific to this domain.
        let receipts = self.primary_chain_client.runtime_api().extract_receipts(
            &BlockId::Hash(primary_hash),
            extrinsics.clone(),
            self.domain_id,
        )?;

        let mut bad_receipts_to_write = vec![];

        for execution_receipt in receipts.iter() {
            let secondary_hash = execution_receipt.secondary_hash;
            match crate::aux_schema::load_execution_receipt::<
                _,
                Block::Hash,
                NumberFor<PBlock>,
                PBlock::Hash,
            >(&*self.client, secondary_hash)?
            {
                Some(local_receipt) => {
                    if let Some(trace_mismatch_index) =
                        find_trace_mismatch(&local_receipt, execution_receipt)
                    {
                        bad_receipts_to_write.push((
                            execution_receipt.primary_number,
                            execution_receipt.hash(),
                            (trace_mismatch_index, secondary_hash),
                        ));
                    }
                }
                None => {
                    let block_number: BlockNumber = execution_receipt
                        .primary_number
                        .try_into()
                        .unwrap_or_else(|_| panic!("Primary number must fit into u32; qed"));

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
                    target: LOG_TARGET,
                    error = ?e,
                    ?bad_receipt_number,
                    ?bad_signed_bundle_hash,
                    "Failed to delete bad receipt",
                );
            }
        }

        Ok(())
    }

    fn try_submit_fraud_proof_for_first_unconfirmed_bad_receipt(
        &self,
    ) -> Result<(), sp_blockchain::Error> {
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

            // TODO: self.system_domain_client.runtime_api().submit_fraud_proof_unsigned()
            self.primary_chain_client
                .runtime_api()
                .submit_fraud_proof_unsigned(
                    &BlockId::Hash(self.primary_chain_client.info().best_hash),
                    fraud_proof,
                )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_keyring::sr25519::Keyring;
    use sp_runtime::traits::{BlakeTwo256, Hash as HashT};

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

        let dummy_seed = BlakeTwo256::hash_of(&[1u8; 64]).into();
        let shuffled_extrinsics = shuffle_extrinsics(extrinsics, dummy_seed);

        assert_eq!(
            shuffled_extrinsics,
            vec![100, 30, 10, 1, 11, 101, 31, 12, 102, 2]
        );
    }
}
