use crate::worker::ExecutorSlotInfo;
use crate::{BundleSender, ExecutionReceiptFor};
use codec::{Decode, Encode};
use futures::{select, FutureExt};
use sc_client_api::{AuxStore, BlockBackend, ProofProvider};
use sc_transaction_pool_api::InPoolTransaction;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderBackend;
use sp_core::H256;
use sp_domains::{
    calculate_bundle_election_threshold, derive_bundle_election_solution,
    is_election_solution_within_threshold, make_local_randomness_transcript_data, well_known_keys,
    Bundle, BundleElectionParams, BundleHeader, ExecutorApi, ExecutorPublicKey, ExecutorSignature,
    ProofOfElection, SignedBundle, SignedOpaqueBundle, StakeWeight,
};
use sp_keystore::{SyncCryptoStore, SyncCryptoStorePtr};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Hash as HashT, Header as HeaderT, Zero};
use sp_runtime::RuntimeAppPublic;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time;
use subspace_core_primitives::{Blake2b256Hash, BlockNumber};
use system_runtime_primitives::{AccountId, SecondaryApi};

const LOG_TARGET: &str = "bundle-producer";

pub(super) struct BundleProducer<Block, PBlock, Client, PClient, TransactionPool>
where
    Block: BlockT,
    PBlock: BlockT,
{
    primary_chain_client: Arc<PClient>,
    client: Arc<Client>,
    transaction_pool: Arc<TransactionPool>,
    bundle_sender: Arc<BundleSender<Block, PBlock>>,
    is_authority: bool,
    keystore: SyncCryptoStorePtr,
    _phantom_data: PhantomData<PBlock>,
}

impl<Block, PBlock, Client, PClient, TransactionPool> Clone
    for BundleProducer<Block, PBlock, Client, PClient, TransactionPool>
where
    Block: BlockT,
    PBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            primary_chain_client: self.primary_chain_client.clone(),
            client: self.client.clone(),
            transaction_pool: self.transaction_pool.clone(),
            bundle_sender: self.bundle_sender.clone(),
            is_authority: self.is_authority,
            keystore: self.keystore.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, PBlock, Client, PClient, TransactionPool>
    BundleProducer<Block, PBlock, Client, PClient, TransactionPool>
where
    Block: BlockT,
    PBlock: BlockT,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>,
    Client::Api: SecondaryApi<Block, AccountId> + BlockBuilder<Block>,
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock>,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
    pub(super) fn new(
        primary_chain_client: Arc<PClient>,
        client: Arc<Client>,
        transaction_pool: Arc<TransactionPool>,
        bundle_sender: Arc<BundleSender<Block, PBlock>>,
        is_authority: bool,
        keystore: SyncCryptoStorePtr,
    ) -> Self {
        Self {
            primary_chain_client,
            client,
            transaction_pool,
            bundle_sender,
            is_authority,
            keystore,
            _phantom_data: PhantomData::default(),
        }
    }

    pub(super) async fn produce_bundle(
        self,
        primary_hash: PBlock::Hash,
        slot_info: ExecutorSlotInfo,
    ) -> Result<
        Option<SignedOpaqueBundle<NumberFor<PBlock>, PBlock::Hash, Block::Hash>>,
        sp_blockchain::Error,
    > {
        let ExecutorSlotInfo {
            slot,
            slot_randomness,
        } = slot_info;

        let parent_number = self.client.info().best_number;

        let mut t1 = self.transaction_pool.ready_at(parent_number).fuse();
        // TODO: proper timeout
        let mut t2 = futures_timer::Delay::new(time::Duration::from_micros(100)).fuse();

        let pending_iterator = select! {
            res = t1 => res,
            _ = t2 => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "Timeout fired waiting for transaction pool at #{}, proceeding with production.",
                    parent_number,
                );
                self.transaction_pool.ready()
            }
        };

        // TODO: proper deadline
        let pushing_duration = time::Duration::from_micros(500);

        let start = time::Instant::now();

        // TODO: Select transactions properly from the transaction pool
        //
        // Selection policy:
        // - minimize the transaction equivocation.
        // - maximize the executor computation power.
        let mut extrinsics = Vec::new();

        for pending_tx in pending_iterator {
            if start.elapsed() >= pushing_duration {
                break;
            }
            let pending_tx_data = pending_tx.data().clone();
            extrinsics.push(pending_tx_data);
        }

        let extrinsics_root = BlakeTwo256::ordered_trie_root(
            extrinsics.iter().map(|xt| xt.encode()).collect(),
            sp_core::storage::StateVersion::V1,
        );

        let _state_root = self
            .client
            .expect_header(BlockId::Number(parent_number))?
            .state_root();

        let receipts = if self
            .primary_chain_client
            .expect_block_number_from_id(&BlockId::Hash(primary_hash))?
            .is_zero()
        {
            Vec::new()
        } else {
            self.expected_receipts_on_primary_chain(primary_hash, parent_number)?
        };

        let bundle = Bundle {
            header: BundleHeader {
                primary_hash,
                slot_number: slot.into(),
                extrinsics_root,
            },
            receipts,
            extrinsics,
        };

        let best_hash = self.client.info().best_hash;

        if let Some(proof_of_election) =
            self.solve_bundle_election_challenge(best_hash, slot_randomness)?
        {
            tracing::info!(target: LOG_TARGET, "📦 Claimed bundle at slot {slot}");

            let to_sign = bundle.hash();
            match SyncCryptoStore::sign_with(
                &*self.keystore,
                ExecutorPublicKey::ID,
                &proof_of_election.executor_public_key.clone().into(),
                to_sign.as_ref(),
            ) {
                Ok(Some(signature)) => {
                    let signed_bundle = SignedBundle {
                        bundle,
                        proof_of_election,
                        signature: ExecutorSignature::decode(&mut signature.as_slice()).map_err(
                            |err| {
                                sp_blockchain::Error::Application(Box::from(format!(
                                    "Failed to decode the signature of bundle: {err}"
                                )))
                            },
                        )?,
                    };

                    // TODO: Re-enable the bundle gossip over X-Net when the compact bundle is supported.
                    // if let Err(e) = self.bundle_sender.unbounded_send(signed_bundle.clone()) {
                    // tracing::error!(target: LOG_TARGET, error = ?e, "Failed to send transaction bundle");
                    // }

                    Ok(Some(signed_bundle.into_signed_opaque_bundle()))
                }
                Ok(None) => Err(sp_blockchain::Error::Application(Box::from(
                    "This should not happen as the existence of key was just checked",
                ))),
                Err(error) => Err(sp_blockchain::Error::Application(Box::from(format!(
                    "Error occurred when signing the bundle: {error}"
                )))),
            }
        } else {
            Ok(None)
        }
    }

    fn solve_bundle_election_challenge(
        &self,
        best_hash: Block::Hash,
        slot_randomness: Blake2b256Hash,
    ) -> sp_blockchain::Result<Option<ProofOfElection>> {
        let best_block_id = BlockId::Hash(best_hash);

        let BundleElectionParams {
            authorities,
            total_stake_weight,
            slot_probability,
        } = self
            .client
            .runtime_api()
            .bundle_elections_params(&best_block_id)?;

        assert!(
            total_stake_weight
                == authorities
                    .iter()
                    .map(|(_, weight)| weight)
                    .sum::<StakeWeight>(),
            "Total stake weight mismatches, which must be a bug in the runtime"
        );

        let transcript_data = make_local_randomness_transcript_data(&slot_randomness);

        for (authority_id, stake_weight) in authorities {
            if let Ok(Some(vrf_signature)) = SyncCryptoStore::sr25519_vrf_sign(
                &*self.keystore,
                ExecutorPublicKey::ID,
                authority_id.as_ref(),
                transcript_data.clone(),
            ) {
                // TODO: specify domain_id properly.
                const SYSTEM_DOMAIN_ID: u64 = 0;

                let election_solution = derive_bundle_election_solution(
                    vrf_signature.output.to_bytes(),
                    &authority_id,
                    &slot_randomness,
                )
                .map_err(|err| {
                    sp_blockchain::Error::Application(Box::from(format!(
                        "Failed to derive bundle election solution: {err}",
                    )))
                })?;

                let threshold = calculate_bundle_election_threshold(
                    stake_weight,
                    total_stake_weight,
                    slot_probability,
                );

                if is_election_solution_within_threshold(election_solution, threshold) {
                    let storage_keys = well_known_keys::bundle_election_storage_keys();
                    // TODO: bench how large the storage proof we can afford and try proving a single
                    // electioned executor storage instead of the whole authority set.
                    let storage_proof = self.client.read_proof(
                        &best_block_id,
                        &mut storage_keys.iter().map(|s| s.as_slice()),
                    )?;

                    let state_root = *self
                        .client
                        .header(best_block_id)?
                        .expect("Best block header must exist; qed")
                        .state_root();
                    let state_root =
                        H256::decode(&mut state_root.encode().as_slice()).map_err(|err| {
                            sp_blockchain::Error::Application(Box::from(format!(
                                "Failed to decode state root({state_root:?}) into H256: {err}",
                            )))
                        })?;

                    let proof_of_election = ProofOfElection {
                        domain_id: SYSTEM_DOMAIN_ID,
                        vrf_output: vrf_signature.output.to_bytes(),
                        vrf_proof: vrf_signature.proof.to_bytes(),
                        executor_public_key: authority_id,
                        slot_randomness,
                        state_root,
                        storage_proof,
                    };

                    return Ok(Some(proof_of_election));
                }
            }
        }

        Ok(None)
    }

    fn expected_receipts_on_primary_chain(
        &self,
        primary_hash: PBlock::Hash,
        header_number: NumberFor<Block>,
    ) -> sp_blockchain::Result<Vec<ExecutionReceiptFor<PBlock, Block::Hash>>> {
        let best_execution_chain_number = self
            .primary_chain_client
            .runtime_api()
            .best_execution_chain_number(&BlockId::Hash(primary_hash))?;

        let best_execution_chain_number: BlockNumber = best_execution_chain_number
            .try_into()
            .unwrap_or_else(|_| panic!("Primary number must fit into u32; qed"));

        let load_receipt = |block_hash| {
            crate::aux_schema::load_execution_receipt::<
                _,
                Block::Hash,
                NumberFor<PBlock>,
                PBlock::Hash,
            >(&*self.client, block_hash)?
            .ok_or_else(|| {
                sp_blockchain::Error::Backend(format!("Receipt not found for {block_hash}"))
            })
        };

        let header_number: BlockNumber = header_number
            .try_into()
            .unwrap_or_else(|_| panic!("Secondary number must fit into u32; qed"));

        // Ideally, the receipt of current block will be included in the next block, i.e., no
        // missing receipts.
        let receipts = if header_number == best_execution_chain_number + 1 {
            let block_hash = self.client.hash(header_number.into())?.ok_or_else(|| {
                sp_blockchain::Error::Backend(format!(
                    "Hash for Block {:?} not found",
                    header_number
                ))
            })?;
            vec![load_receipt(block_hash)?]
        } else {
            // Receipts for some previous blocks are missing.
            let max_drift = self
                .primary_chain_client
                .runtime_api()
                .maximum_receipt_drift(&BlockId::Hash(primary_hash))?;

            let max_drift: BlockNumber = max_drift
                .try_into()
                .unwrap_or_else(|_| panic!("Primary number must fit into u32; qed"));

            let max_allowed = (best_execution_chain_number + max_drift).min(header_number);

            let mut to_send = best_execution_chain_number + 1;
            let mut receipts = Vec::with_capacity((max_allowed - to_send + 1) as usize);
            while to_send <= max_allowed {
                let block_hash = self.client.hash(to_send.into())?.ok_or_else(|| {
                    sp_blockchain::Error::Backend(format!("Hash for Block {:?} not found", to_send))
                })?;
                receipts.push(load_receipt(block_hash)?);
                to_send += 1;
            }
            receipts
        };

        Ok(receipts)
    }
}
