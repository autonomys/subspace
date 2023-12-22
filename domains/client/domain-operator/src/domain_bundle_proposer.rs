use crate::ExecutionReceiptFor;
use codec::Encode;
use domain_runtime_primitives::DomainCoreApi;
use futures::{select, FutureExt};
use sc_client_api::{AuxStore, BlockBackend};
use sc_transaction_pool_api::InPoolTransaction;
use sp_api::{ApiExt, HeaderT, NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderBackend;
use sp_domains::{
    BundleHeader, DomainId, DomainsApi, ExecutionReceipt, HeaderHashingFor, ProofOfElection,
};
use sp_runtime::traits::{Block as BlockT, Hash as HashT, One, Zero};
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use sp_weights::Weight;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time;
use subspace_core_primitives::U256;
use subspace_runtime_primitives::Balance;

pub struct DomainBundleProposer<Block, Client, CBlock, CClient, TransactionPool> {
    domain_id: DomainId,
    client: Arc<Client>,
    consensus_client: Arc<CClient>,
    transaction_pool: Arc<TransactionPool>,
    _phantom_data: PhantomData<(Block, CBlock)>,
}

impl<Block, Client, CBlock, CClient, TransactionPool> Clone
    for DomainBundleProposer<Block, Client, CBlock, CClient, TransactionPool>
{
    fn clone(&self) -> Self {
        Self {
            domain_id: self.domain_id,
            client: self.client.clone(),
            consensus_client: self.consensus_client.clone(),
            transaction_pool: self.transaction_pool.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

pub(super) type ProposeBundleOutput<Block, CBlock> = (
    BundleHeader<NumberFor<CBlock>, <CBlock as BlockT>::Hash, <Block as BlockT>::Header, Balance>,
    Vec<<Block as BlockT>::Extrinsic>,
);

impl<Block, Client, CBlock, CClient, TransactionPool>
    DomainBundleProposer<Block, Client, CBlock, CClient, TransactionPool>
where
    Block: BlockT,
    CBlock: BlockT,
    NumberFor<Block>: Into<NumberFor<CBlock>>,
    Client: HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block>,
    Client::Api: BlockBuilder<Block> + DomainCoreApi<Block> + TaggedTransactionQueue<Block>,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock>,
    CClient::Api: DomainsApi<CBlock, Block::Header>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
    pub fn new(
        domain_id: DomainId,
        client: Arc<Client>,
        consensus_client: Arc<CClient>,
        transaction_pool: Arc<TransactionPool>,
    ) -> Self {
        Self {
            domain_id,
            client,
            consensus_client,
            transaction_pool,
            _phantom_data: PhantomData,
        }
    }

    pub(crate) async fn propose_bundle_at(
        &self,
        proof_of_election: ProofOfElection<CBlock::Hash>,
        tx_range: U256,
    ) -> sp_blockchain::Result<ProposeBundleOutput<Block, CBlock>> {
        let parent_number = self.client.info().best_number;
        let parent_hash = self.client.info().best_hash;

        let mut t1 = self.transaction_pool.ready_at(parent_number).fuse();
        // TODO: proper timeout
        let mut t2 = futures_timer::Delay::new(time::Duration::from_micros(100)).fuse();

        let pending_iterator = select! {
            res = t1 => res,
            _ = t2 => {
                tracing::warn!(
                    "Timeout fired waiting for transaction pool at #{parent_number},{parent_hash}, \
                    proceeding with bundle production."
                );
                self.transaction_pool.ready()
            }
        };

        let bundle_vrf_hash = U256::from_be_bytes(proof_of_election.vrf_hash());
        let domain_block_limit = self
            .consensus_client
            .runtime_api()
            .domain_block_limit(self.consensus_client.info().best_hash, self.domain_id)?
            .ok_or_else(|| {
                sp_blockchain::Error::Application(
                    format!("Domain block limit for {:?} not found", self.domain_id).into(),
                )
            })?;
        let mut extrinsics = Vec::new();
        let mut estimated_bundle_weight = Weight::default();
        let mut bundle_size = 0u32;

        // Seperate code block to make sure that runtime api instance is dropped after validation is done.
        {
            // We are using one runtime api instance here to maintain storage changes in the instance's internal buffer
            // between runtime calls done in this loop.
            let runtime_api_instance = self.client.runtime_api();
            for pending_tx in pending_iterator {
                let pending_tx_data = pending_tx.data();

                let is_within_tx_range = runtime_api_instance
                    .is_within_tx_range(parent_hash, pending_tx_data, &bundle_vrf_hash, &tx_range)
                    .map_err(|err| {
                        tracing::error!(
                            ?err,
                            ?pending_tx_data,
                            "Error occurred in locating the tx range"
                        );
                    })
                    .unwrap_or(false);
                if !is_within_tx_range {
                    continue;
                }

                let tx_weight = runtime_api_instance
                    .extrinsic_weight(parent_hash, pending_tx_data)
                    .map_err(|error| {
                        sp_blockchain::Error::Application(Box::from(format!(
                            "Error getting extrinsic weight: {error}"
                        )))
                    })?;
                let next_estimated_bundle_weight =
                    estimated_bundle_weight.saturating_add(tx_weight);
                if next_estimated_bundle_weight.any_gt(domain_block_limit.max_block_weight) {
                    break;
                }

                let next_bundle_size = bundle_size + pending_tx_data.encoded_size() as u32;
                if next_bundle_size > domain_block_limit.max_block_size {
                    break;
                }

                estimated_bundle_weight = next_estimated_bundle_weight;
                bundle_size = next_bundle_size;

                // Double check the transaction validity, because the tx pool are re-validate the transaction
                // in pool asynchronously so there is race condition that the operator imported a domain block
                // and start producing bundle immediately before the re-validation based on the latest block
                // is finished, cause the bundle contains illegal tx accidentally and being considered as invalid
                // bundle and slashing on the honest operator.
                //
                // This check is done in similar fashion to block builder's build block.
                // This check needs to be the last check as otherwise if the tx won't be part of bundle due to
                // some other checks, its side effect will still be part of RuntimeApiImpl's changes buffer.
                let transaction_validity_result =
                    runtime_api_instance.execute_in_transaction(|api| {
                        let transaction_validity_result = api.check_extrinsics_and_do_pre_dispatch(
                            parent_hash,
                            vec![pending_tx_data.clone()],
                            parent_number,
                            parent_hash,
                        );
                        // Only commit, if there are no errors (both ApiError and CheckTxValidityError)
                        if let Ok(Ok(_)) = transaction_validity_result {
                            sp_api::TransactionOutcome::Commit(transaction_validity_result)
                        } else {
                            sp_api::TransactionOutcome::Rollback(transaction_validity_result)
                        }
                    })?;
                if transaction_validity_result.is_err() {
                    continue;
                }

                extrinsics.push(pending_tx_data.clone());
            }
        }

        let extrinsics_root = HeaderHashingFor::<Block::Header>::ordered_trie_root(
            extrinsics.iter().map(|xt| xt.encode()).collect(),
            sp_core::storage::StateVersion::V1,
        );

        let receipt = self.load_bundle_receipt(parent_number)?;

        let header = BundleHeader {
            proof_of_election,
            receipt,
            bundle_size,
            estimated_bundle_weight,
            bundle_extrinsics_root: extrinsics_root,
        };

        Ok((header, extrinsics))
    }

    /// Returns the receipt in the next domain bundle.
    fn load_bundle_receipt(
        &self,
        header_number: NumberFor<Block>,
    ) -> sp_blockchain::Result<ExecutionReceiptFor<Block, CBlock>> {
        let consensus_chain_block_hash = self.consensus_client.info().best_hash;
        let head_receipt_number = self
            .consensus_client
            .runtime_api()
            .head_receipt_number(consensus_chain_block_hash, self.domain_id)?;

        // TODO: the `receipt_number` may not be the best domain block number if there
        // is fraud proof submitted and bad ERs pruned, thus the ER may not the one that
        // derive from the latest domain block, which may cause the lagging operator able
        // to submit invalid bundle accidentally.
        //
        // We need to resolve `https://github.com/subspace/subspace/issues/1673` to fix it
        // completely.
        let receipt_number = (head_receipt_number + One::one()).min(header_number);

        tracing::trace!(
            ?header_number,
            ?head_receipt_number,
            ?receipt_number,
            "Collecting receipts at {consensus_chain_block_hash:?}"
        );

        if receipt_number.is_zero() {
            let genesis_hash = self.client.info().genesis_hash;
            let genesis_header = self.client.header(genesis_hash)?.ok_or_else(|| {
                sp_blockchain::Error::Backend(format!(
                    "Domain block header for #{genesis_hash:?} not found",
                ))
            })?;

            return Ok(ExecutionReceipt::genesis(
                *genesis_header.state_root(),
                *genesis_header.extrinsics_root(),
                genesis_hash,
            ));
        }

        // Get the domain block hash corresponding to `receipt_number` in the domain canonical chain
        let domain_hash = self.client.hash(receipt_number)?.ok_or_else(|| {
            sp_blockchain::Error::Backend(format!(
                "Domain block hash for #{receipt_number:?} not found"
            ))
        })?;

        crate::load_execution_receipt_by_domain_hash::<Block, CBlock, _>(
            &*self.client,
            domain_hash,
            receipt_number,
        )
    }
}
