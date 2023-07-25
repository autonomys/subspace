use crate::parent_chain::ParentChainInterface;
use crate::sortition::{TransactionSelectError, TransactionSelector};
use crate::ExecutionReceiptFor;
use codec::Encode;
use domain_runtime_primitives::DomainCoreApi;
use futures::{select, FutureExt};
use sc_client_api::{AuxStore, BlockBackend};
use sc_transaction_pool_api::InPoolTransaction;
use sp_api::{HeaderT, NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::{HashAndNumber, HeaderBackend};
use sp_domains::{BundleHeader, ExecutionReceipt, ProofOfElection};
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Hash as HashT, One, Saturating, Zero};
use sp_weights::Weight;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time;
use subspace_runtime_primitives::Balance;

pub(super) struct DomainBundleProposer<Block, Client, CBlock, CClient, TransactionPool> {
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
            client: self.client.clone(),
            consensus_client: self.consensus_client.clone(),
            transaction_pool: self.transaction_pool.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

pub(super) type ProposeBundleOutput<Block, CBlock> = (
    BundleHeader<
        NumberFor<CBlock>,
        <CBlock as BlockT>::Hash,
        NumberFor<Block>,
        <Block as BlockT>::Hash,
        Balance,
    >,
    Vec<<Block as BlockT>::Extrinsic>,
);

impl<Block, Client, CBlock, CClient, TransactionPool>
    DomainBundleProposer<Block, Client, CBlock, CClient, TransactionPool>
where
    Block: BlockT,
    CBlock: BlockT,
    NumberFor<Block>: Into<NumberFor<CBlock>>,
    Client: HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block>,
    Client::Api: BlockBuilder<Block> + DomainCoreApi<Block>,
    CClient: HeaderBackend<CBlock>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
    pub(crate) fn new(
        client: Arc<Client>,
        consensus_client: Arc<CClient>,
        transaction_pool: Arc<TransactionPool>,
    ) -> Self {
        Self {
            client,
            consensus_client,
            transaction_pool,
            _phantom_data: PhantomData,
        }
    }

    pub(crate) async fn propose_bundle_at<ParentChain, ParentChainBlock>(
        &self,
        proof_of_election: ProofOfElection<Block::Hash>,
        consensus_block_info: HashAndNumber<CBlock>,
        parent_chain: ParentChain,
        tx_selector: TransactionSelector<Block, Client>,
    ) -> sp_blockchain::Result<ProposeBundleOutput<Block, CBlock>>
    where
        ParentChainBlock: BlockT,
        ParentChain: ParentChainInterface<Block, ParentChainBlock>,
    {
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

        let domain_block_limit = parent_chain.domain_block_limit(parent_chain.best_hash())?;
        let mut extrinsics = Vec::new();
        let mut estimated_bundle_weight = Weight::default();
        let mut bundle_size = 0u32;
        for pending_tx in pending_iterator {
            let pending_tx_data = pending_tx.data().clone();
            let should_select_this_tx = tx_selector
                .should_select_tx(parent_hash, pending_tx_data.clone())
                .unwrap_or_else(|err| {
                    // Accept unsigned transactions like cross domain.
                    tracing::trace!("propose bundle: sortition select failed: {err:?}");
                    matches!(err, TransactionSelectError::TxSignerNotFound)
                });
            if should_select_this_tx {
                let tx_weight = self
                    .client
                    .runtime_api()
                    .extrinsic_weight(parent_hash, &pending_tx_data)
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
                extrinsics.push(pending_tx_data);
            }
        }

        let extrinsics_root = BlakeTwo256::ordered_trie_root(
            extrinsics.iter().map(|xt| xt.encode()).collect(),
            sp_core::storage::StateVersion::V1,
        );

        let receipt = self.load_bundle_receipt(parent_number, parent_hash, parent_chain)?;

        let header = BundleHeader {
            consensus_block_number: consensus_block_info.number,
            proof_of_election,
            receipt,
            bundle_size,
            estimated_bundle_weight,
            bundle_extrinsics_root: extrinsics_root,
        };

        Ok((header, extrinsics))
    }

    /// Returns the receipt in the next domain bundle.
    fn load_bundle_receipt<ParentChain, ParentChainBlock>(
        &self,
        header_number: NumberFor<Block>,
        header_hash: Block::Hash,
        parent_chain: ParentChain,
    ) -> sp_blockchain::Result<ExecutionReceiptFor<Block, CBlock>>
    where
        ParentChainBlock: BlockT,
        ParentChain: ParentChainInterface<Block, ParentChainBlock>,
    {
        let parent_chain_block_hash = parent_chain.best_hash();
        let head_receipt_number = parent_chain.head_receipt_number(parent_chain_block_hash)?;
        let max_drift = parent_chain.block_tree_pruning_depth(parent_chain_block_hash)?;

        tracing::trace!(
            ?header_number,
            ?head_receipt_number,
            ?max_drift,
            "Collecting receipts at {parent_chain_block_hash:?}"
        );

        let header_block_receipt_is_written = crate::aux_schema::consensus_block_hash_for::<
            _,
            _,
            CBlock::Hash,
        >(&*self.client, header_hash)?
        .is_some();

        // TODO: remove once the receipt generation can be done before the domain block is
        // committed to the database, in other words, only when the receipt of block N+1 has
        // been generated can the `client.info().best_number` be updated from N to N+1.
        //
        // This requires:
        // 1. Reimplement `runtime_api.intermediate_roots()` on the client side.
        // 2. Add a hook before the upstream `client.commit_operation(op)`.
        let available_best_receipt_number = if header_block_receipt_is_written {
            header_number
        } else {
            header_number.saturating_sub(One::one())
        };

        let receipt_number = (head_receipt_number + One::one()).min(available_best_receipt_number);

        if receipt_number.is_zero() {
            let genesis_hash = self.client.info().genesis_hash;
            let genesis_header = self.client.header(genesis_hash)?.ok_or_else(|| {
                sp_blockchain::Error::Backend(format!(
                    "Domain block header for #{genesis_hash:?} not found",
                ))
            })?;
            return Ok(ExecutionReceipt::genesis(
                self.consensus_client.info().genesis_hash,
                *genesis_header.state_root(),
            ));
        }

        let domain_hash = self.client.hash(receipt_number)?.ok_or_else(|| {
            sp_blockchain::Error::Backend(format!(
                "Domain block hash for #{receipt_number:?} not found"
            ))
        })?;

        crate::aux_schema::load_execution_receipt_by_domain_hash::<_, Block, CBlock>(
            &*self.client,
            domain_hash,
        )?
        .ok_or_else(|| {
            sp_blockchain::Error::Backend(format!(
                "Receipt of domain block #{receipt_number},{domain_hash} not found"
            ))
        })
    }
}
