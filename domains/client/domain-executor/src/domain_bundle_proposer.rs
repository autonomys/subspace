use crate::parent_chain::ParentChainInterface;
use crate::ExecutionReceiptFor;
use codec::Encode;
use futures::{select, FutureExt};
use sc_client_api::{AuxStore, BlockBackend};
use sc_transaction_pool_api::InPoolTransaction;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderBackend;
use sp_consensus_slots::Slot;
use sp_domains::{BundleSolution, PreliminaryBundleHeader};
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Hash as HashT, One, Saturating};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time;

pub(super) struct DomainBundleProposer<Block, Client, PBlock, PClient, TransactionPool> {
    client: Arc<Client>,
    primary_chain_client: Arc<PClient>,
    transaction_pool: Arc<TransactionPool>,
    _phantom_data: PhantomData<(Block, PBlock)>,
}

impl<Block, Client, PBlock, PClient, TransactionPool> Clone
    for DomainBundleProposer<Block, Client, PBlock, PClient, TransactionPool>
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            primary_chain_client: self.primary_chain_client.clone(),
            transaction_pool: self.transaction_pool.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

pub(super) type ProposeBundleOutput<Block, PBlock> = (
    PreliminaryBundleHeader<NumberFor<PBlock>, <PBlock as BlockT>::Hash, <Block as BlockT>::Hash>,
    ExecutionReceiptFor<PBlock, <Block as BlockT>::Hash>,
    Vec<<Block as BlockT>::Extrinsic>,
);

impl<Block, Client, PBlock, PClient, TransactionPool>
    DomainBundleProposer<Block, Client, PBlock, PClient, TransactionPool>
where
    Block: BlockT,
    PBlock: BlockT,
    NumberFor<Block>: Into<NumberFor<PBlock>>,
    Client: HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block>,
    Client::Api: BlockBuilder<Block>,
    PClient: HeaderBackend<PBlock>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
    pub(crate) fn new(
        client: Arc<Client>,
        primary_chain_client: Arc<PClient>,
        transaction_pool: Arc<TransactionPool>,
    ) -> Self {
        Self {
            client,
            primary_chain_client,
            transaction_pool,
            _phantom_data: PhantomData,
        }
    }

    pub(crate) async fn propose_bundle_at<ParentChain, ParentChainBlock>(
        &self,
        bundle_solution: BundleSolution<Block::Hash>,
        slot: Slot,
        primary_info: (PBlock::Hash, NumberFor<PBlock>),
        parent_chain: ParentChain,
    ) -> sp_blockchain::Result<ProposeBundleOutput<Block, PBlock>>
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
                    "Timeout fired waiting for transaction pool at #{parent_number}, proceeding with production."
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

        let (primary_hash, primary_number) = primary_info;

        let receipt = self.load_bundle_receipt(parent_number, parent_hash, parent_chain)?;

        let header = PreliminaryBundleHeader {
            primary_number,
            primary_hash,
            slot_number: slot.into(),
            extrinsics_root,
            bundle_solution,
        };

        Ok((header, receipt, extrinsics))
    }

    /// Returns the receipt in the next domain bundle.
    fn load_bundle_receipt<ParentChain, ParentChainBlock>(
        &self,
        header_number: NumberFor<Block>,
        header_hash: Block::Hash,
        parent_chain: ParentChain,
    ) -> sp_blockchain::Result<ExecutionReceiptFor<PBlock, Block::Hash>>
    where
        ParentChainBlock: BlockT,
        ParentChain: ParentChainInterface<Block, ParentChainBlock>,
    {
        let parent_chain_block_hash = parent_chain.best_hash();
        let head_receipt_number = parent_chain.head_receipt_number(parent_chain_block_hash)?;
        let max_drift = parent_chain.maximum_receipt_drift(parent_chain_block_hash)?;

        tracing::trace!(
            ?header_number,
            ?head_receipt_number,
            ?max_drift,
            "Collecting receipts at {parent_chain_block_hash:?}"
        );

        let load_receipt = |primary_block_hash, block_number| {
            crate::aux_schema::load_execution_receipt::<
                _,
                Block::Hash,
                NumberFor<PBlock>,
                PBlock::Hash,
            >(&*self.client, primary_block_hash)?
            .ok_or_else(|| {
                sp_blockchain::Error::Backend(format!(
                    "Receipt of primary block #{block_number},{primary_block_hash} not found"
                ))
            })
        };

        let header_block_receipt_is_written =
            crate::aux_schema::primary_hash_for::<_, _, PBlock::Hash>(&*self.client, header_hash)?
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

        let primary_block_hash = self
            .primary_chain_client
            .hash(receipt_number.into())?
            .ok_or_else(|| {
                sp_blockchain::Error::Backend(format!(
                    "Primary block hash for #{receipt_number:?} not found"
                ))
            })?;

        load_receipt(primary_block_hash, receipt_number)
    }
}
