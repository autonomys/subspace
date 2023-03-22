use crate::parent_chain::ParentChainInterface;
use crate::utils::to_number_primitive;
use crate::ExecutionReceiptFor;
use codec::Encode;
use futures::{select, FutureExt};
use sc_client_api::{AuxStore, BlockBackend};
use sc_transaction_pool_api::InPoolTransaction;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderBackend;
use sp_consensus_slots::Slot;
use sp_domains::{Bundle, BundleHeader};
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Hash as HashT, One, Zero};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time;

pub(super) struct DomainBundleProposer<Block, Client, TransactionPool> {
    client: Arc<Client>,
    transaction_pool: Arc<TransactionPool>,
    _phantom_data: PhantomData<Block>,
}

impl<Block, Client, TransactionPool> Clone
    for DomainBundleProposer<Block, Client, TransactionPool>
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            transaction_pool: self.transaction_pool.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, Client, TransactionPool> DomainBundleProposer<Block, Client, TransactionPool>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block>,
    Client::Api: BlockBuilder<Block>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
    pub(crate) fn new(client: Arc<Client>, transaction_pool: Arc<TransactionPool>) -> Self {
        Self {
            client,
            transaction_pool,
            _phantom_data: PhantomData::default(),
        }
    }

    pub(crate) async fn propose_bundle_at<PBlock, ParentChain, ParentChainBlock>(
        &self,
        slot: Slot,
        primary_info: (PBlock::Hash, NumberFor<PBlock>),
        parent_chain: ParentChain,
    ) -> sp_blockchain::Result<Bundle<Block::Extrinsic, NumberFor<PBlock>, PBlock::Hash, Block::Hash>>
    where
        PBlock: BlockT,
        ParentChainBlock: BlockT,
        ParentChain: ParentChainInterface<ParentChainBlock>,
    {
        let parent_number = self.client.info().best_number;

        let mut t1 = self.transaction_pool.ready_at(parent_number).fuse();
        // TODO: proper timeout
        let mut t2 = futures_timer::Delay::new(time::Duration::from_micros(100)).fuse();

        let pending_iterator = select! {
            res = t1 => res,
            _ = t2 => {
                tracing::warn!(
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

        let (primary_hash, primary_number) = primary_info;

        let receipts = if primary_number.is_zero() {
            Vec::new()
        } else {
            self.collect_bundle_receipts::<PBlock, _, _>(parent_number, parent_chain)?
        };

        receipts_sanity_check::<Block, PBlock>(&receipts)?;

        let bundle = Bundle {
            header: BundleHeader {
                primary_number,
                primary_hash,
                slot_number: slot.into(),
                extrinsics_root,
            },
            receipts,
            extrinsics,
        };

        Ok(bundle)
    }

    /// Returns the receipts in the next domain bundle.
    fn collect_bundle_receipts<PBlock, ParentChain, ParentChainBlock>(
        &self,
        header_number: NumberFor<Block>,
        parent_chain: ParentChain,
    ) -> sp_blockchain::Result<Vec<ExecutionReceiptFor<PBlock, Block::Hash>>>
    where
        PBlock: BlockT,
        ParentChainBlock: BlockT,
        ParentChain: ParentChainInterface<ParentChainBlock>,
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

        let mut receipts = Vec::new();
        let mut to_send = head_receipt_number + 1;
        let max_allowed = (head_receipt_number + max_drift).min(to_number_primitive(header_number));
        loop {
            let block_hash = self.client.hash(to_send.into())?.ok_or_else(|| {
                sp_blockchain::Error::Backend(format!("Hash for Block {to_send:?} not found"))
            })?;
            receipts.push(load_receipt(block_hash)?);
            to_send += 1;

            if to_send > max_allowed {
                break;
            }
        }

        Ok(receipts)
    }
}

/// Performs the sanity check in order to detect the potential invalid receipts earlier.
fn receipts_sanity_check<Block, PBlock>(
    receipts: &[ExecutionReceiptFor<PBlock, Block::Hash>],
) -> sp_blockchain::Result<()>
where
    Block: BlockT,
    PBlock: BlockT,
{
    for (i, [ref head, ref tail]) in receipts.array_windows().enumerate() {
        if head.primary_number + One::one() != tail.primary_number {
            return Err(sp_blockchain::Error::Application(Box::from(format!(
                "Found inconsecutive receipt at index {}, receipts[{i}]: {:?}, receipts[{}]: {:?}",
                i + 1,
                (head.primary_number, head.primary_hash),
                i + 1,
                (tail.primary_number, tail.primary_hash),
            ))));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::receipts_sanity_check;
    use domain_test_service::runtime::Block;
    use sp_core::H256;
    use sp_domains::ExecutionReceipt;
    use subspace_core_primitives::BlockNumber;
    use subspace_runtime_primitives::Hash;
    use subspace_test_runtime::Block as PBlock;

    fn create_dummy_receipt_for(
        primary_number: BlockNumber,
    ) -> ExecutionReceipt<BlockNumber, Hash, H256> {
        ExecutionReceipt {
            primary_number,
            primary_hash: H256::random(),
            domain_hash: H256::random(),
            trace: if primary_number == 0 {
                Vec::new()
            } else {
                vec![H256::random(), H256::random()]
            },
            trace_root: Default::default(),
        }
    }

    #[test]
    fn test_receipts_sanity_check() {
        let receipts = vec![
            create_dummy_receipt_for(1),
            create_dummy_receipt_for(2),
            create_dummy_receipt_for(4),
        ];
        assert!(receipts_sanity_check::<Block, PBlock>(&receipts).is_err());

        let receipts = vec![
            create_dummy_receipt_for(1),
            create_dummy_receipt_for(2),
            create_dummy_receipt_for(3),
        ];
        assert!(receipts_sanity_check::<Block, PBlock>(&receipts).is_ok());

        let receipts = vec![create_dummy_receipt_for(1)];
        assert!(receipts_sanity_check::<Block, PBlock>(&receipts).is_ok());

        assert!(receipts_sanity_check::<Block, PBlock>(&[]).is_ok());
    }
}
