use crate::domain_bundle_producer::ReceiptInterface;
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
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Hash as HashT, Zero};
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

    pub(crate) async fn propose_bundle_at<PBlock, R, RHash>(
        &self,
        slot: Slot,
        primary_info: (PBlock::Hash, NumberFor<PBlock>),
        receipt_interface: R,
        receipt_interface_block_hash: RHash,
    ) -> sp_blockchain::Result<Bundle<Block::Extrinsic, NumberFor<PBlock>, PBlock::Hash, Block::Hash>>
    where
        PBlock: BlockT,
        R: ReceiptInterface<RHash>,
        RHash: Copy,
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
            self.collect_bundle_receipts::<PBlock, _, _>(
                parent_number,
                receipt_interface,
                receipt_interface_block_hash,
            )?
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

        Ok(bundle)
    }

    /// Returns the receipts in the next core domain bundle.
    fn collect_bundle_receipts<PBlock, R, RHash>(
        &self,
        header_number: NumberFor<Block>,
        receipt_interface: R,
        receipt_interface_block_hash: RHash,
    ) -> sp_blockchain::Result<Vec<ExecutionReceiptFor<PBlock, Block::Hash>>>
    where
        PBlock: BlockT,
        R: ReceiptInterface<RHash>,
        RHash: Copy,
    {
        let head_receipt_number =
            receipt_interface.head_receipt_number(receipt_interface_block_hash)?;
        let max_drift = receipt_interface.maximum_receipt_drift(receipt_interface_block_hash)?;

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

        let header_number = to_number_primitive(header_number);

        // Ideally, the receipt of current block will be included in the next block, i.e., no
        // missing receipts.
        let receipts = if header_number == head_receipt_number + 1 {
            let block_hash = self.client.hash(header_number.into())?.ok_or_else(|| {
                sp_blockchain::Error::Backend(
                    format!("Hash for Block {header_number:?} not found",),
                )
            })?;
            vec![load_receipt(block_hash)?]
        } else {
            // Receipts for some previous blocks are missing.
            let max_allowed = (head_receipt_number + max_drift).min(header_number);

            let mut to_send = head_receipt_number + 1;
            let mut receipts = Vec::with_capacity((max_allowed - to_send + 1) as usize);
            while to_send <= max_allowed {
                let block_hash = self.client.hash(to_send.into())?.ok_or_else(|| {
                    sp_blockchain::Error::Backend(format!("Hash for Block {to_send:?} not found"))
                })?;
                receipts.push(load_receipt(block_hash)?);
                to_send += 1;
            }
            receipts
        };

        Ok(receipts)
    }
}
