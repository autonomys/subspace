use codec::Encode;
use futures::{select, FutureExt};
use sc_client_api::BlockBackend;
use sc_transaction_pool_api::InPoolTransaction;
use sp_api::ProvideRuntimeApi;
use sp_runtime::{
	generic::BlockId,
	traits::{BlakeTwo256, Block as BlockT, Hash as HashT, Header as HeaderT},
};
use std::time;

use cirrus_node_primitives::{BundleResult, ExecutorSlotInfo};
use cirrus_primitives::{AccountId, SecondaryApi};
use sp_executor::{Bundle, BundleHeader};

use subspace_runtime_primitives::Hash as PHash;

use super::{Executor, LOG_TARGET};

impl<Block, Client, TransactionPool, Backend, E>
	Executor<Block, Client, TransactionPool, Backend, E>
where
	Block: BlockT,
	Client: sp_blockchain::HeaderBackend<Block> + BlockBackend<Block> + ProvideRuntimeApi<Block>,
	Client::Api: SecondaryApi<Block, AccountId>
		+ sp_block_builder::BlockBuilder<Block>
		+ sp_api::ApiExt<
			Block,
			StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
		>,
	Backend: sc_client_api::Backend<Block>,
	TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
	pub(super) async fn produce_bundle_impl(
		self,
		_primary_hash: PHash,
		slot_info: ExecutorSlotInfo,
	) -> Option<BundleResult> {
		println!("TODO: solve some puzzle based on `slot_info` to be allowed to produce a bundle");

		let parent_number = self.client.info().best_number;

		let mut t1 = self.transaction_pool.ready_at(parent_number).fuse();
		// TODO: proper timeout
		let mut t2 = futures_timer::Delay::new(time::Duration::from_micros(100)).fuse();

		let mut pending_iterator = select! {
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

		while let Some(pending_tx) = pending_iterator.next() {
			if start.elapsed() >= pushing_duration {
				break
			}
			let pending_tx_data = pending_tx.data().clone();
			extrinsics.push(pending_tx_data);
		}

		let extrinsics_root = BlakeTwo256::ordered_trie_root(
			extrinsics.iter().map(|xt| xt.encode()).collect(),
			sp_core::storage::StateVersion::V1,
		);

		let _state_root =
			self.client.expect_header(BlockId::Number(parent_number)).ok()?.state_root();

		let bundle = Bundle {
			header: BundleHeader { slot_number: slot_info.slot.into(), extrinsics_root },
			extrinsics,
		};

		if let Err(e) = self.bundle_sender.unbounded_send(bundle.clone()) {
			tracing::error!(target: LOG_TARGET, error = ?e, "Failed to send transaction bundle");
		}

		Some(BundleResult { opaque_bundle: bundle.into() })
	}
}
