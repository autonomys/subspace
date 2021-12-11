// Copyright 2019-2021 Parity Technologies (UK) Ltd.
// This file is part of Cumulus.

// Cumulus is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Cumulus is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Cumulus.  If not, see <http://www.gnu.org/licenses/>.

use sc_client_api::{
	Backend, BlockBackend, BlockImportNotification, BlockchainEvents, Finalizer, UsageProvider,
};
use sc_consensus::{BlockImport, BlockImportParams, ForkChoiceStrategy};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{Error as ClientError, HeaderBackend, Result as ClientResult};
use sp_consensus::{BlockOrigin, BlockStatus};
use sp_runtime::{
	generic::BlockId,
	traits::{Block as BlockT, Header as HeaderT},
	SaturatedConversion,
};

use codec::{Decode, Encode};
use futures::{future, select, FutureExt, Stream, StreamExt};

use std::{pin::Pin, sync::Arc};

use sp_executor::ExecutorApi;
use subspace_runtime_primitives::{opaque::Block as PBlock, BlockNumber};

/// Helper for the relay chain client. This is expected to be a lightweight handle like an `Arc`.
pub trait RelaychainClient: Clone + 'static {
	/// The error type for interacting with the Polkadot client.
	type Error: std::fmt::Debug + Send;

	/// A stream that yields head-data for a parachain.
	type HeadStream: Stream<Item = Vec<u8>> + Send + Unpin;

	/// Get a stream of new best heads for the given parachain.
	fn new_best_heads<Block: BlockT, SecondaryClient: HeaderBackend<Block> + 'static>(
		&self,
		client: Arc<SecondaryClient>,
	) -> Self::HeadStream;

	fn executor_head_at(
		&self,
		at: &BlockId<PBlock>,
		number: BlockNumber,
	) -> ClientResult<Option<Vec<u8>>>;
}

/// Run the parachain consensus.
///
/// This will follow the given `relay_chain` to act as consesus for the parachain that corresponds
/// to the given `para_id`. It will set the new best block of the parachain as it gets aware of it.
/// The same happens for the finalized block.
///
/// # Note
///
/// This will access the backend of the parachain and thus, this future should be spawned as blocking
/// task.
pub async fn run_parachain_consensus<P, R, Block, B>(
	parachain: Arc<P>,
	relay_chain: R,
	announce_block: Arc<dyn Fn(Block::Hash, Option<Vec<u8>>) + Send + Sync>,
) where
	Block: BlockT,
	P: Finalizer<Block, B>
		+ UsageProvider<Block>
		+ Send
		+ Sync
		+ 'static
		+ BlockBackend<Block>
		+ HeaderBackend<Block>
		+ BlockchainEvents<Block>,
	for<'a> &'a P: BlockImport<Block>,
	R: RelaychainClient,
	B: Backend<Block>,
{
	let follow_new_best = follow_new_best(parachain.clone(), relay_chain.clone(), announce_block);

	select! {
		_ = follow_new_best.fuse() => {},
	}
}

/// Follow the relay chain new best head, to update the Parachain new best head.
async fn follow_new_best<P, R, Block, B>(
	parachain: Arc<P>,
	relay_chain: R,
	announce_block: Arc<dyn Fn(Block::Hash, Option<Vec<u8>>) + Send + Sync>,
) where
	Block: BlockT,
	P: Finalizer<Block, B>
		+ UsageProvider<Block>
		+ Send
		+ Sync
		+ 'static
		+ BlockBackend<Block>
		+ HeaderBackend<Block>
		+ BlockchainEvents<Block>,
	for<'a> &'a P: BlockImport<Block>,
	R: RelaychainClient,
	B: Backend<Block>,
{
	let mut new_best_heads = relay_chain.new_best_heads(parachain.clone()).fuse();
	let mut imported_blocks = parachain.import_notification_stream().fuse();
	// The unset best header of the parachain. Will be `Some(_)` when we have imported a relay chain
	// block before the parachain block it included. In this case we need to wait for this block to
	// be imported to set it as new best.
	let mut unset_best_header = None;

	loop {
		select! {
			h = new_best_heads.next() => {
				match h {
					Some(h) => handle_new_best_parachain_head_subspace(
						h,
						&*parachain,
						&mut unset_best_header,
					).await,
					None => {
						tracing::debug!(
							target: "cirrus::consensus",
							"Stopping following new best.",
						);
						return
					}
				}
			},
			i = imported_blocks.next() => {
				match i {
					Some(i) => handle_new_block_imported(
						i,
						&mut unset_best_header,
						&*parachain,
						&*announce_block,
					).await,
					None => {
						tracing::debug!(
							target: "cirrus::consensus",
							"Stopping following imported blocks.",
						);
						return
					}
				}
			},
		}
	}
}

/// Handle a new import block of the parachain.
async fn handle_new_block_imported<Block, P>(
	notification: BlockImportNotification<Block>,
	unset_best_header_opt: &mut Option<Block::Header>,
	parachain: &P,
	announce_block: &(dyn Fn(Block::Hash, Option<Vec<u8>>) + Send + Sync),
) where
	Block: BlockT,
	P: UsageProvider<Block> + Send + Sync + BlockBackend<Block>,
	for<'a> &'a P: BlockImport<Block>,
{
	// HACK
	//
	// Remove after https://github.com/paritytech/substrate/pull/8052 or similar is merged
	if notification.origin != BlockOrigin::Own {
		announce_block(notification.hash, None);
	}

	let unset_best_header = match (notification.is_new_best, &unset_best_header_opt) {
		// If this is the new best block or we don't have any unset block, we can end it here.
		(true, _) | (_, None) => return,
		(false, Some(ref u)) => u,
	};

	let unset_hash = if notification.header.number() < unset_best_header.number() {
		return
	} else if notification.header.number() == unset_best_header.number() {
		let unset_hash = unset_best_header.hash();

		if unset_hash != notification.hash {
			return
		} else {
			unset_hash
		}
	} else {
		unset_best_header.hash()
	};

	match parachain.block_status(&BlockId::Hash(unset_hash)) {
		Ok(BlockStatus::InChainWithState) => {
			let unset_best_header = unset_best_header_opt
				.take()
				.expect("We checked above that the value is set; qed");

			import_block_as_new_best(unset_hash, unset_best_header, parachain).await;
		},
		state => tracing::debug!(
			target: "cirrus::consensus",
			?unset_best_header,
			?notification.header,
			?state,
			"Unexpected state for unset best header.",
		),
	}
}

/// Handle the new best parachain head as extracted from the new best relay chain.
async fn handle_new_best_parachain_head_subspace<Block, P>(
	encoded_head_hash: Vec<u8>,
	parachain: &P,
	unset_best_header: &mut Option<Block::Header>,
) where
	Block: BlockT,
	P: UsageProvider<Block> + Send + Sync + BlockBackend<Block> + HeaderBackend<Block>,
	for<'a> &'a P: BlockImport<Block>,
{
	let parachain_head_hash = match <<<Block as BlockT>::Header as HeaderT>::Hash>::decode(
		&mut &encoded_head_hash[..],
	) {
		Ok(header) => header,
		Err(err) => {
			tracing::debug!(
				target: "cirrus::consensus",
				error = ?err,
				"Could not decode Parachain header while following best heads.",
			);
			return
		},
	};

	let parachain_head = match parachain.header(BlockId::Hash(parachain_head_hash)) {
		Ok(Some(head)) => head,
		Ok(None) => {
			tracing::error!(
				target: "cirrus::consensus",
				?parachain_head_hash,
				"Parachain header does not exist",
			);
			return;
		}
		Err(e) => {
			tracing::error!(
				target: "cirrus::consensus",
				?parachain_head_hash,
				error = ?e,
				"Could not fetch Parachain header",
			);
			return;
		}
	};

	let hash = parachain_head.hash();

	if parachain.usage_info().chain.best_hash == hash {
		tracing::debug!(
			target: "cirrus::consensus",
			block_hash = ?hash,
			usage_info = ?parachain.usage_info(),
			"Skipping set new best block, because block is already the best.",
		)
	} else {
		// Make sure the block is already known or otherwise we skip setting new best.
		match parachain.block_status(&BlockId::Hash(hash)) {
			Ok(BlockStatus::InChainWithState) => {
				unset_best_header.take();

				import_block_as_new_best(hash, parachain_head, parachain).await;
			},
			Ok(BlockStatus::InChainPruned) => {
				tracing::error!(
					target: "cirrus::consensus",
					block_hash = ?hash,
					"Trying to set pruned block as new best!",
				);
			},
			Ok(BlockStatus::Unknown) => {
				*unset_best_header = Some(parachain_head);

				tracing::debug!(
					target: "cirrus::consensus",
					block_hash = ?hash,
					"Parachain block not yet imported, waiting for import to enact as best block.",
				);
			},
			Err(e) => {
				tracing::error!(
					target: "cirrus::consensus",
					block_hash = ?hash,
					error = ?e,
					"Failed to get block status of block.",
				);
			},
			_ => {},
		}
	}
}

async fn import_block_as_new_best<Block, P>(hash: Block::Hash, header: Block::Header, parachain: &P)
where
	Block: BlockT,
	P: UsageProvider<Block> + Send + Sync + BlockBackend<Block>,
	for<'a> &'a P: BlockImport<Block>,
{
	let best_number = parachain.usage_info().chain.best_number;
	if *header.number() < best_number {
		tracing::debug!(
			target: "cirrus::consensus",
			%best_number,
			block_number = %header.number(),
			"Skipping importing block as new best block, because there already exists a \
			 best block with an higher number",
		);
		return
	}

	// Make it the new best block
	let mut block_import_params = BlockImportParams::new(BlockOrigin::ConsensusBroadcast, header);
	block_import_params.fork_choice = Some(ForkChoiceStrategy::Custom(true));
	block_import_params.import_existing = true;

	if let Err(err) = (&*parachain).import_block(block_import_params, Default::default()).await {
		tracing::warn!(
			target: "cirrus::consensus",
			block_hash = ?hash,
			error = ?err,
			"Failed to set new best block.",
		);
	}
}

impl<T> RelaychainClient for Arc<T>
where
	T: sc_client_api::BlockchainEvents<PBlock> + ProvideRuntimeApi<PBlock> + 'static + Send + Sync,
	<T as ProvideRuntimeApi<PBlock>>::Api: sp_executor::ExecutorApi<PBlock>,
{
	type Error = ClientError;

	type HeadStream = Pin<Box<dyn Stream<Item = Vec<u8>> + Send>>;

	fn new_best_heads<
		Block: BlockT,
		SecondaryClient: sp_blockchain::HeaderBackend<Block> + 'static,
	>(
		&self,
		client: Arc<SecondaryClient>,
	) -> Self::HeadStream {
		let relay_chain = self.clone();

		self.import_notification_stream()
			.filter_map(move |n| {
				future::ready(if n.is_new_best {
					let best_number = client.info().best_number;
					let pending_number = best_number.saturated_into::<BlockNumber>() + 1;
					relay_chain
						.executor_head_at(&BlockId::hash(n.hash), pending_number)
						.ok()
						.flatten()
				} else {
					None
				})
			})
			.boxed()
	}

	fn executor_head_at(
		&self,
		at: &BlockId<PBlock>,
		number: BlockNumber,
	) -> ClientResult<Option<Vec<u8>>> {
		self.runtime_api()
			.head_hash(at, number)
			.map(|h| h.map(|h| h.encode()))
			.map_err(Into::into)
	}
}
