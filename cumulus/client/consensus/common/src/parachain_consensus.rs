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
use sp_blockchain::HeaderBackend;
use sp_consensus::{BlockOrigin, BlockStatus};
use sp_runtime::{
	generic::BlockId,
	traits::{Block as BlockT, Header as HeaderT},
};

use futures::{select, StreamExt};

use std::sync::Arc;

/// Run the parachain consensus.
///
/// This will follow the given `relay_chain` to act as consensus for the parachain that corresponds
/// to the given `para_id`. It will set the new best block of the parachain as it gets aware of it.
/// The same happens for the finalized block.
///
/// # Note
///
/// This will access the backend of the parachain and thus, this future should be spawned as blocking
/// task.
pub async fn run_parachain_consensus<P, Block, B>(parachain: Arc<P>)
where
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
	B: Backend<Block>,
{
	let mut imported_blocks = parachain.import_notification_stream().fuse();
	// The unset best header of the parachain. Will be `Some(_)` when we have imported a relay chain
	// block before the parachain block it included. In this case we need to wait for this block to
	// be imported to set it as new best.
	let mut unset_best_header = None;

	loop {
		select! {
			i = imported_blocks.next() => {
				match i {
					Some(i) => handle_new_block_imported(
						i,
						&mut unset_best_header,
						&*parachain,
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
) where
	Block: BlockT,
	P: UsageProvider<Block> + Send + Sync + BlockBackend<Block>,
	for<'a> &'a P: BlockImport<Block>,
{
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
