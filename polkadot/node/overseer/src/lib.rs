// Copyright 2020 Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! # Overseer
//!
//! `overseer` implements the Overseer architecture described in the
//! [implementers-guide](https://w3f.github.io/parachain-implementers-guide/node/index.html).
//! For the motivations behind implementing the overseer itself you should
//! check out that guide, documentation in this crate will be mostly discussing
//! technical stuff.
//!
//! An `Overseer` is something that allows spawning/stopping and overseeing
//! asynchronous tasks as well as establishing a well-defined and easy to use
//! protocol that the tasks can use to communicate with each other. It is desired
//! that this protocol is the only way tasks communicate with each other, however
//! at this moment there are no foolproof guards against other ways of communication.
//!
//! The `Overseer` is instantiated with a pre-defined set of `Subsystems` that
//! share the same behavior from `Overseer`'s point of view.
//!
//! ```text
//!                              +-----------------------------+
//!                              |         Overseer            |
//!                              +-----------------------------+
//!
//!             ................|  Overseer "holds" these and uses |..............
//!             .                  them to (re)start things                      .
//!             .                                                                .
//!             .  +-------------------+                +---------------------+  .
//!             .  |   Subsystem1      |                |   Subsystem2        |  .
//!             .  +-------------------+                +---------------------+  .
//!             .           |                                       |            .
//!             ..................................................................
//!                         |                                       |
//!                       start()                                 start()
//!                         V                                       V
//!             ..................| Overseer "runs" these |.......................
//!             .  +--------------------+               +---------------------+  .
//!             .  | SubsystemInstance1 |               | SubsystemInstance2  |  .
//!             .  +--------------------+               +---------------------+  .
//!             ..................................................................
//! ```

// unused dependencies can not work for test and examples at the same time
// yielding false positives
#![warn(missing_docs)]
#![allow(clippy::all)]

use std::{
	collections::{hash_map, HashMap},
	fmt::Debug,
	pin::Pin,
	sync::Arc,
	time::Duration,
};

use futures::{future::BoxFuture, select, stream::FusedStream, Future, FutureExt, StreamExt};
use lru::LruCache;

use client::{BlockImportNotification, BlockchainEvents, FinalityNotification};

use polkadot_node_subsystem_types::messages::{CollationGenerationMessage, RuntimeApiMessage};
pub use polkadot_node_subsystem_types::{
	errors::{SubsystemError, SubsystemResult},
	ActivatedLeaf, ActiveLeavesUpdate, LeafStatus, OverseerSignal,
};

use cirrus_node_primitives::ExecutorSlotInfo;
use subspace_runtime_primitives::{opaque::Block, BlockNumber, Hash};

pub use polkadot_overseer_gen as gen;
pub use polkadot_overseer_gen::{
	overlord, FromOverseer, MapSubsystem, MessagePacket, SignalsReceived, SpawnNamed, Subsystem,
	SubsystemContext, SubsystemIncomingMessages, SubsystemInstance, SubsystemMeterReadouts,
	SubsystemMeters, SubsystemSender, TimeoutExt, ToOverseer,
};

/// Store 2 days worth of blocks, not accounting for forks,
/// in the LRU cache. Assumes a 6-second block time.
pub const KNOWN_LEAVES_CACHE_SIZE: usize = 2 * 24 * 3600 / 6;

/// A handle used to communicate with the [`Overseer`].
///
/// [`Overseer`]: struct.Overseer.html
#[derive(Clone)]
pub struct Handle(OverseerHandle);

impl Handle {
	/// Create a new [`Handle`].
	pub fn new(raw: OverseerHandle) -> Self {
		Self(raw)
	}

	/// Inform the `Overseer` that that some block was imported.
	pub async fn block_imported(&mut self, block: BlockInfo) {
		self.send_and_log_error(Event::BlockImported(block)).await
	}

	/// Send some message to one of the `Subsystem`s.
	pub async fn send_msg(&mut self, msg: impl Into<AllMessages>, origin: &'static str) {
		self.send_and_log_error(Event::MsgToSubsystem { msg: msg.into(), origin }).await
	}

	/// Inform the `Overseer` that a new slot was triggered.
	pub async fn slot_arrived(&mut self, slot_info: ExecutorSlotInfo) {
		self.send_and_log_error(Event::NewSlot(slot_info)).await
	}

	/// Tell `Overseer` to shutdown.
	pub async fn stop(&mut self) {
		self.send_and_log_error(Event::Stop).await;
	}

	/// Most basic operation, to stop a server.
	async fn send_and_log_error(&mut self, event: Event) {
		if self.0.send(event).await.is_err() {
			tracing::info!(target: LOG_TARGET, "Failed to send an event to Overseer");
		}
	}
}

/// An event telling the `Overseer` on the particular block
/// that has been imported or finalized.
///
/// This structure exists solely for the purposes of decoupling
/// `Overseer` code from the client code and the necessity to call
/// `HeaderBackend::block_number_from_id()`.
#[derive(Debug, Clone)]
pub struct BlockInfo {
	/// hash of the block.
	pub hash: Hash,
	/// hash of the parent block.
	pub parent_hash: Hash,
	/// block's number.
	pub number: BlockNumber,
}

impl From<BlockImportNotification<Block>> for BlockInfo {
	fn from(n: BlockImportNotification<Block>) -> Self {
		BlockInfo { hash: n.hash, parent_hash: n.header.parent_hash, number: n.header.number }
	}
}

impl From<FinalityNotification<Block>> for BlockInfo {
	fn from(n: FinalityNotification<Block>) -> Self {
		BlockInfo { hash: n.hash, parent_hash: n.header.parent_hash, number: n.header.number }
	}
}

/// An event from outside the overseer scope, such
/// as the substrate framework or user interaction.
pub enum Event {
	/// A new block was imported.
	BlockImported(BlockInfo),
	/// A new slot arrived.
	NewSlot(ExecutorSlotInfo),
	/// Message as sent to a subsystem.
	MsgToSubsystem {
		/// The actual message.
		msg: AllMessages,
		/// The originating subsystem name.
		origin: &'static str,
	},
	/// Stop the overseer on i.e. a UNIX signal.
	Stop,
}

/// Glues together the [`Overseer`] and `BlockchainEvents` by forwarding
/// import and finality notifications into the [`OverseerHandle`].
pub async fn forward_events<P: BlockchainEvents<Block>>(
	client: Arc<P>,
	mut slots: impl FusedStream<Item = ExecutorSlotInfo> + Unpin,
	mut handle: Handle,
) {
	let mut imports = client.import_notification_stream();

	loop {
		select! {
			i = imports.next() => {
				match i {
					Some(block) => {
						handle.block_imported(block.into()).await;
					}
					None => break,
				}
			},
			s = slots.next() => {
				match s {
					Some(executor_slot_info) => {
						handle.slot_arrived(executor_slot_info).await;
					}
					None => break,
				}
			}
			complete => break,
		}
	}
}

/// Create a new instance of the [`Overseer`] with a fixed set of [`Subsystem`]s.
///
/// This returns the overseer along with an [`OverseerHandle`] which can
/// be used to send messages from external parts of the codebase.
///
/// The [`OverseerHandle`] returned from this function is connected to
/// the returned [`Overseer`].
///
/// ```text
///                  +------------------------------------+
///                  |            Overseer                |
///                  +------------------------------------+
///                    /            |             |      \
///      ................. subsystems...................................
///      . +-----------+    +-----------+   +----------+   +---------+ .
///      . |           |    |           |   |          |   |         | .
///      . +-----------+    +-----------+   +----------+   +---------+ .
///      ...............................................................
///                              |
///                        probably `spawn`
///                            a `job`
///                              |
///                              V
///                         +-----------+
///                         |           |
///                         +-----------+
///
/// ```
///
/// [`Subsystem`]: trait.Subsystem.html
///
/// # Example
///
/// The [`Subsystems`] may be any type as long as they implement an expected interface.
/// Here, we create a mock validation subsystem and a few dummy ones and start the `Overseer` with them.
/// For the sake of simplicity the termination of the example is done with a timeout.
/// ```
/// # use std::time::Duration;
/// # use futures::{executor, pin_mut, select, FutureExt};
/// # use futures_timer::Delay;
/// # use polkadot_primitives::v1::Hash;
/// # use polkadot_overseer::{
/// # 	self as overseer,
/// #   OverseerSignal,
/// # 	SubsystemSender as _,
/// # 	AllMessages,
/// # 	HeadSupportsParachains,
/// # 	Overseer,
/// # 	SubsystemError,
/// # 	gen::{
/// # 		SubsystemContext,
/// # 		FromOverseer,
/// # 		SpawnedSubsystem,
/// # 	},
/// # };
/// # use polkadot_node_subsystem_types::messages::{
/// # 	CandidateValidationMessage, CandidateBackingMessage,
/// # 	NetworkBridgeMessage,
/// # };
///
/// struct ValidationSubsystem;
///
/// impl<Ctx> overseer::Subsystem<Ctx, SubsystemError> for ValidationSubsystem
/// where
///     Ctx: overseer::SubsystemContext<
///				Message=CandidateValidationMessage,
///				AllMessages=AllMessages,
///				Signal=OverseerSignal,
///				Error=SubsystemError,
///			>,
/// {
///     fn start(
///         self,
///         mut ctx: Ctx,
///     ) -> SpawnedSubsystem<SubsystemError> {
///         SpawnedSubsystem {
///             name: "validation-subsystem",
///             future: Box::pin(async move {
///                 loop {
///                     Delay::new(Duration::from_secs(1)).await;
///                 }
///             }),
///         }
///     }
/// }
///
/// # fn main() { executor::block_on(async move {
///
/// struct AlwaysSupportsParachains;
/// impl HeadSupportsParachains for AlwaysSupportsParachains {
///      fn head_supports_parachains(&self, _head: &Hash) -> bool { true }
/// }
/// let spawner = sp_core::testing::TaskExecutor::new();
/// let (overseer, _handle) = dummy_overseer_builder(spawner, AlwaysSupportsParachains, None)
///		.unwrap()
///		.replace_candidate_validation(|_| ValidationSubsystem)
///		.build()
///		.unwrap();
///
/// let timer = Delay::new(Duration::from_millis(50)).fuse();
///
/// let overseer_fut = overseer.run().fuse();
/// pin_mut!(timer);
/// pin_mut!(overseer_fut);
///
/// select! {
///     _ = overseer_fut => (),
///     _ = timer => (),
/// }
/// #
/// # 	});
/// # }
/// ```
#[overlord(
	gen=AllMessages,
	event=Event,
	signal=OverseerSignal,
	error=SubsystemError,
)]
pub struct Overseer {
	#[subsystem(no_dispatch, blocking, RuntimeApiMessage)]
	runtime_api: RuntimeApi,

	#[subsystem(no_dispatch, CollationGenerationMessage)]
	collation_generation: CollationGeneration,

	/// A set of leaves that `Overseer` starts working with.
	///
	/// Drained at the beginning of `run` and never used again.
	pub leaves: Vec<(Hash, BlockNumber)>,

	/// The set of the "active leaves".
	pub active_leaves: HashMap<Hash, BlockNumber>,

	/// An LRU cache for keeping track of relay-chain heads that have already been seen.
	pub known_leaves: LruCache<Hash, ()>,
}

impl<S> Overseer<S>
where
	S: SpawnNamed,
{
	/// Stop the overseer.
	async fn stop(mut self) {
		let _ = self.wait_terminate(OverseerSignal::Conclude, Duration::from_secs(1_u64)).await;
	}

	/// Run the `Overseer`.
	pub async fn run(mut self) -> SubsystemResult<()> {
		// Notify about active leaves on startup before starting the loop
		for (hash, number) in std::mem::take(&mut self.leaves) {
			let _ = self.active_leaves.insert(hash, number);
			if let Some(status) = self.on_head_activated(&hash) {
				let update = ActiveLeavesUpdate::start_work(ActivatedLeaf { hash, number, status });
				self.broadcast_signal(OverseerSignal::ActiveLeaves(update)).await?;
			}
		}

		loop {
			select! {
				msg = self.events_rx.select_next_some() => {
					match msg {
						Event::MsgToSubsystem { msg, origin } => {
							self.route_message(msg, origin).await?;
						}
						Event::Stop => {
							self.stop().await;
							return Ok(());
						}
						Event::BlockImported(block) => {
							self.block_imported(block).await?;
						}
						Event::NewSlot(slot_info) => {
							self.on_new_slot(slot_info).await?;
						}
					}
				},
				msg = self.to_overseer_rx.select_next_some() => {
					match msg {
						ToOverseer::SpawnJob { name, subsystem, s } => {
							self.spawn_job(name, subsystem, s);
						}
					}
				},
				res = self.running_subsystems.select_next_some() => {
					tracing::error!(
						target: LOG_TARGET,
						subsystem = ?res,
						"subsystem finished unexpectedly",
					);
					self.stop().await;
					return res;
				},
			}
		}
	}

	async fn block_imported(&mut self, block: BlockInfo) -> SubsystemResult<()> {
		match self.active_leaves.entry(block.hash) {
			hash_map::Entry::Vacant(entry) => entry.insert(block.number),
			hash_map::Entry::Occupied(entry) => {
				debug_assert_eq!(*entry.get(), block.number);
				return Ok(())
			},
		};

		let mut update = match self.on_head_activated(&block.hash) {
			Some(status) => ActiveLeavesUpdate::start_work(ActivatedLeaf {
				hash: block.hash,
				number: block.number,
				status,
			}),
			None => ActiveLeavesUpdate::default(),
		};

		if let Some(number) = self.active_leaves.remove(&block.parent_hash) {
			debug_assert_eq!(block.number.saturating_sub(1), number);
			update.deactivated.push(block.parent_hash);
		}

		self.clean_up_external_listeners();

		if !update.is_empty() {
			self.broadcast_signal(OverseerSignal::ActiveLeaves(update)).await?;
		}
		Ok(())
	}

	async fn on_new_slot(&mut self, slot_info: ExecutorSlotInfo) -> SubsystemResult<()> {
		self.broadcast_signal(OverseerSignal::NewSlot(slot_info)).await?;
		Ok(())
	}

	/// Handles a header activation. If the header's state doesn't support the parachains API,
	/// this returns `None`.
	fn on_head_activated(&mut self, hash: &Hash) -> Option<LeafStatus> {
		let status = if self.known_leaves.put(*hash, ()).is_some() {
			LeafStatus::Stale
		} else {
			LeafStatus::Fresh
		};

		Some(status)
	}

	fn clean_up_external_listeners(&mut self) {}

	fn spawn_job(
		&mut self,
		task_name: &'static str,
		subsystem_name: Option<&'static str>,
		j: BoxFuture<'static, ()>,
	) {
		self.spawner.spawn(task_name, subsystem_name, j);
	}
}
