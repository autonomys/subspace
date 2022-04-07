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

pub mod collation_generation;
mod polkadot_node_subsystem_types;
mod polkadot_overseer_gen;

use std::{
	collections::{hash_map, HashMap},
	fmt::Debug,
	sync::Arc,
	time::Duration,
};

use futures::{future::BoxFuture, select, stream::FusedStream, FutureExt, StreamExt};
use lru::LruCache;
use sp_core::traits::SpawnNamed;

use sc_client_api::{
	BlockBackend, BlockImportNotification, BlockchainEvents, FinalityNotification,
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;

use crate::collation_generation::CollationGenerationMessage;
pub use polkadot_node_subsystem_types::errors::SubsystemError;
use polkadot_node_subsystem_types::{
	errors::SubsystemResult, ActivatedLeaf, ActiveLeavesUpdate, LeafStatus, OverseerSignal,
};

use cirrus_node_primitives::{CollationGenerationConfig, ExecutorSlotInfo};
use sp_executor::{BundleEquivocationProof, ExecutorApi, FraudProof, InvalidTransactionProof};
use subspace_runtime_primitives::{opaque::Block, BlockNumber, Hash};

use polkadot_overseer_gen::{
	FromOverseer, MessagePacket, SignalsReceived, SubsystemInstance, TimeoutExt,
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
	async fn block_imported(&mut self, block: BlockInfo) {
		self.send_and_log_error(Event::BlockImported(block)).await
	}

	/// Send some message to one of the `Subsystem`s.
	async fn send_msg(&mut self, msg: CollationGenerationMessage) {
		self.send_and_log_error(Event::MsgToSubsystem(msg)).await
	}

	/// Inform the `Overseer` that a new slot was triggered.
	async fn slot_arrived(&mut self, slot_info: ExecutorSlotInfo) {
		self.send_and_log_error(Event::NewSlot(slot_info)).await
	}

	/// Most basic operation, to stop a server.
	async fn send_and_log_error(&mut self, event: Event) {
		if self.0.send(event).await.is_err() {
			tracing::info!(target: LOG_TARGET, "Failed to send an event to Overseer");
		}
	}

	/// TODO
	pub async fn initialize(&mut self, config: CollationGenerationConfig) {
		self.send_msg(CollationGenerationMessage::Initialize(config)).await;
	}

	/// TODO
	pub async fn submit_bundle_equivocation_proof(
		&mut self,
		bundle_equivocation_proof: BundleEquivocationProof,
	) {
		self.send_msg(CollationGenerationMessage::BundleEquivocationProof(
			bundle_equivocation_proof,
		))
		.await
	}

	/// TODO
	pub async fn submit_fraud_proof(&mut self, fraud_proof: FraudProof) {
		self.send_msg(CollationGenerationMessage::FraudProof(fraud_proof)).await;
	}

	/// TODO
	pub async fn submit_invalid_transaction_proof(
		&mut self,
		invalid_transaction_proof: InvalidTransactionProof,
	) {
		self.send_msg(CollationGenerationMessage::InvalidTransactionProof(
			invalid_transaction_proof,
		))
		.await;
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
	MsgToSubsystem(CollationGenerationMessage),
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

// SystemTime { tv_sec: 1649250089, tv_nsec: 861080098 }
/// Capacity of a bounded message channel between overseer and subsystem
/// but also for bounded channels between two subsystems.
const CHANNEL_CAPACITY: usize = 1024usize;
/// Capacity of a signal channel between a subsystem and the overseer.
const SIGNAL_CHANNEL_CAPACITY: usize = 64usize;
/// The log target tag.
const LOG_TARGET: &'static str = "overseer";
/// The overseer.
pub struct Overseer {
	/// A subsystem instance.
	collation_generation: polkadot_overseer_gen::SubsystemInstance,
	/// A user specified addendum field.
	pub leaves: Vec<(Hash, BlockNumber)>,
	/// A user specified addendum field.
	pub active_leaves: HashMap<Hash, BlockNumber>,
	/// A user specified addendum field.
	pub known_leaves: LruCache<Hash, ()>,
	/// The set of running subsystems.
	running_subsystems: futures::stream::FuturesUnordered<
		BoxFuture<'static, ::std::result::Result<(), SubsystemError>>,
	>,
	/// Events that are sent to the overseer from the outside world.
	events_rx: metered::MeteredReceiver<Event>,
}
impl Overseer {
	/// Send the given signal, a termination signal, to all subsystems
	/// and wait for all subsystems to go down.
	///
	/// The definition of a termination signal is up to the user and
	/// implementation specific.
	pub async fn wait_terminate(
		&mut self,
		signal: OverseerSignal,
		timeout: ::std::time::Duration,
	) -> ::std::result::Result<(), SubsystemError> {
		::std::mem::drop(self.broadcast_signal(signal).await);
		let mut timeout_fut = futures_timer::Delay::new(timeout).fuse();
		loop {
			select! {
				_ = self.running_subsystems.next() => if
				self.running_subsystems.is_empty() { break ; }, _ =
				timeout_fut => break, complete => break,
			}
		}
		Ok(())
	}
	/// Broadcast a signal to all subsystems.
	pub async fn broadcast_signal(
		&mut self,
		signal: OverseerSignal,
	) -> ::std::result::Result<(), SubsystemError> {
		const SIGNAL_TIMEOUT: ::std::time::Duration = ::std::time::Duration::from_secs(10);
		match self.collation_generation.tx_signal.send(signal).timeout(SIGNAL_TIMEOUT).await {
			None =>
				Err(SubsystemError::from(polkadot_overseer_gen::OverseerError::SubsystemStalled(
					self.collation_generation.name,
				))),
			Some(res) => {
				let res = res.map_err(Into::into);
				if res.is_ok() {
					self.collation_generation.signals_received += 1;
				}
				res
			},
		}
	}
	/// Route a particular message to a subsystem that consumes the message.
	pub async fn send_message(
		&mut self,
		message: CollationGenerationMessage,
	) -> ::std::result::Result<(), SubsystemError> {
		const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);
		match self
			.collation_generation
			.tx_bounded
			.send(MessagePacket {
				signals_received: self.collation_generation.signals_received,
				message,
			})
			.timeout(MESSAGE_TIMEOUT)
			.await
		{
			None => {
				tracing::error!(
					target: LOG_TARGET,
					"Subsystem {} appears unresponsive.",
					self.collation_generation.name,
				);
				Err(SubsystemError::from(polkadot_overseer_gen::OverseerError::SubsystemStalled(
					self.collation_generation.name,
				)))
			},
			Some(res) => res.map_err(Into::into),
		}
	}
}
impl Overseer {
	/// Create a new overseer utilizing the builder.
	pub fn builder<Client, S>(
		collation_generation: crate::collation_generation::CollationGenerationSubsystem<Client>,
		spawner: S,
	) -> OverseerBuilder<Client, S>
	where
		Client: HeaderBackend<Block>
			+ BlockBackend<Block>
			+ ProvideRuntimeApi<Block>
			+ Send
			+ 'static
			+ Sync,
		Client::Api: ExecutorApi<Block>,
		S: SpawnNamed,
	{
		OverseerBuilder::new(collation_generation, spawner)
	}
}
/// Handle for an overseer.
pub type OverseerHandle = metered::MeteredSender<Event>;
/// External connector.
pub struct OverseerConnector {
	/// Publicly accessible handle, to be used for setting up
	/// components that are _not_ subsystems but access is needed
	/// due to other limitations.
	///
	/// For subsystems, use the `_with` variants of the builder.
	handle: OverseerHandle,
	/// The side consumed by the `spawned` side of the overseer pattern.
	consumer: metered::MeteredReceiver<Event>,
}
impl ::std::default::Default for OverseerConnector {
	fn default() -> Self {
		let (events_tx, events_rx) = metered::channel::<Event>(SIGNAL_CHANNEL_CAPACITY);
		Self { handle: events_tx, consumer: events_rx }
	}
}
/// Initialization type to be used for a field of the overseer.
#[allow(missing_docs)]
pub struct OverseerBuilder<Client, S> {
	collation_generation: crate::collation_generation::CollationGenerationSubsystem<Client>,
	leaves: ::std::option::Option<Vec<(Hash, BlockNumber)>>,
	active_leaves: ::std::option::Option<HashMap<Hash, BlockNumber>>,
	known_leaves: ::std::option::Option<LruCache<Hash, ()>>,
	spawner: S,
}
impl<Client, S> OverseerBuilder<Client, S>
where
	Client: HeaderBackend<Block>
		+ BlockBackend<Block>
		+ ProvideRuntimeApi<Block>
		+ Send
		+ 'static
		+ Sync,
	Client::Api: ExecutorApi<Block>,
	S: SpawnNamed,
{
	fn new(
		collation_generation: crate::collation_generation::CollationGenerationSubsystem<Client>,
		spawner: S,
	) -> Self {
		Self {
			collation_generation,
			leaves: None,
			active_leaves: None,
			known_leaves: None,
			spawner,
		}
	}
	/// Attach the user defined addendum type.
	pub fn leaves(mut self, baggage: Vec<(Hash, BlockNumber)>) -> Self {
		self.leaves = Some(baggage);
		self
	}
	/// Attach the user defined addendum type.
	pub fn active_leaves(mut self, baggage: HashMap<Hash, BlockNumber>) -> Self {
		self.active_leaves = Some(baggage);
		self
	}
	/// Attach the user defined addendum type.
	pub fn known_leaves(mut self, baggage: LruCache<Hash, ()>) -> Self {
		self.known_leaves = Some(baggage);
		self
	}
	/// Complete the construction and create the overseer type.
	pub fn build(self) -> ::std::result::Result<(Overseer, OverseerHandle), SubsystemError> {
		let connector = OverseerConnector::default();
		self.build_with_connector(connector)
	}
	/// Complete the construction and create the overseer type based on an existing `connector`.
	pub fn build_with_connector(
		self,
		connector: OverseerConnector,
	) -> ::std::result::Result<(Overseer, OverseerHandle), SubsystemError> {
		let OverseerConnector { handle, consumer: events_rx } = connector;
		let (collation_generation_tx, collation_generation_rx) =
			metered::channel::<MessagePacket>(CHANNEL_CAPACITY);
		let running_subsystems = futures::stream::FuturesUnordered::<
			BoxFuture<'static, ::std::result::Result<(), SubsystemError>>,
		>::new();
		let collation_generation = self.collation_generation;
		let (signal_tx, signal_rx) = metered::channel(SIGNAL_CHANNEL_CAPACITY);
		let subsystem_string = String::from(stringify!(collation_generation));
		let subsystem_static_str = Box::leak(subsystem_string.replace("_", "-").into_boxed_str());
		let ctx = OverseerSubsystemContext::new(signal_rx, collation_generation_rx);
		let collation_generation = {
			let future = collation_generation.run(ctx);
			let (tx, rx) = futures::channel::oneshot::channel();
			let fut = Box::pin(async move {
				future.await;
				tracing::debug!("subsystem exited without an error");
				let _ = tx.send(());
			});
			self.spawner
				.spawn("collation-generation-subsystem", Some(subsystem_static_str), fut);
			running_subsystems.push(Box::pin(rx.map(|e| {
				tracing :: warn! (err = ? e, "dropping error");
				Ok(())
			})));
			SubsystemInstance {
				tx_signal: signal_tx,
				tx_bounded: collation_generation_tx,
				signals_received: 0,
				name: "collation-generation-subsystem",
			}
		};
		let leaves = self.leaves.expect(&format!(
			"Baggage variable `{0}` of `{1}` must be set by the user!",
			stringify!(leaves),
			stringify!(Overseer)
		));
		let active_leaves = self.active_leaves.expect(&format!(
			"Baggage variable `{0}` of `{1}` must be set by the user!",
			stringify!(active_leaves),
			stringify!(Overseer)
		));
		let known_leaves = self.known_leaves.expect(&format!(
			"Baggage variable `{0}` of `{1}` must be set by the user!",
			stringify!(known_leaves),
			stringify!(Overseer)
		));
		let overseer = Overseer {
			collation_generation,
			leaves,
			active_leaves,
			known_leaves,
			running_subsystems,
			events_rx,
		};
		Ok((overseer, handle))
	}
}
/// A context type that is given to the [`Subsystem`] upon spawning.
/// It can be used by [`Subsystem`] to communicate with other [`Subsystem`]s
/// or to spawn it's [`SubsystemJob`]s.
///
/// [`Overseer`]: struct.Overseer.html
/// [`Subsystem`]: trait.Subsystem.html
/// [`SubsystemJob`]: trait.SubsystemJob.html
#[derive(Debug)]
#[allow(missing_docs)]
pub struct OverseerSubsystemContext {
	signals: metered::MeteredReceiver<OverseerSignal>,
	messages: metered::MeteredReceiver<MessagePacket>,
	signals_received: SignalsReceived,
	pending_incoming: Option<(usize, CollationGenerationMessage)>,
}
impl OverseerSubsystemContext {
	/// Create a new context.
	fn new(
		signals: metered::MeteredReceiver<OverseerSignal>,
		messages: metered::MeteredReceiver<MessagePacket>,
	) -> Self {
		let signals_received = SignalsReceived::default();
		OverseerSubsystemContext { signals, messages, signals_received, pending_incoming: None }
	}
}
impl OverseerSubsystemContext {
	async fn recv(
		&mut self,
	) -> ::std::result::Result<polkadot_overseer_gen::FromOverseer, SubsystemError> {
		loop {
			if let Some((needs_signals_received, msg)) = self.pending_incoming.take() {
				if needs_signals_received <= self.signals_received.load() {
					return Ok(polkadot_overseer_gen::FromOverseer::Communication { msg })
				} else {
					self.pending_incoming = Some((needs_signals_received, msg));
					let signal = self.signals.next().await.ok_or(
						polkadot_overseer_gen::OverseerError::Context(
							"Signal channel is terminated and empty.".to_owned(),
						),
					)?;
					self.signals_received.inc();
					return Ok(polkadot_overseer_gen::FromOverseer::Signal(signal))
				}
			}
			let mut await_message = self.messages.next().fuse();
			let mut await_signal = self.signals.next().fuse();
			let signals_received = self.signals_received.load();
			let pending_incoming = &mut self.pending_incoming;
			let from_overseer = futures::select_biased! {
				signal = await_signal =>
				{
					let signal =
					signal.ok_or(polkadot_overseer_gen :: OverseerError ::
					Context("Signal channel is terminated and empty.".to_owned()))
					? ; polkadot_overseer_gen :: FromOverseer :: Signal(signal)
				} msg = await_message =>
				{
					let packet =
					msg.ok_or(polkadot_overseer_gen :: OverseerError ::
					Context("Message channel is terminated and empty.".to_owned()))
					? ; if packet.signals_received > signals_received
					{
						* pending_incoming =
						Some((packet.signals_received, packet.message)) ; continue ;
					} else
					{
						polkadot_overseer_gen :: FromOverseer :: Communication
						{ msg : packet.message }
					}
				}
			};
			if let polkadot_overseer_gen::FromOverseer::Signal(_) = from_overseer {
				self.signals_received.inc();
			}
			return Ok(from_overseer)
		}
	}
}
impl Overseer {
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
						Event::MsgToSubsystem(msg) => {
							self.send_message(msg).await?;
						}
						Event::BlockImported(block) => {
							self.block_imported(block).await?;
						}
						Event::NewSlot(slot_info) => {
							self.on_new_slot(slot_info).await?;
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
}
