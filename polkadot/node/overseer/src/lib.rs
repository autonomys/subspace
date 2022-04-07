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

use sc_client_api::{BlockImportNotification, BlockchainEvents, FinalityNotification};

pub use polkadot_node_subsystem_types::errors::SubsystemError;
use polkadot_node_subsystem_types::{
	errors::SubsystemResult, messages::CollationGenerationMessage, ActivatedLeaf,
	ActiveLeavesUpdate, LeafStatus, OverseerSignal,
};

use cirrus_node_primitives::{CollationGenerationConfig, ExecutorSlotInfo};
use sp_executor::{BundleEquivocationProof, FraudProof, InvalidTransactionProof};
use subspace_runtime_primitives::{opaque::Block, BlockNumber, Hash};

pub use polkadot_overseer_gen::Subsystem;
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
	async fn send_msg(&mut self, msg: CollationGenerationMessage, origin: &'static str) {
		self.send_and_log_error(Event::MsgToSubsystem { msg: msg.into(), origin }).await
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
		self.send_msg(CollationGenerationMessage::Initialize(config), "StartCollator")
			.await;
	}

	/// TODO
	pub async fn submit_bundle_equivocation_proof(
		&mut self,
		bundle_equivocation_proof: BundleEquivocationProof,
	) {
		self.send_msg(
			CollationGenerationMessage::BundleEquivocationProof(bundle_equivocation_proof),
			"SubmitBundleEquivocationProof",
		)
		.await
	}

	/// TODO
	pub async fn submit_fraud_proof(&mut self, fraud_proof: FraudProof) {
		self.send_msg(CollationGenerationMessage::FraudProof(fraud_proof), "SubmitFraudProof")
			.await;
	}

	/// TODO
	pub async fn submit_invalid_transaction_proof(
		&mut self,
		invalid_transaction_proof: InvalidTransactionProof,
	) {
		self.send_msg(
			CollationGenerationMessage::InvalidTransactionProof(invalid_transaction_proof),
			"SubmitInvalidTransactionProof",
		)
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
	MsgToSubsystem {
		/// The actual message.
		msg: CollationGenerationMessage,
		/// The originating subsystem name.
		origin: &'static str,
	},
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
	collation_generation: OverseenSubsystem,
	/// A user specified addendum field.
	pub leaves: Vec<(Hash, BlockNumber)>,
	/// A user specified addendum field.
	pub active_leaves: HashMap<Hash, BlockNumber>,
	/// A user specified addendum field.
	pub known_leaves: LruCache<Hash, ()>,
	/// The set of running subsystems.
	running_subsystems: polkadot_overseer_gen::FuturesUnordered<
		BoxFuture<'static, ::std::result::Result<(), SubsystemError>>,
	>,
	/// Events that are sent to the overseer from the outside world.
	events_rx: polkadot_overseer_gen::metered::MeteredReceiver<Event>,
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
		::std::mem::drop(self.collation_generation.send_signal(signal.clone()).await);
		let _ = signal;
		let mut timeout_fut = polkadot_overseer_gen::Delay::new(timeout).fuse();
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
		let _ = self.collation_generation.send_signal(signal.clone()).await;
		let _ = signal;
		Ok(())
	}
	/// Route a particular message to a subsystem that consumes the message.
	pub async fn route_message(
		&mut self,
		message: CollationGenerationMessage,
		origin: &'static str,
	) -> ::std::result::Result<(), SubsystemError> {
		OverseenSubsystem::send_message2(&mut self.collation_generation, message, origin).await?;
		Ok(())
	}
}
impl Overseer {
	/// Create a new overseer utilizing the builder.
	pub fn builder<S, CollationGeneration>(
		collation_generation: CollationGeneration,
	) -> OverseerBuilder<S, CollationGeneration>
	where
		S: SpawnNamed,
		CollationGeneration: Subsystem<SubsystemError>,
	{
		OverseerBuilder::new(collation_generation)
	}
}
/// Handle for an overseer.
pub type OverseerHandle = polkadot_overseer_gen::metered::MeteredSender<Event>;
/// External connector.
pub struct OverseerConnector {
	/// Publicly accessible handle, to be used for setting up
	/// components that are _not_ subsystems but access is needed
	/// due to other limitations.
	///
	/// For subsystems, use the `_with` variants of the builder.
	handle: OverseerHandle,
	/// The side consumed by the `spawned` side of the overseer pattern.
	consumer: polkadot_overseer_gen::metered::MeteredReceiver<Event>,
}
impl ::std::default::Default for OverseerConnector {
	fn default() -> Self {
		let (events_tx, events_rx) =
			polkadot_overseer_gen::metered::channel::<Event>(SIGNAL_CHANNEL_CAPACITY);
		Self { handle: events_tx, consumer: events_rx }
	}
}
/// Initialization type to be used for a field of the overseer.
#[allow(missing_docs)]
pub struct OverseerBuilder<S, CollationGeneration> {
	collation_generation: CollationGeneration,
	leaves: ::std::option::Option<Vec<(Hash, BlockNumber)>>,
	active_leaves: ::std::option::Option<HashMap<Hash, BlockNumber>>,
	known_leaves: ::std::option::Option<LruCache<Hash, ()>>,
	spawner: ::std::option::Option<S>,
}
impl<S, CollationGeneration> OverseerBuilder<S, CollationGeneration>
where
	S: SpawnNamed,
	CollationGeneration: Subsystem<SubsystemError>,
{
	fn new(collation_generation: CollationGeneration) -> Self {
		fn trait_from_must_be_implemented<E>()
		where
			E: std::error::Error
				+ Send
				+ Sync
				+ 'static
				+ From<polkadot_overseer_gen::OverseerError>,
		{
		}
		trait_from_must_be_implemented::<SubsystemError>();
		Self {
			collation_generation,
			leaves: None,
			active_leaves: None,
			known_leaves: None,
			spawner: None,
		}
	}
	/// The spawner to use for spawning tasks.
	pub fn spawner(mut self, spawner: S) -> Self
	where
		S: SpawnNamed + Send,
	{
		self.spawner = Some(spawner);
		self
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
			polkadot_overseer_gen::metered::channel::<MessagePacket>(CHANNEL_CAPACITY);
		let spawner = self.spawner.expect("Spawner is set. qed");
		let running_subsystems = polkadot_overseer_gen::FuturesUnordered::<
			BoxFuture<'static, ::std::result::Result<(), SubsystemError>>,
		>::new();
		let collation_generation = self.collation_generation;
		let (signal_tx, signal_rx) =
			polkadot_overseer_gen::metered::channel(SIGNAL_CHANNEL_CAPACITY);
		let subsystem_string = String::from(stringify!(collation_generation));
		let subsystem_static_str = Box::leak(subsystem_string.replace("_", "-").into_boxed_str());
		let ctx = OverseerSubsystemContext::new(signal_rx, collation_generation_rx);
		let collation_generation: OverseenSubsystem = {
			let polkadot_overseer_gen::SpawnedSubsystem { future, name } =
				collation_generation.start(ctx);
			let (tx, rx) = polkadot_overseer_gen::oneshot::channel();
			let fut = Box::pin(async move {
				if let Err(e) = future.await {
					polkadot_overseer_gen :: tracing :: error!
					(subsystem = name, err = ? e, "subsystem exited with error");
				} else {
					polkadot_overseer_gen::tracing::debug!(
						subsystem = name,
						"subsystem exited without an error"
					);
				}
				let _ = tx.send(());
			});
			spawner.spawn(name, Some(subsystem_static_str), fut);
			running_subsystems.push(Box::pin(rx.map(|e| {
				tracing :: warn! (err = ? e, "dropping error");
				Ok(())
			})));
			let instance = Some(SubsystemInstance {
				tx_signal: signal_tx,
				tx_bounded: collation_generation_tx,
				signals_received: 0,
				name,
			});

			OverseenSubsystem { instance }
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
/// A subsystem that the overseer oversees.
///
/// Ties together the [`Subsystem`] itself and it's running instance
/// (which may be missing if the [`Subsystem`] is not running at the moment
/// for whatever reason).
///
/// [`Subsystem`]: trait.Subsystem.html
pub struct OverseenSubsystem {
	/// The instance.
	pub instance: std::option::Option<polkadot_overseer_gen::SubsystemInstance<OverseerSignal>>,
}
impl OverseenSubsystem {
	/// Send a message to the wrapped subsystem.
	///
	/// If the inner `instance` is `None`, nothing is happening.
	pub async fn send_message2(
		&mut self,
		message: CollationGenerationMessage,
		origin: &'static str,
	) -> ::std::result::Result<(), SubsystemError> {
		const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);
		if let Some(ref mut instance) = self.instance {
			match instance
				.tx_bounded
				.send(MessagePacket {
					signals_received: instance.signals_received,
					message: message.into(),
				})
				.timeout(MESSAGE_TIMEOUT)
				.await
			{
				None => {
					polkadot_overseer_gen :: tracing :: error!
					(target : LOG_TARGET, % origin,
                    "Subsystem {} appears unresponsive.", instance.name,);
					Err(SubsystemError::from(
						polkadot_overseer_gen::OverseerError::SubsystemStalled(instance.name),
					))
				},
				Some(res) => res.map_err(Into::into),
			}
		} else {
			Ok(())
		}
	}
	/// Send a signal to the wrapped subsystem.
	///
	/// If the inner `instance` is `None`, nothing is happening.
	pub async fn send_signal(
		&mut self,
		signal: OverseerSignal,
	) -> ::std::result::Result<(), SubsystemError> {
		const SIGNAL_TIMEOUT: ::std::time::Duration = ::std::time::Duration::from_secs(10);
		if let Some(ref mut instance) = self.instance {
			match instance.tx_signal.send(signal).timeout(SIGNAL_TIMEOUT).await {
				None => Err(SubsystemError::from(
					polkadot_overseer_gen::OverseerError::SubsystemStalled(instance.name),
				)),
				Some(res) => {
					let res = res.map_err(Into::into);
					if res.is_ok() {
						instance.signals_received += 1;
					}
					res
				},
			}
		} else {
			Ok(())
		}
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
	signals: polkadot_overseer_gen::metered::MeteredReceiver<OverseerSignal>,
	messages: polkadot_overseer_gen::metered::MeteredReceiver<MessagePacket>,
	signals_received: SignalsReceived,
	pending_incoming: Option<(usize, CollationGenerationMessage)>,
}
impl OverseerSubsystemContext {
	/// Create a new context.
	fn new(
		signals: polkadot_overseer_gen::metered::MeteredReceiver<OverseerSignal>,
		messages: polkadot_overseer_gen::metered::MeteredReceiver<MessagePacket>,
	) -> Self {
		let signals_received = SignalsReceived::default();
		OverseerSubsystemContext { signals, messages, signals_received, pending_incoming: None }
	}
}
impl OverseerSubsystemContext {
	async fn recv(
		&mut self,
	) -> ::std::result::Result<FromOverseer<OverseerSignal>, SubsystemError> {
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
			let from_overseer = polkadot_overseer_gen::futures::select_biased! {
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
						Event::MsgToSubsystem { msg, origin } => {
							self.route_message(msg, origin).await?;
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
