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

use polkadot_node_subsystem_types::messages::CollationGenerationMessage;
pub use polkadot_node_subsystem_types::{
	errors::{SubsystemError, SubsystemResult},
	ActivatedLeaf, ActiveLeavesUpdate, LeafStatus, OverseerSignal,
};

use cirrus_node_primitives::ExecutorSlotInfo;
use subspace_runtime_primitives::{opaque::Block, BlockNumber, Hash};

pub use polkadot_overseer_gen as gen;
pub use polkadot_overseer_gen::{
	FromOverseer, MapSubsystem, MessagePacket, SignalsReceived, SpawnNamed, Subsystem,
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

// SystemTime { tv_sec: 1649250089, tv_nsec: 861080098 }
/// Capacity of a bounded message channel between overseer and subsystem
/// but also for bounded channels between two subsystems.
const CHANNEL_CAPACITY: usize = 1024usize;
/// Capacity of a signal channel between a subsystem and the overseer.
const SIGNAL_CHANNEL_CAPACITY: usize = 64usize;
/// The log target tag.
const LOG_TARGET: &'static str = "overseer";
/// The overseer.
pub struct Overseer<S> {
	/// A subsystem instance.
	collation_generation: OverseenSubsystem<CollationGenerationMessage>,
	/// A user specified addendum field.
	pub leaves: Vec<(Hash, BlockNumber)>,
	/// A user specified addendum field.
	pub active_leaves: HashMap<Hash, BlockNumber>,
	/// A user specified addendum field.
	pub known_leaves: LruCache<Hash, ()>,
	/// Responsible for driving the subsystem futures.
	spawner: S,
	/// The set of running subsystems.
	running_subsystems: polkadot_overseer_gen::FuturesUnordered<
		BoxFuture<'static, ::std::result::Result<(), SubsystemError>>,
	>,
	/// Gather running subsystems' outbound streams into one.
	to_overseer_rx: polkadot_overseer_gen::stream::Fuse<
		polkadot_overseer_gen::metered::UnboundedMeteredReceiver<polkadot_overseer_gen::ToOverseer>,
	>,
	/// Events that are sent to the overseer from the outside world.
	events_rx: polkadot_overseer_gen::metered::MeteredReceiver<Event>,
}
impl<S> Overseer<S>
where
	S: polkadot_overseer_gen::SpawnNamed,
{
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
		message: AllMessages,
		origin: &'static str,
	) -> ::std::result::Result<(), SubsystemError> {
		match message {
			AllMessages::CollationGeneration(inner) =>
				OverseenSubsystem::<CollationGenerationMessage>::send_message2(
					&mut self.collation_generation,
					inner,
					origin,
				)
				.await?,
			AllMessages::Empty => {},
		}
		Ok(())
	}
	/// Extract information from each subsystem.
	pub fn map_subsystems<'a, Mapper, Output>(&'a self, mapper: Mapper) -> Vec<Output>
	where
		Mapper: MapSubsystem<&'a OverseenSubsystem<CollationGenerationMessage>, Output = Output>,
	{
		vec![mapper.map_subsystem(&self.collation_generation)]
	}
	/// Get access to internal task spawner.
	pub fn spawner<'a>(&'a mut self) -> &'a mut S {
		&mut self.spawner
	}
}
impl<S> Overseer<S>
where
	S: polkadot_overseer_gen::SpawnNamed,
{
	/// Create a new overseer utilizing the builder.
	pub fn builder<CollationGeneration>() -> OverseerBuilder<S, CollationGeneration>
	where
		S: polkadot_overseer_gen::SpawnNamed,
		CollationGeneration:
			Subsystem<OverseerSubsystemContext<CollationGenerationMessage>, SubsystemError>,
	{
		OverseerBuilder::default()
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
impl OverseerConnector {
	/// Obtain access to the overseer handle.
	pub fn as_handle_mut(&mut self) -> &mut OverseerHandle {
		&mut self.handle
	}
	/// Obtain access to the overseer handle.
	pub fn as_handle(&self) -> &OverseerHandle {
		&self.handle
	}
	/// Obtain a clone of the handle.
	pub fn handle(&self) -> OverseerHandle {
		self.handle.clone()
	}
}
impl ::std::default::Default for OverseerConnector {
	fn default() -> Self {
		let (events_tx, events_rx) =
			polkadot_overseer_gen::metered::channel::<Event>(SIGNAL_CHANNEL_CAPACITY);
		Self { handle: events_tx, consumer: events_rx }
	}
}
/// Convenience alias.
type SubsystemInitFn<T> =
	Box<dyn FnOnce(OverseerHandle) -> ::std::result::Result<T, SubsystemError>>;
/// Initialization type to be used for a field of the overseer.
enum FieldInitMethod<T> {
	/// Defer initialization to a point where the `handle` is available.
	Fn(SubsystemInitFn<T>),
	/// Directly initialize the subsystem with the given subsystem type `T`.
	Value(T),
	/// Subsystem field does not have value just yet.
	Uninitialized,
}
impl<T> ::std::default::Default for FieldInitMethod<T> {
	fn default() -> Self {
		Self::Uninitialized
	}
}
#[allow(missing_docs)]
pub struct OverseerBuilder<S, CollationGeneration> {
	collation_generation: FieldInitMethod<CollationGeneration>,
	leaves: ::std::option::Option<Vec<(Hash, BlockNumber)>>,
	active_leaves: ::std::option::Option<HashMap<Hash, BlockNumber>>,
	known_leaves: ::std::option::Option<LruCache<Hash, ()>>,
	spawner: ::std::option::Option<S>,
}
impl<S, CollationGeneration> Default for OverseerBuilder<S, CollationGeneration> {
	fn default() -> Self {
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
			collation_generation: Default::default(),
			leaves: None,
			active_leaves: None,
			known_leaves: None,
			spawner: None,
		}
	}
}
impl<S, CollationGeneration> OverseerBuilder<S, CollationGeneration>
where
	S: polkadot_overseer_gen::SpawnNamed,
	CollationGeneration:
		Subsystem<OverseerSubsystemContext<CollationGenerationMessage>, SubsystemError>,
{
	/// The spawner to use for spawning tasks.
	pub fn spawner(mut self, spawner: S) -> Self
	where
		S: polkadot_overseer_gen::SpawnNamed + Send,
	{
		self.spawner = Some(spawner);
		self
	}
	/// Specify the particular subsystem implementation.
	pub fn collation_generation(mut self, subsystem: CollationGeneration) -> Self {
		self.collation_generation = FieldInitMethod::Value(subsystem);
		self
	}
	/// Specify the particular subsystem by giving a init function.
	pub fn collation_generation_with<'a, F>(mut self, subsystem_init_fn: F) -> Self
	where
		F: 'static
			+ FnOnce(OverseerHandle) -> ::std::result::Result<CollationGeneration, SubsystemError>,
	{
		self.collation_generation = FieldInitMethod::Fn(
			Box::new(subsystem_init_fn) as SubsystemInitFn<CollationGeneration>
		);
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
	pub fn build(self) -> ::std::result::Result<(Overseer<S>, OverseerHandle), SubsystemError> {
		let connector = OverseerConnector::default();
		self.build_with_connector(connector)
	}
	/// Complete the construction and create the overseer type based on an existing `connector`.
	pub fn build_with_connector(
		self,
		connector: OverseerConnector,
	) -> ::std::result::Result<(Overseer<S>, OverseerHandle), SubsystemError> {
		let OverseerConnector { handle: events_tx, consumer: events_rx } = connector;
		let handle = events_tx.clone();
		let (to_overseer_tx, to_overseer_rx) =
			polkadot_overseer_gen::metered::unbounded::<ToOverseer>();
		let (collation_generation_tx, collation_generation_rx) =
			polkadot_overseer_gen::metered::channel::<MessagePacket<CollationGenerationMessage>>(
				CHANNEL_CAPACITY,
			);
		let (collation_generation_unbounded_tx, collation_generation_unbounded_rx) =
			polkadot_overseer_gen::metered::unbounded::<MessagePacket<CollationGenerationMessage>>(
			);
		let channels_out = ChannelsOut {
			collation_generation: collation_generation_tx.clone(),
			collation_generation_unbounded: collation_generation_unbounded_tx,
		};
		let mut spawner = self.spawner.expect("Spawner is set. qed");
		let mut running_subsystems = polkadot_overseer_gen::FuturesUnordered::<
			BoxFuture<'static, ::std::result::Result<(), SubsystemError>>,
		>::new();
		let collation_generation = match self.collation_generation {
			FieldInitMethod::Fn(func) => func(handle.clone())?,
			FieldInitMethod::Value(val) => val,
			FieldInitMethod::Uninitialized => {
				panic!("All subsystems must exist with the builder pattern.")
			},
		};
		let unbounded_meter = collation_generation_unbounded_rx.meter().clone();
		let message_rx: SubsystemIncomingMessages<CollationGenerationMessage> =
			polkadot_overseer_gen::select(
				collation_generation_rx,
				collation_generation_unbounded_rx,
			);
		let (signal_tx, signal_rx) =
			polkadot_overseer_gen::metered::channel(SIGNAL_CHANNEL_CAPACITY);
		let subsystem_string = String::from(stringify!(collation_generation));
		let subsystem_static_str = Box::leak(subsystem_string.replace("_", "-").into_boxed_str());
		let ctx = OverseerSubsystemContext::<CollationGenerationMessage>::new(
			signal_rx,
			message_rx,
			channels_out.clone(),
			to_overseer_tx.clone(),
			subsystem_static_str,
		);
		let collation_generation: OverseenSubsystem<CollationGenerationMessage> =
			spawn::<_, _, Regular, _, _, _>(
				&mut spawner,
				collation_generation_tx,
				signal_tx,
				unbounded_meter,
				ctx,
				collation_generation,
				subsystem_static_str,
				&mut running_subsystems,
			)?;
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
		let to_overseer_rx = to_overseer_rx.fuse();
		let overseer = Overseer {
			collation_generation,
			leaves,
			active_leaves,
			known_leaves,
			spawner,
			running_subsystems,
			events_rx,
			to_overseer_rx,
		};
		Ok((overseer, handle))
	}
}
impl<S, CollationGeneration> OverseerBuilder<S, CollationGeneration>
where
	S: polkadot_overseer_gen::SpawnNamed,
	CollationGeneration:
		Subsystem<OverseerSubsystemContext<CollationGenerationMessage>, SubsystemError>,
{
	/// Replace a subsystem by another implementation for the
	/// consumable message type.
	pub fn replace_collation_generation<NEW, F>(
		self,
		gen_replacement_fn: F,
	) -> OverseerBuilder<S, NEW>
	where
		CollationGeneration: 'static,
		F: 'static + FnOnce(CollationGeneration) -> NEW,
		NEW: polkadot_overseer_gen::Subsystem<
			OverseerSubsystemContext<CollationGenerationMessage>,
			SubsystemError,
		>,
	{
		let Self { collation_generation, leaves, active_leaves, known_leaves, spawner } = self;
		let replacement: FieldInitMethod<NEW> = match collation_generation {
			FieldInitMethod::Fn(fx) =>
				FieldInitMethod::Fn(Box::new(move |handle: OverseerHandle| {
					let orig = fx(handle)?;
					Ok(gen_replacement_fn(orig))
				})),
			FieldInitMethod::Value(val) => FieldInitMethod::Value(gen_replacement_fn(val)),
			FieldInitMethod::Uninitialized => {
				panic!("Must have a value before it can be replaced. qed")
			},
		};
		OverseerBuilder::<S, NEW> {
			collation_generation: replacement,
			leaves,
			active_leaves,
			known_leaves,
			spawner,
		}
	}
}
/// Task kind to launch.
pub trait TaskKind {
	/// Spawn a task, it depends on the implementer if this is blocking or not.
	fn launch_task<S: SpawnNamed>(
		spawner: &mut S,
		task_name: &'static str,
		subsystem_name: &'static str,
		future: BoxFuture<'static, ()>,
	);
}
#[allow(missing_docs)]
struct Regular;
impl TaskKind for Regular {
	fn launch_task<S: SpawnNamed>(
		spawner: &mut S,
		task_name: &'static str,
		subsystem_name: &'static str,
		future: BoxFuture<'static, ()>,
	) {
		spawner.spawn(task_name, Some(subsystem_name), future)
	}
}
#[allow(missing_docs)]
struct Blocking;
impl TaskKind for Blocking {
	fn launch_task<S: SpawnNamed>(
		spawner: &mut S,
		task_name: &'static str,
		subsystem_name: &'static str,
		future: BoxFuture<'static, ()>,
	) {
		spawner.spawn(task_name, Some(subsystem_name), future)
	}
}
/// Spawn task of kind `self` using spawner `S`.
pub fn spawn<S, M, TK, Ctx, E, SubSys>(
	spawner: &mut S,
	message_tx: polkadot_overseer_gen::metered::MeteredSender<MessagePacket<M>>,
	signal_tx: polkadot_overseer_gen::metered::MeteredSender<OverseerSignal>,
	unbounded_meter: polkadot_overseer_gen::metered::Meter,
	ctx: Ctx,
	s: SubSys,
	subsystem_name: &'static str,
	futures: &mut polkadot_overseer_gen::FuturesUnordered<
		BoxFuture<'static, ::std::result::Result<(), SubsystemError>>,
	>,
) -> ::std::result::Result<OverseenSubsystem<M>, SubsystemError>
where
	S: polkadot_overseer_gen::SpawnNamed,
	M: std::fmt::Debug + Send + 'static,
	TK: TaskKind,
	Ctx: polkadot_overseer_gen::SubsystemContext<Message = M>,
	E: std::error::Error + Send + Sync + 'static + From<polkadot_overseer_gen::OverseerError>,
	SubSys: polkadot_overseer_gen::Subsystem<Ctx, E>,
{
	let polkadot_overseer_gen::SpawnedSubsystem::<E> { future, name } = s.start(ctx);
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
	<TK as TaskKind>::launch_task(spawner, name, subsystem_name, fut);
	futures.push(Box::pin(rx.map(|e| {
		tracing :: warn! (err = ? e, "dropping error");
		Ok(())
	})));
	let instance = Some(SubsystemInstance {
		meters: polkadot_overseer_gen::SubsystemMeters {
			unbounded: unbounded_meter,
			bounded: message_tx.meter().clone(),
			signals: signal_tx.meter().clone(),
		},
		tx_signal: signal_tx,
		tx_bounded: message_tx,
		signals_received: 0,
		name,
	});
	Ok(OverseenSubsystem { instance })
}
/// A subsystem that the overseer oversees.
///
/// Ties together the [`Subsystem`] itself and it's running instance
/// (which may be missing if the [`Subsystem`] is not running at the moment
/// for whatever reason).
///
/// [`Subsystem`]: trait.Subsystem.html
pub struct OverseenSubsystem<M> {
	/// The instance.
	pub instance: std::option::Option<polkadot_overseer_gen::SubsystemInstance<M, OverseerSignal>>,
}
impl<M> OverseenSubsystem<M> {
	/// Send a message to the wrapped subsystem.
	///
	/// If the inner `instance` is `None`, nothing is happening.
	pub async fn send_message2(
		&mut self,
		message: M,
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
/// Collection of channels to the individual subsystems.
///
/// Naming is from the point of view of the overseer.
#[derive(Debug, Clone)]
pub struct ChannelsOut {
	/// Bounded channel sender, connected to a subsystem.
	pub collation_generation:
		polkadot_overseer_gen::metered::MeteredSender<MessagePacket<CollationGenerationMessage>>,
	/// Unbounded channel sender, connected to a subsystem.
	pub collation_generation_unbounded: polkadot_overseer_gen::metered::UnboundedMeteredSender<
		MessagePacket<CollationGenerationMessage>,
	>,
}
#[allow(unreachable_code)]
impl ChannelsOut {
	/// Send a message via a bounded channel.
	pub async fn send_and_log_error(&mut self, signals_received: usize, message: AllMessages) {
		let res: ::std::result::Result<_, _> = match message {
			AllMessages::CollationGeneration(inner) => self
				.collation_generation
				.send(polkadot_overseer_gen::make_packet(signals_received, inner))
				.await
				.map_err(|_| stringify!(collation_generation)),
			AllMessages::Empty => Ok(()),
		};
		if let Err(subsystem_name) = res {
			polkadot_overseer_gen::tracing::debug!(
				target: LOG_TARGET,
				"Failed to send (bounded) a message to {} subsystem",
				subsystem_name
			);
		}
	}
	/// Send a message to another subsystem via an unbounded channel.
	pub fn send_unbounded_and_log_error(&self, signals_received: usize, message: AllMessages) {
		let res: ::std::result::Result<_, _> = match message {
			AllMessages::CollationGeneration(inner) => self
				.collation_generation_unbounded
				.unbounded_send(polkadot_overseer_gen::make_packet(signals_received, inner))
				.map_err(|_| stringify!(collation_generation)),
			AllMessages::Empty => Ok(()),
		};
		if let Err(subsystem_name) = res {
			polkadot_overseer_gen::tracing::debug!(
				target: LOG_TARGET,
				"Failed to send_unbounded a message to {} subsystem",
				subsystem_name
			);
		}
	}
}
/// Connector to send messages towards all subsystems,
/// while tracking the which signals where already received.
#[derive(Debug, Clone)]
pub struct OverseerSubsystemSender {
	/// Collection of channels to all subsystems.
	channels: ChannelsOut,
	/// Systemwide tick for which signals were received by all subsystems.
	signals_received: SignalsReceived,
}
/// implementation for wrapping message type...
#[polkadot_overseer_gen::async_trait]
impl SubsystemSender<AllMessages> for OverseerSubsystemSender {
	async fn send_message(&mut self, msg: AllMessages) {
		self.channels.send_and_log_error(self.signals_received.load(), msg).await;
	}
	async fn send_messages<T>(&mut self, msgs: T)
	where
		T: IntoIterator<Item = AllMessages> + Send,
		T::IntoIter: Send,
	{
		for msg in msgs {
			self.send_message(msg).await;
		}
	}
	fn send_unbounded_message(&mut self, msg: AllMessages) {
		self.channels.send_unbounded_and_log_error(self.signals_received.load(), msg);
	}
}
#[polkadot_overseer_gen::async_trait]
impl SubsystemSender<CollationGenerationMessage> for OverseerSubsystemSender {
	async fn send_message(&mut self, msg: CollationGenerationMessage) {
		self.channels
			.send_and_log_error(self.signals_received.load(), AllMessages::from(msg))
			.await;
	}
	async fn send_messages<T>(&mut self, msgs: T)
	where
		T: IntoIterator<Item = CollationGenerationMessage> + Send,
		T::IntoIter: Send,
	{
		for msg in msgs {
			self.send_message(msg).await;
		}
	}
	fn send_unbounded_message(&mut self, msg: CollationGenerationMessage) {
		self.channels
			.send_unbounded_and_log_error(self.signals_received.load(), AllMessages::from(msg));
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
pub struct OverseerSubsystemContext<M> {
	signals: polkadot_overseer_gen::metered::MeteredReceiver<OverseerSignal>,
	messages: SubsystemIncomingMessages<M>,
	to_subsystems: OverseerSubsystemSender,
	to_overseer:
		polkadot_overseer_gen::metered::UnboundedMeteredSender<polkadot_overseer_gen::ToOverseer>,
	signals_received: SignalsReceived,
	pending_incoming: Option<(usize, M)>,
	name: &'static str,
}
impl<M> OverseerSubsystemContext<M> {
	/// Create a new context.
	fn new(
		signals: polkadot_overseer_gen::metered::MeteredReceiver<OverseerSignal>,
		messages: SubsystemIncomingMessages<M>,
		to_subsystems: ChannelsOut,
		to_overseer: polkadot_overseer_gen::metered::UnboundedMeteredSender<
			polkadot_overseer_gen::ToOverseer,
		>,
		name: &'static str,
	) -> Self {
		let signals_received = SignalsReceived::default();
		OverseerSubsystemContext {
			signals,
			messages,
			to_subsystems: OverseerSubsystemSender {
				channels: to_subsystems,
				signals_received: signals_received.clone(),
			},
			to_overseer,
			signals_received,
			pending_incoming: None,
			name,
		}
	}
	fn name(&self) -> &'static str {
		self.name
	}
}
#[polkadot_overseer_gen::async_trait]
impl<M: std::fmt::Debug + Send + 'static> polkadot_overseer_gen::SubsystemContext
	for OverseerSubsystemContext<M>
where
	OverseerSubsystemSender: polkadot_overseer_gen::SubsystemSender<AllMessages>,
	AllMessages: From<M>,
{
	type Message = M;
	type Signal = OverseerSignal;
	type Sender = OverseerSubsystemSender;
	type AllMessages = AllMessages;
	type Error = SubsystemError;
	async fn try_recv(
		&mut self,
	) -> ::std::result::Result<Option<FromOverseer<M, OverseerSignal>>, ()> {
		match polkadot_overseer_gen::poll!(self.recv()) {
			polkadot_overseer_gen::Poll::Ready(msg) => Ok(Some(msg.map_err(|_| ())?)),
			polkadot_overseer_gen::Poll::Pending => Ok(None),
		}
	}
	async fn recv(
		&mut self,
	) -> ::std::result::Result<FromOverseer<M, OverseerSignal>, SubsystemError> {
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
	fn sender(&mut self) -> &mut Self::Sender {
		&mut self.to_subsystems
	}
	fn spawn(
		&mut self,
		name: &'static str,
		s: Pin<Box<dyn Future<Output = ()> + Send>>,
	) -> ::std::result::Result<(), SubsystemError> {
		self.to_overseer
			.unbounded_send(polkadot_overseer_gen::ToOverseer::SpawnJob {
				name,
				subsystem: Some(self.name()),
				s,
			})
			.map_err(|_| polkadot_overseer_gen::OverseerError::TaskSpawn(name))?;
		Ok(())
	}
}
/// Generated message type wrapper
#[allow(missing_docs)]
#[derive(Debug)]
pub enum AllMessages {
	CollationGeneration(CollationGenerationMessage),
	Empty,
}
impl ::std::convert::From<()> for AllMessages {
	fn from(_: ()) -> Self {
		AllMessages::Empty
	}
}
impl ::std::convert::From<CollationGenerationMessage> for AllMessages {
	fn from(message: CollationGenerationMessage) -> Self {
		AllMessages::CollationGeneration(message)
	}
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
