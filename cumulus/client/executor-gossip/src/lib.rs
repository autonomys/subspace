#![allow(clippy::type_complexity)]

mod worker;

use self::worker::GossipWorker;
use parity_scale_codec::{Decode, Encode};
use parking_lot::{Mutex, RwLock};
use sc_network::{ObservedRole, PeerId};
use sc_network_gossip::{
	GossipEngine, MessageIntent, Network as GossipNetwork, ValidationResult, Validator,
	ValidatorContext,
};
use sc_utils::mpsc::TracingUnboundedReceiver;
use sp_core::hashing::twox_64;
use sp_executor::{Bundle, ExecutionReceipt};
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use std::{
	collections::HashSet,
	fmt::Debug,
	sync::Arc,
	time::{Duration, Instant},
};

const LOG_TARGET: &str = "gossip::executor";

const EXECUTOR_PROTOCOL_NAME: &str = "/subspace/executor/1";

// TODO: proper timeout
/// Timeout for rebroadcasting messages.
/// The default value used in network-gossip is 1100ms.
const REBROADCAST_AFTER: Duration = Duration::from_secs(6);

type MessageHash = [u8; 8];

/// Returns the configuration value to put in [`sc_network::config::NetworkConfiguration::extra_sets`].
pub fn executor_gossip_peers_set_config() -> sc_network::config::NonDefaultSetConfig {
	let mut cfg =
		sc_network::config::NonDefaultSetConfig::new(EXECUTOR_PROTOCOL_NAME.into(), 1024 * 1024);
	cfg.allow_non_reserved(25, 25);
	cfg
}

/// Gossip engine messages topic.
fn topic<Block: BlockT>() -> Block::Hash {
	<<Block::Header as HeaderT>::Hashing as HashT>::hash(b"executor")
}

/// Executor gossip message type.
///
/// This is the root type that gets encoded and sent on the network.
#[derive(Debug, Encode, Decode)]
pub enum GossipMessage<Block: BlockT> {
	Bundle(Bundle<Block::Extrinsic>),
	ExecutionReceipt(ExecutionReceipt<Block::Hash>),
}

impl<Block: BlockT> From<Bundle<Block::Extrinsic>> for GossipMessage<Block> {
	fn from(bundle: Bundle<Block::Extrinsic>) -> Self {
		Self::Bundle(bundle)
	}
}

impl<Block: BlockT> From<ExecutionReceipt<Block::Hash>> for GossipMessage<Block> {
	fn from(execution_receipt: ExecutionReceipt<Block::Hash>) -> Self {
		Self::ExecutionReceipt(execution_receipt)
	}
}

/// What to do with the successfully verified gossip message.
#[derive(Debug)]
pub enum Action {
	/// All good, no message needs to be rebroadcasted.
	Empty,
	/// Gossip the bundle message to other executor peers.
	RebroadcastBundle,
	/// Gossip the execution exceipt message to other executor peers.
	RebroadcastExecutionReceipt,
}

impl Action {
	fn rebroadcast_bundle(&self) -> bool {
		matches!(self, Self::RebroadcastBundle)
	}

	fn rebroadcast_execution_receipt(&self) -> bool {
		matches!(self, Self::RebroadcastExecutionReceipt)
	}
}

/// Outcome of the network gossip message processing.
#[derive(Debug)]
pub enum HandlerOutcome<Error> {
	/// The message is valid.
	Good(Action),
	/// The message is invalid.
	Bad(Error),
}

/// Handler for the messages received from the executor gossip network.
pub trait GossipMessageHandler<Block: BlockT> {
	/// Error type.
	type Error: Debug;

	/// Validates and applies when a transaction bundle was received.
	fn on_bundle(&self, bundle: &Bundle<Block::Extrinsic>) -> HandlerOutcome<Self::Error>;

	/// Validates and applies when an execution receipt was received.
	fn on_execution_receipt(
		&self,
		execution_receipt: &ExecutionReceipt<Block::Hash>,
	) -> HandlerOutcome<Self::Error>;
}

/// Validator for the gossip messages.
pub struct GossipValidator<Block: BlockT, Executor> {
	topic: Block::Hash,
	executor: Executor,
	next_rebroadcast: Mutex<Instant>,
	known_rebroadcasted: RwLock<HashSet<MessageHash>>,
}

impl<Block: BlockT, Executor: GossipMessageHandler<Block>> GossipValidator<Block, Executor> {
	pub fn new(executor: Executor) -> Self {
		Self {
			topic: topic::<Block>(),
			executor,
			next_rebroadcast: Mutex::new(Instant::now() + REBROADCAST_AFTER),
			known_rebroadcasted: RwLock::new(HashSet::new()),
		}
	}

	pub(crate) fn note_rebroadcasted(&self, encoded_message: &[u8]) {
		let mut known_rebroadcasted = self.known_rebroadcasted.write();
		known_rebroadcasted.insert(twox_64(encoded_message));
	}

	fn validate_message(&self, msg: GossipMessage<Block>) -> ValidationResult<Block::Hash> {
		use HandlerOutcome::{Bad, Good};

		match msg {
			GossipMessage::Bundle(bundle) => {
				let outcome = self.executor.on_bundle(&bundle);
				match outcome {
					Good(action) if action.rebroadcast_bundle() =>
						ValidationResult::ProcessAndKeep(self.topic),
					Bad(err) => {
						tracing::debug!(
							target: LOG_TARGET,
							?err,
							"Invalid GossipMessage::Bundle discarded"
						);
						ValidationResult::Discard
					},
					_ => ValidationResult::ProcessAndDiscard(self.topic),
				}
			},
			GossipMessage::ExecutionReceipt(execution_receipt) => {
				let outcome = self.executor.on_execution_receipt(&execution_receipt);
				match outcome {
					Good(action) if action.rebroadcast_execution_receipt() =>
						ValidationResult::ProcessAndKeep(self.topic),
					Bad(err) => {
						tracing::debug!(
							target: LOG_TARGET,
							?err,
							"Invalid GossipMessage::ExecutionReceipt discarded"
						);
						ValidationResult::Discard
					},
					_ => ValidationResult::ProcessAndDiscard(self.topic),
				}
			},
		}
	}
}

impl<Block: BlockT, Executor: GossipMessageHandler<Block> + Send + Sync> Validator<Block>
	for GossipValidator<Block, Executor>
{
	fn new_peer(
		&self,
		_context: &mut dyn ValidatorContext<Block>,
		_who: &PeerId,
		_role: ObservedRole,
	) {
	}

	fn peer_disconnected(&self, _context: &mut dyn ValidatorContext<Block>, _who: &PeerId) {}

	fn validate(
		&self,
		_context: &mut dyn ValidatorContext<Block>,
		_sender: &PeerId,
		mut data: &[u8],
	) -> ValidationResult<Block::Hash> {
		match GossipMessage::<Block>::decode(&mut data) {
			Ok(msg) => {
				tracing::debug!(target: LOG_TARGET, ?msg, "Validating incoming message");
				self.validate_message(msg)
			},
			Err(err) => {
				tracing::debug!(
					target: LOG_TARGET,
					?err,
					?data,
					"Message discarded due to the decoding error"
				);
				ValidationResult::Discard
			},
		}
	}

	/// Produce a closure for validating messages on a given topic.
	///
	/// The gossip engine will periodically prune old or no longer relevant messages using
	/// `message_expired`.
	fn message_expired<'a>(&'a self) -> Box<dyn FnMut(Block::Hash, &[u8]) -> bool + 'a> {
		Box::new(move |_topic, mut data| {
			let msg_hash = twox_64(data);
			// TODO: can be expired due to the message itself might be too old?
			let _msg = match GossipMessage::<Block>::decode(&mut data) {
				Ok(msg) => msg,
				Err(_) => return true,
			};
			let expired = {
				let known_rebroadcasted = self.known_rebroadcasted.read();
				known_rebroadcasted.contains(&msg_hash)
			};
			if expired {
				let mut known_rebroadcasted = self.known_rebroadcasted.write();
				known_rebroadcasted.remove(&msg_hash);
			}
			expired
		})
	}

	/// Produce a closure for filtering egress messages.
	///
	/// Called before actually sending a message to a peer.
	fn message_allowed<'a>(
		&'a self,
	) -> Box<dyn FnMut(&PeerId, MessageIntent, &Block::Hash, &[u8]) -> bool + 'a> {
		let do_rebroadcast = {
			let now = Instant::now();
			let mut next_rebroadcast = self.next_rebroadcast.lock();
			if now >= *next_rebroadcast {
				*next_rebroadcast = now + REBROADCAST_AFTER;
				true
			} else {
				false
			}
		};

		Box::new(move |_who, intent, _topic, mut data| {
			if let MessageIntent::PeriodicRebroadcast = intent {
				return do_rebroadcast
			}

			match GossipMessage::<Block>::decode(&mut data) {
				Ok(_) => true,
				Err(_) => false,
			}
		})
	}
}

/// Parameters to run the executor gossip service.
pub struct ExecutorGossipParams<Block: BlockT, Network, Executor> {
	/// Substrate network service.
	pub network: Network,
	/// Executor instance.
	pub executor: Executor,
	/// Stream of transaction bundle produced locally.
	pub bundle_receiver: TracingUnboundedReceiver<Bundle<Block::Extrinsic>>,
	/// Stream of execution receipt produced locally.
	pub execution_receipt_receiver: TracingUnboundedReceiver<ExecutionReceipt<Block::Hash>>,
}

/// Starts the executor gossip worker.
pub async fn start_gossip_worker<Block, Network, Executor>(
	gossip_params: ExecutorGossipParams<Block, Network, Executor>,
) where
	Block: BlockT,
	Network: GossipNetwork<Block> + Send + Sync + Clone + 'static,
	Executor: GossipMessageHandler<Block> + Send + Sync + 'static,
{
	let ExecutorGossipParams { network, executor, bundle_receiver, execution_receipt_receiver } =
		gossip_params;

	let gossip_validator = Arc::new(GossipValidator::new(executor));
	let gossip_engine =
		GossipEngine::new(network, EXECUTOR_PROTOCOL_NAME, gossip_validator.clone(), None);

	let gossip_worker = GossipWorker::new(
		gossip_validator,
		Arc::new(Mutex::new(gossip_engine)),
		bundle_receiver,
		execution_receipt_receiver,
	);

	gossip_worker.run().await
}
