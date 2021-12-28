mod worker;

use self::worker::GossipWorker;
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_network::{ObservedRole, PeerId};
use sc_network_gossip::{
	GossipEngine, MessageIntent, Network as GossipNetwork, ValidationResult, Validator,
	ValidatorContext,
};
use sc_utils::mpsc::TracingUnboundedReceiver;
use sp_executor::{Bundle, ExecutionReceipt};
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use std::sync::Arc;

const LOG_TARGET: &str = "gossip::executor";

const EXECUTOR_PROTOCOL_NAME: &str = "/subspace/executor/1";

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

/// Outcome of the network gossip message processing.
#[derive(Debug)]
pub enum HandlerOutcome {
	/// All good, no message needs to be rebroadcasted.
	Good,
	/// Gossip the bundle message to other executor peers.
	RebroadcastBundle,
	/// Gossip the execution exceipt message to other executor peers.
	RebroadcastExecutionReceipt,
}

impl HandlerOutcome {
	fn rebroadcast_bundle(&self) -> bool {
		matches!(self, Self::RebroadcastBundle)
	}

	fn rebroadcast_execution_receipt(&self) -> bool {
		matches!(self, Self::RebroadcastExecutionReceipt)
	}
}

/// Handler for the messages received from the executor gossip network.
#[async_trait::async_trait]
pub trait GossipMessageHandler<Block: BlockT> {
	/// A transaction bundle was received.
	async fn on_bundle(&mut self, bundle: &Bundle<Block::Extrinsic>) -> HandlerOutcome;

	/// An execution receipt was received.
	async fn on_execution_receipt(
		&mut self,
		execution_receipt: &ExecutionReceipt<Block::Hash>,
	) -> HandlerOutcome;
}

/// Validator for the gossip messages.
pub struct GossipValidator<Block: BlockT> {
	topic: Block::Hash,
	// inner: parking_lot::RwLock<Inner<Block>>,
	// set_state: environment::SharedVoterSetState<Block>,
	// report_sender: TracingUnboundedSender<PeerReport>,
}

impl<Block: BlockT> GossipValidator<Block> {
	pub fn new() -> Self {
		Self { topic: topic::<Block>() }
	}
}

impl<Block: BlockT> Validator<Block> for GossipValidator<Block> {
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
		if let Ok(msg) = GossipMessage::<Block>::decode(&mut data) {
			tracing::debug!(target: LOG_TARGET, ?msg, "Validating incoming message");

			// TODO: handle the message properly
			return ValidationResult::ProcessAndKeep(self.topic)
		}

		tracing::debug!(target: LOG_TARGET, ?data, "Message discarded");

		ValidationResult::Discard
	}

	/// Produce a closure for validating messages on a given topic.
	fn message_expired<'a>(&'a self) -> Box<dyn FnMut(Block::Hash, &[u8]) -> bool + 'a> {
		Box::new(move |_topic, _data| false)
	}

	/// Produce a closure for filtering egress messages.
	fn message_allowed<'a>(
		&'a self,
	) -> Box<dyn FnMut(&PeerId, MessageIntent, &Block::Hash, &[u8]) -> bool + 'a> {
		Box::new(move |_who, _intent, _topic, _data| true)
	}
}

/// Parameters to run the executor gossip service.
pub struct ExecutorGossipParams<Block: BlockT, N, E> {
	/// Substrate network service.
	pub network: N,
	/// Executor instance.
	pub executor: E,
	/// Stream of transaction bundle produced locally.
	pub bundle_receiver: TracingUnboundedReceiver<Bundle<Block::Extrinsic>>,
	/// Stream of execution receipt produced locally.
	pub execution_receipt_receiver: TracingUnboundedReceiver<ExecutionReceipt<Block::Hash>>,
}

/// Starts the executor gossip worker.
pub async fn start_gossip_worker<Block, N, E>(gossip_params: ExecutorGossipParams<Block, N, E>)
where
	Block: BlockT,
	N: GossipNetwork<Block> + Send + Sync + Clone + 'static,
	E: GossipMessageHandler<Block>,
{
	let ExecutorGossipParams { network, executor, bundle_receiver, execution_receipt_receiver } =
		gossip_params;

	let gossip_validator = Arc::new(GossipValidator::new());
	let gossip_engine =
		GossipEngine::new(network, EXECUTOR_PROTOCOL_NAME, gossip_validator.clone(), None);

	let gossip_worker = GossipWorker::new(
		executor,
		gossip_validator,
		Arc::new(Mutex::new(gossip_engine)),
		bundle_receiver,
		execution_receipt_receiver,
	);

	gossip_worker.run().await
}
