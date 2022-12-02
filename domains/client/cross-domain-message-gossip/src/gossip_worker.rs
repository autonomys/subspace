use futures::StreamExt;
use parity_scale_codec::{Decode, Encode};
use sc_network_gossip::{
    GossipEngine, MessageIntent, ValidationResult, Validator, ValidatorContext,
};
use sc_utils::mpsc::TracingUnboundedSender;
use sp_domains::DomainId;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use std::collections::BTreeMap;

const LOG_TARGET: &str = "cross_domain_gossip_worker";

/// Unbounded sender to send encoded ext to listeners.
pub type DomainExtSender = TracingUnboundedSender<Vec<u8>>;

/// A cross domain message with encoded data.
#[derive(Debug, Encode, Decode)]
pub struct Message {
    pub domain_id: DomainId,
    pub encoded_data: Vec<u8>,
}

struct GossipWorker<Block: BlockT> {
    gossip_engine: GossipEngine<Block>,
    domain_ext_senders: BTreeMap<DomainId, DomainExtSender>,
}

/// Cross domain message topic.
fn topic<Block: BlockT>() -> Block::Hash {
    <<Block::Header as HeaderT>::Hashing as HashT>::hash(b"cross-domain-messages")
}

impl<Block: BlockT> GossipWorker<Block> {
    pub fn new(
        gossip_engine: GossipEngine<Block>,
        domain_ext_senders: BTreeMap<DomainId, DomainExtSender>,
    ) -> Self {
        GossipWorker {
            gossip_engine,
            domain_ext_senders,
        }
    }

    pub async fn run(mut self) {
        let mut incoming_cross_domain_messages = Box::pin(
            self.gossip_engine
                .messages_for(topic::<Block>())
                .filter_map(|notification| async move {
                    Message::decode(&mut &notification.message[..]).ok()
                }),
        );

        loop {
            futures::select! {
                cross_domain_message = incoming_cross_domain_messages.next() => {
                    if let Some(Message{domain_id, encoded_data}) = cross_domain_message {
                        tracing::debug!(target: LOG_TARGET, "Incoming cross domain message for domain: {:?}", domain_id);
                        self.incoming_cross_domain_message(domain_id, encoded_data);
                    }
                }
            }
        }
    }

    fn incoming_cross_domain_message(&mut self, domain_id: DomainId, encoded_ext: Vec<u8>) {
        let sink = match self.domain_ext_senders.get(&domain_id) {
            Some(sink) => sink,
            None => return,
        };

        // send the message to the open and ready channel
        if !sink.is_closed() && sink.unbounded_send(encoded_ext).is_ok() {
            return;
        }

        // sink is either closed or failed to send unbounded message
        // consider it closed and remove the sink.
        tracing::error!(
            target: LOG_TARGET,
            "Failed to send incoming domain message: {:?}",
            domain_id
        );
        self.domain_ext_senders.remove(&domain_id);
    }
}
