mod handler;
mod protocol;

use crate::peer_info::handler::HandlerInEvent;
use event_listener_primitives::HandlerId;
use handler::Handler;
pub use handler::{Config, PeerInfoError, PeerInfoSuccess};
use libp2p::core::{Endpoint, Multiaddr};
use libp2p::swarm::behaviour::{ConnectionEstablished, FromSwarm};
use libp2p::swarm::{
    ConnectionClosed, ConnectionDenied, ConnectionId, NetworkBehaviour, NotifyHandler,
    PollParameters, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::PeerId;
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use tracing::debug;

#[derive(Debug, Clone, Copy)]
/// Peer info notification stub.
pub struct Notification;
/// Defines a subscription to a peer-info notification.
pub type NotificationHandler = Arc<dyn Fn(&Notification) + Send + Sync + 'static>;

/// Cuckoo filter data transfer object.
#[derive(Clone, Encode, Decode, Default)]
pub struct CuckooFilterDTO {
    /// Exported cuckoo filter values.
    pub values: Vec<u8>,
    /// Cuckoo filter items.
    pub length: u64,
}

impl fmt::Debug for CuckooFilterDTO {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CuckooFilterDTO")
            .field("values", &self.length)
            .field("length", &self.values.len())
            .finish()
    }
}

#[derive(Clone, Encode, Decode, Default, Debug)]
/// Peer info data
pub enum PeerInfo {
    /// DSN farmer.
    Farmer {
        /// Peer info data.
        cuckoo_filter: Arc<CuckooFilterDTO>,
    },
    /// DSN node.
    Node,
    /// DSN bootstrap node.
    BootstrapNode,
    /// Unspecified client (testing, custom utilities, etc).
    #[default]
    Client,
}

impl PeerInfo {
    /// Returns whether [`PeerInfo`] is a Farmer.
    pub fn is_farmer(peer_info: &PeerInfo) -> bool {
        matches!(peer_info, Self::Farmer { .. })
    }
}

/// A [`NetworkBehaviour`] that handles inbound peer info requests and
/// sends outbound peer info requests on the first established connection.
pub struct Behaviour {
    /// Peer info protocol configuration.
    config: Config,
    /// Queue of events to yield to the swarm.
    events: VecDeque<Event>,
    /// Outbound peer info pushes.
    requests: Vec<Request>,
    /// Provides up-to-date peer info.
    peer_info_provider: PeerInfoProvider,
    /// Whether the behaviour should notify connected peers.
    should_notify_handlers: Arc<AtomicBool>,
    /// We just save the handler ID.
    _notify_handler_id: Option<HandlerId>,
    /// Known connected peers.
    connected_peers: HashSet<PeerId>,
    /// Future waker.
    waker: Arc<Mutex<Option<Waker>>>,
}

#[derive(Debug)]
/// Peer info push request. Handlers wait for these requests to send data.
struct Request {
    peer_id: PeerId,
    peer_info: Arc<PeerInfo>,
}

/// Handles constant peer info data.
#[derive(Debug)]
pub enum PeerInfoProvider {
    /// Provides peer-info for Node peer type.
    Node,
    /// Provides peer-info for Boostrap Node peer type.
    BootstrapNode,
    /// Provides peer-info for Client peer type.
    Client,
    /// Provides peer-info for Farmer peer type.
    Farmer(Box<dyn CuckooFilterProvider + Send>),
}

/// Provides the current cuckoo-filter data.
pub trait CuckooFilterProvider: Debug + 'static {
    /// Returns the current cuckoo filter data.
    fn cuckoo_filter(&self) -> CuckooFilterDTO;
    /// Subscribe to cuckoo filter updates and invoke provided callback.
    fn on_notification(&self, callback: NotificationHandler) -> Option<HandlerId>;
}

impl PeerInfoProvider {
    /// Creates a new Node peer-info provider.
    pub fn new_node() -> Self {
        Self::Node
    }
    /// Creates a new Bootstrap Node peer-info provider.
    pub fn new_bootstrap_node() -> Self {
        Self::BootstrapNode
    }
    /// Creates a new Client peer-info provider.
    pub fn new_client() -> Self {
        Self::Client
    }
    /// Creates a new Farmer peer-info provider.
    pub fn new_farmer(provider: Box<dyn CuckooFilterProvider + Send>) -> Self {
        Self::Farmer(provider)
    }

    /// Returns the peer info data.
    pub fn peer_info(&self) -> PeerInfo {
        match self {
            PeerInfoProvider::Node => PeerInfo::Node,
            PeerInfoProvider::BootstrapNode => PeerInfo::BootstrapNode,
            PeerInfoProvider::Client => PeerInfo::Client,
            PeerInfoProvider::Farmer(provider) => PeerInfo::Farmer {
                cuckoo_filter: Arc::new(provider.cuckoo_filter()),
            },
        }
    }
    /// Subscribe to peer info updates and invoke provided callback.
    pub fn on_notification(&self, handler: NotificationHandler) -> Option<HandlerId> {
        match self {
            PeerInfoProvider::Node | PeerInfoProvider::BootstrapNode | PeerInfoProvider::Client => {
                None
            }
            PeerInfoProvider::Farmer(provider) => provider.on_notification(handler),
        }
    }
}

/// Event generated by the `Peer Info` network behaviour.
#[derive(Debug)]
pub struct Event {
    /// The peer ID of the remote.
    pub peer_id: PeerId,
    /// The result of an inbound or outbound peer info request.
    pub result: Result<PeerInfoSuccess, PeerInfoError>,
}

impl Behaviour {
    /// Creates a new `Peer Info` network behaviour with the given configuration.
    pub fn new(config: Config, peer_info_provider: PeerInfoProvider) -> Self {
        let waker = Arc::new(Mutex::new(None::<Waker>));
        let should_notify_handlers = Arc::new(AtomicBool::new(false));
        let _notify_handler_id = peer_info_provider.on_notification({
            let should_notify_handlers = should_notify_handlers.clone();
            let waker = waker.clone();

            Arc::new(move |_| {
                should_notify_handlers.store(true, Ordering::SeqCst);
                if let Some(waker) = waker.lock().as_mut() {
                    waker.wake_by_ref();
                }
            })
        });

        Self {
            _notify_handler_id,
            config,
            peer_info_provider,
            events: VecDeque::new(),
            requests: Vec::new(),
            should_notify_handlers,
            connected_peers: HashSet::new(),
            waker,
        }
    }

    fn wake(&self) {
        if let Some(waker) = &self.waker.lock().as_mut() {
            waker.wake_by_ref()
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Handler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(self.config.clone()))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(self.config.clone()))
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        _: ConnectionId,
        result: THandlerOutEvent<Self>,
    ) {
        self.events.push_front(Event {
            peer_id: peer,
            result,
        });
        self.wake();
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        _: &mut impl PollParameters,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if self.should_notify_handlers.swap(false, Ordering::SeqCst) {
            debug!("Notify peer-info handlers.");

            self.requests.clear();
            let peer_info = Arc::new(self.peer_info_provider.peer_info());
            for peer_id in self.connected_peers.iter().cloned() {
                self.requests.push(Request {
                    peer_id,
                    peer_info: peer_info.clone(),
                });
            }
        }

        if let Some(e) = self.events.pop_back() {
            let Event { result, peer_id } = &e;

            match result {
                Ok(PeerInfoSuccess::Sent) => {
                    debug!(%peer_id, "Peer info sent.")
                }
                Ok(PeerInfoSuccess::Received(_)) => {
                    debug!(%peer_id, "Peer info received")
                }
                Err(err) => {
                    debug!(%peer_id, ?err, "Peer info error");
                }
            }

            return Poll::Ready(ToSwarm::GenerateEvent(e));
        }

        // Check for pending requests.
        if let Some(Request { peer_id, peer_info }) = self.requests.pop() {
            return Poll::Ready(ToSwarm::NotifyHandler {
                peer_id,
                handler: NotifyHandler::Any,
                event: HandlerInEvent { peer_info },
            });
        }

        self.waker.lock().replace(cx.waker().clone());
        Poll::Pending
    }

    fn on_swarm_event(&mut self, event: FromSwarm<Self::ConnectionHandler>) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id,
                other_established,
                ..
            }) => {
                self.connected_peers.insert(peer_id);

                // Push the peer-info request on the first connection.
                if other_established == 0 {
                    let peer_info = Arc::new(self.peer_info_provider.peer_info());
                    self.requests.push(Request { peer_id, peer_info });
                    self.wake();
                }
            }
            FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id,
                remaining_established,
                ..
            }) => {
                if remaining_established == 0 {
                    self.connected_peers.remove(&peer_id);
                }
            }
            FromSwarm::AddressChange(_)
            | FromSwarm::DialFailure(_)
            | FromSwarm::ListenFailure(_)
            | FromSwarm::NewListener(_)
            | FromSwarm::NewListenAddr(_)
            | FromSwarm::ExpiredListenAddr(_)
            | FromSwarm::ListenerError(_)
            | FromSwarm::ListenerClosed(_)
            | FromSwarm::NewExternalAddrCandidate(_)
            | FromSwarm::ExternalAddrConfirmed(_)
            | FromSwarm::ExternalAddrExpired(_) => {}
        }
    }
}
