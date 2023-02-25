use crate::create::temporary_bans::TemporaryBans;
use crate::CreationError;
use libp2p::core::multiaddr::{Multiaddr, Protocol};
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{Boxed, ListenerId, TransportError, TransportEvent};
use libp2p::core::Transport;
use libp2p::dns::TokioDnsConfig;
use libp2p::noise::NoiseConfig;
use libp2p::tcp::tokio::Transport as TokioTcpTransport;
use libp2p::tcp::Config as GenTcpConfig;
use libp2p::websocket::WsConfig;
use libp2p::yamux::YamuxConfig;
use libp2p::{core, identity, noise, PeerId};
use parking_lot::Mutex;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tracing::debug;

// Builds the transport stack that LibP2P will communicate over along with a relay client.
pub(super) fn build_transport(
    allow_non_global_addresses_in_dht: bool,
    keypair: &identity::Keypair,
    temporary_bans: Arc<Mutex<TemporaryBans>>,
    timeout: Duration,
    yamux_config: YamuxConfig,
) -> Result<Boxed<(PeerId, StreamMuxerBox)>, CreationError> {
    let transport = {
        let dns_tcp = TokioDnsConfig::system(CustomTransportWrapper::new(
            TokioTcpTransport::new(GenTcpConfig::default().nodelay(true)),
            allow_non_global_addresses_in_dht,
            temporary_bans.clone(),
        ))?;
        let ws = WsConfig::new(TokioDnsConfig::system(CustomTransportWrapper::new(
            TokioTcpTransport::new(GenTcpConfig::default().nodelay(true)),
            allow_non_global_addresses_in_dht,
            temporary_bans,
        ))?);

        dns_tcp.or_transport(ws).boxed()
    };

    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(keypair)
        .expect("Signing libp2p-noise static DH keypair failed.");

    Ok(transport
        .upgrade(core::upgrade::Version::V1Lazy)
        .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(yamux_config)
        .timeout(timeout)
        .boxed())
}

#[derive(Debug, Clone)]
struct CustomTransportWrapper<T> {
    base_transport: T,
    allow_non_global_addresses: bool,
    temporary_bans: Arc<Mutex<TemporaryBans>>,
}

impl<T> CustomTransportWrapper<T> {
    fn new(
        base_transport: T,
        allow_non_global_addresses: bool,
        temporary_bans: Arc<Mutex<TemporaryBans>>,
    ) -> Self {
        CustomTransportWrapper {
            base_transport,
            allow_non_global_addresses,
            temporary_bans,
        }
    }
}

impl<T> Transport for CustomTransportWrapper<T>
where
    T: Transport + Unpin,
    T::Error: From<io::Error>,
{
    type Output = T::Output;
    type Error = T::Error;
    type ListenerUpgrade = T::ListenerUpgrade;
    type Dial = T::Dial;

    fn listen_on(&mut self, addr: Multiaddr) -> Result<ListenerId, TransportError<Self::Error>> {
        self.base_transport.listen_on(addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.base_transport.remove_listener(id)
    }

    fn dial(&mut self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        let mut addr_iter = addr.iter();

        match addr_iter.next() {
            Some(Protocol::Ip4(a)) => {
                if !(self.allow_non_global_addresses || a.is_global()) {
                    debug!(?a, "Not dialing non global IP address.",);
                    return Err(TransportError::MultiaddrNotSupported(addr));
                }
            }
            Some(Protocol::Ip6(a)) => {
                if !(self.allow_non_global_addresses || a.is_global()) {
                    debug!(?a, "Not dialing non global IP address.");
                    return Err(TransportError::MultiaddrNotSupported(addr));
                }
            }
            _ => {
                // TODO: This will not catch DNS records pointing to private addresses
            }
        }

        {
            let temporary_bans = self.temporary_bans.lock();
            for protocol in addr_iter {
                if let Protocol::P2p(multihash) = protocol {
                    if let Ok(peer_id) = PeerId::try_from(multihash) {
                        if temporary_bans.is_banned(&peer_id) {
                            let error =
                                io::Error::new(io::ErrorKind::Other, "Peer is temporarily banned");
                            return Err(TransportError::Other(error.into()));
                        }
                    }
                }
            }
        }

        self.base_transport.dial(addr)
    }

    fn dial_as_listener(
        &mut self,
        addr: Multiaddr,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.base_transport.dial_as_listener(addr)
    }

    fn address_translation(&self, listen: &Multiaddr, observed: &Multiaddr) -> Option<Multiaddr> {
        self.base_transport.address_translation(listen, observed)
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.base_transport).poll(cx)
    }
}
