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
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tracing::debug;

// Builds the transport stack that LibP2P will communicate over along with a relay client.
pub(super) fn build_transport(
    allow_non_global_addresses_in_dht: bool,
    keypair: &identity::Keypair,
    timeout: Duration,
    yamux_config: YamuxConfig,
) -> Result<Boxed<(PeerId, StreamMuxerBox)>, CreationError> {
    let transport = {
        let dns_tcp = TokioDnsConfig::system(TokioTcpTransport::new(
            GenTcpConfig::default().nodelay(true),
        ))?;
        let ws = WsConfig::new(TokioDnsConfig::system(TokioTcpTransport::new(
            GenTcpConfig::default().nodelay(true),
        ))?);

        let dns_tcp_or_ws_transport = dns_tcp.or_transport(ws).boxed();

        if allow_non_global_addresses_in_dht {
            dns_tcp_or_ws_transport
        } else {
            GlobalIpOnlyTransport::new(dns_tcp_or_ws_transport).boxed()
        }
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

// Wrapper around a libp2p `Transport` dropping all dial requests to non-global
// IP addresses.
#[derive(Debug, Clone, Default)]
pub struct GlobalIpOnlyTransport<T> {
    inner: T,
}

impl<T> GlobalIpOnlyTransport<T> {
    pub fn new(transport: T) -> Self {
        GlobalIpOnlyTransport { inner: transport }
    }
}

impl<T: Transport + Unpin> Transport for GlobalIpOnlyTransport<T> {
    type Output = <T as Transport>::Output;
    type Error = <T as Transport>::Error;
    type ListenerUpgrade = <T as Transport>::ListenerUpgrade;
    type Dial = <T as Transport>::Dial;

    fn listen_on(&mut self, addr: Multiaddr) -> Result<ListenerId, TransportError<Self::Error>> {
        self.inner.listen_on(addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(&mut self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        match addr.iter().next() {
            Some(Protocol::Ip4(a)) => {
                if a.is_global() {
                    self.inner.dial(addr)
                } else {
                    debug!(?a, "Not dialing non global IP address.",);
                    Err(TransportError::MultiaddrNotSupported(addr))
                }
            }
            Some(Protocol::Ip6(a)) => {
                if a.is_global() {
                    self.inner.dial(addr)
                } else {
                    debug!(?a, "Not dialing non global IP address.");
                    Err(TransportError::MultiaddrNotSupported(addr))
                }
            }
            _ => {
                debug!(?addr, "Not dialing unsupported Multiaddress.");
                Err(TransportError::MultiaddrNotSupported(addr))
            }
        }
    }

    fn dial_as_listener(
        &mut self,
        addr: Multiaddr,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.inner.dial_as_listener(addr)
    }

    fn address_translation(&self, listen: &Multiaddr, observed: &Multiaddr) -> Option<Multiaddr> {
        self.inner.address_translation(listen, observed)
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.inner).poll(cx)
    }
}
