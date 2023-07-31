use crate::create::temporary_bans::TemporaryBans;
use crate::CreationError;
use futures::future::Either;
use libp2p::core::multiaddr::{Multiaddr, Protocol};
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{Boxed, ListenerId, TransportError, TransportEvent};
use libp2p::core::Transport;
use libp2p::dns::TokioDnsConfig;
use libp2p::tcp::tokio::Transport as TokioTcpTransport;
use libp2p::tcp::Config as GenTcpConfig;
use libp2p::websocket::WsConfig;
use libp2p::yamux::Config as YamuxConfig;
use libp2p::{core, identity, noise, PeerId};
use libp2p_quic::tokio::Transport as QuicTransport;
use libp2p_quic::Config as QuicConfig;
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
    let wrapped_tcp_ws = {
        let wrapped_tcp = CustomTransportWrapper::new(
            TokioTcpTransport::new(GenTcpConfig::default().nodelay(true)),
            allow_non_global_addresses_in_dht,
            temporary_bans.clone(),
        );

        let wrapped_ws = WsConfig::new(CustomTransportWrapper::new(
            TokioTcpTransport::new(GenTcpConfig::default().nodelay(true)),
            allow_non_global_addresses_in_dht,
            temporary_bans.clone(),
        ));

        wrapped_tcp.or_transport(wrapped_ws)
    };

    let tcp_ws_upgraded = {
        let noise =
            noise::Config::new(keypair).expect("Signing libp2p-noise static DH keypair failed.");

        wrapped_tcp_ws
            .upgrade(core::upgrade::Version::V1Lazy)
            .authenticate(noise)
            .multiplex(yamux_config)
            .timeout(timeout)
            .boxed()
    };

    let quic = QuicTransport::new(QuicConfig::new(keypair))
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)));

    let wrapped_quic =
        CustomTransportWrapper::new(quic, allow_non_global_addresses_in_dht, temporary_bans);

    let tcp_ws_quic = tcp_ws_upgraded
        .or_transport(wrapped_quic)
        .map(|either, _| match either {
            Either::Left((peer_id, muxer)) => (peer_id, muxer),
            Either::Right((peer_id, muxer)) => (peer_id, muxer),
        });

    let dns_wrapped_upgraded_tcp_ws_quic = TokioDnsConfig::system(tcp_ws_quic)?;

    Ok(dns_wrapped_upgraded_tcp_ws_quic.boxed())
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

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.base_transport.listen_on(id, addr)
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
                if let Protocol::P2p(peer_id) = protocol {
                    if temporary_bans.is_banned(&peer_id) {
                        let error =
                            io::Error::new(io::ErrorKind::Other, "Peer is temporarily banned");
                        return Err(TransportError::Other(error.into()));
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
