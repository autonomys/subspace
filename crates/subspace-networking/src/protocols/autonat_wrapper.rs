use crate::utils::is_global_address_or_dns;
use libp2p::autonat::{Behaviour as Autonat, Config as AutonatConfig, Event as AutonatEvent};
use libp2p::core::Endpoint;
use libp2p::core::transport::PortUse;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use std::collections::HashSet;
use std::task::{Context, Poll};
use tracing::debug;

pub(crate) struct Config {
    pub(crate) inner_config: AutonatConfig,
    pub(crate) local_peer_id: PeerId,
    pub(crate) servers: Vec<Multiaddr>,
}

pub(crate) struct Behaviour {
    inner: Autonat,
    private_ips_enabled: bool,
    listen_addresses: HashSet<Multiaddr>,
}

impl Behaviour {
    pub(crate) fn new(config: Config) -> Self {
        let mut inner = Autonat::new(config.local_peer_id, config.inner_config.clone());

        for server in config.servers {
            let maybe_peer_id = server.iter().find_map(|protocol| {
                if let Protocol::P2p(peer_id) = protocol {
                    Some(peer_id)
                } else {
                    None
                }
            });
            if let Some(peer_id) = maybe_peer_id {
                inner.add_server(peer_id, Some(server));
            }
        }

        Self {
            inner,
            private_ips_enabled: !config.inner_config.only_global_ips,
            listen_addresses: Default::default(),
        }
    }

    fn address_corresponds_to_listening_addresses(&self, addr: &Multiaddr) -> bool {
        let Some(candidate_protocol) = addr.iter().find_map(|protocol| match protocol {
            tcp @ Protocol::Tcp(_) => Some(tcp),
            _ => None,
        }) else {
            return false;
        };

        let address_result = self
            .listen_addresses
            .iter()
            .any(|addr| addr.iter().any(|protocol| protocol == candidate_protocol));

        debug!(
            %address_result,
            ?addr,
            listen_addresses=?self.listen_addresses,
            "Address candidate corresponds to listening addresses."
        );

        address_result
    }

    pub(crate) fn public_address(&self) -> Option<&Multiaddr> {
        self.inner.public_address()
    }

    pub(crate) fn confidence(&self) -> usize {
        self.inner.confidence()
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = <Autonat as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = AutonatEvent;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            new_listen_addr_event @ FromSwarm::NewListenAddr(_) => {
                if let FromSwarm::NewListenAddr(addr) = new_listen_addr_event {
                    //TODO: handle listener address change
                    self.listen_addresses.insert(addr.addr.clone());

                    if self.private_ips_enabled || is_global_address_or_dns(addr.addr) {
                        self.inner.on_swarm_event(new_listen_addr_event);
                    } else {
                        debug!(addr=?addr.addr, "Skipped listening address in AutonatWrapper.");
                    }
                }
            }
            new_external_addr_event @ FromSwarm::NewExternalAddrCandidate(_) => {
                if let FromSwarm::NewExternalAddrCandidate(addr) = new_external_addr_event {
                    if self.address_corresponds_to_listening_addresses(addr.addr) {
                        self.inner.on_swarm_event(new_external_addr_event);
                    } else {
                        debug!(
                            addr=?addr.addr,
                            "Skipped external address candidate in AutonatWrapper."
                        );
                    }
                }
            }
            event => {
                self.inner.on_swarm_event(event);
            }
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner
            .on_connection_handler_event(peer_id, connection_id, event)
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.inner.poll(cx)
    }
}
