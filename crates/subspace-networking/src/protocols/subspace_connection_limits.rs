use libp2p::connection_limits::{Behaviour as ConnectionLimitsBehaviour, ConnectionLimits};
use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::task::{Context, Poll};

// TODO: Upstream these capabilities
pub(crate) struct Behaviour {
    inner: ConnectionLimitsBehaviour,
    /// For every peer ID store both their expected IP addresses as well as number of incoming connection attempts
    /// allowed before this allow list entry no longer has an effect
    incoming_allow_list: HashMap<PeerId, (HashSet<IpAddr>, usize)>,
    /// For every peer ID store number of outgoing connection attempts allowed before this allow list entry no longer
    /// has an effect
    outgoing_allow_list: HashMap<PeerId, usize>,
}

impl Behaviour {
    pub(crate) fn new(limits: ConnectionLimits) -> Self {
        Self {
            inner: ConnectionLimitsBehaviour::new(limits),
            incoming_allow_list: HashMap::default(),
            outgoing_allow_list: HashMap::default(),
        }
    }

    /// Add to allow list some attempts of incoming connections from specified peer ID that will bypass global limits
    pub(crate) fn add_to_incoming_allow_list<IpAddresses>(
        &mut self,
        peer: PeerId,
        ip_addresses: IpAddresses,
        add_attempts: usize,
    ) where
        IpAddresses: Iterator<Item = IpAddr>,
    {
        match self.incoming_allow_list.entry(peer) {
            Entry::Occupied(mut entry) => {
                let (existing_ip_addresses, attempts) = entry.get_mut();
                existing_ip_addresses.extend(ip_addresses);
                *attempts = attempts.saturating_add(add_attempts);
            }
            Entry::Vacant(entry) => {
                entry.insert((ip_addresses.collect(), add_attempts));
            }
        }
    }

    /// Remove some (or all) attempts of incoming connections from specified peer ID
    pub(crate) fn remove_from_incoming_allow_list(
        &mut self,
        peer: &PeerId,
        remove_attempts: Option<usize>,
    ) {
        if let Some(remove_attempts) = remove_attempts {
            if let Some((_ip_addresses, attempts)) = self.incoming_allow_list.get_mut(peer) {
                *attempts = attempts.saturating_sub(remove_attempts);

                if *attempts == 0 {
                    self.incoming_allow_list.remove(peer);
                }
            }
        } else {
            self.incoming_allow_list.remove(peer);
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = <ConnectionLimitsBehaviour as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = <ConnectionLimitsBehaviour as NetworkBehaviour>::ToSwarm;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        // PeerId is not yet known at this point, so we check against IP address instead
        if let Some(ip_address) = remote_addr.iter().find_map(|protocol| match protocol {
            Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
            _ => None,
        })
            && self
                .incoming_allow_list
                .values()
                .any(|(ip_addresses, _attempts)| ip_addresses.contains(&ip_address))
            {
                return Ok(());
            }

        self.inner
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if let Some((_ip_addresses, attempts)) = self.incoming_allow_list.get_mut(&peer) {
            *attempts -= 1;

            if *attempts == 0 {
                self.incoming_allow_list.remove(&peer);
            }

            return Ok(Self::ConnectionHandler {});
        }

        self.inner.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if let Some(peer) = &maybe_peer
            && self.incoming_allow_list.contains_key(peer) {
                return Ok(Vec::new());
            }

        self.inner.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
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
        if let Some(attempts) = self.outgoing_allow_list.get_mut(&peer) {
            *attempts -= 1;

            if *attempts == 0 {
                self.outgoing_allow_list.remove(&peer);
            }

            return Ok(Self::ConnectionHandler {});
        }

        self.inner.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.inner.on_swarm_event(event)
    }

    fn on_connection_handler_event(
        &mut self,
        id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner
            .on_connection_handler_event(id, connection_id, event)
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.inner.poll(cx)
    }
}
