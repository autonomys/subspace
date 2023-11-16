use libp2p::connection_limits::{Behaviour as ConnectionLimitsBehaviour, ConnectionLimits};
use libp2p::core::Endpoint;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use std::collections::HashMap;
use std::task::{Context, Poll};

// TODO: Upstream these capabilities
pub(crate) struct Behaviour {
    inner: ConnectionLimitsBehaviour,
    incoming_allow_list: HashMap<PeerId, usize>,
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
    pub(crate) fn add_to_incoming_allow_list(&mut self, peer: PeerId, attempts: usize) {
        self.incoming_allow_list
            .entry(peer)
            .and_modify(|entry| *entry = entry.saturating_add(attempts))
            .or_insert(attempts);
    }

    /// Remove some (or all) attempts of incoming connections from specified peer ID
    pub(crate) fn remove_from_incoming_allow_list(
        &mut self,
        peer: &PeerId,
        remove_attempts: Option<usize>,
    ) {
        if let Some(remove_attempts) = remove_attempts {
            if let Some(attempts) = self.incoming_allow_list.get_mut(peer) {
                *attempts = attempts.saturating_sub(remove_attempts);

                if *attempts == 0 {
                    self.incoming_allow_list.remove(peer);
                }
            }
        } else {
            self.incoming_allow_list.remove(peer);
        }
    }

    /// Add to allow list some attempts of outgoing connections from specified peer ID that will bypass global limits
    // TODO: Not using for now, but will be helpful upstream
    #[allow(dead_code)]
    pub(crate) fn add_to_outgoing_allow_list(&mut self, peer: PeerId, attempts: usize) {
        self.outgoing_allow_list
            .entry(peer)
            .and_modify(|entry| *entry = entry.saturating_add(attempts))
            .or_insert(attempts);
    }

    /// Remove some (or all) attempts of outgoing connections from specified peer ID
    // TODO: Not using for now, but will be helpful upstream
    #[allow(dead_code)]
    pub(crate) fn remove_from_outgoing_allow_list(
        &mut self,
        peer: &PeerId,
        remove_attempts: Option<usize>,
    ) {
        if let Some(remove_attempts) = remove_attempts {
            if let Some(attempts) = self.outgoing_allow_list.get_mut(peer) {
                *attempts = attempts.saturating_sub(remove_attempts);

                if *attempts == 0 {
                    self.outgoing_allow_list.remove(peer);
                }
            }
        } else {
            self.outgoing_allow_list.remove(peer);
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
        if let Some(peer) = remote_addr.iter().find_map(|protocol| {
            if let Protocol::P2p(peer) = protocol {
                Some(peer)
            } else {
                None
            }
        }) {
            if self.incoming_allow_list.contains_key(&peer) {
                return Ok(());
            }
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
        if let Some(attempts) = self.incoming_allow_list.get_mut(&peer) {
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
        if let Some(peer) = &maybe_peer {
            if self.incoming_allow_list.contains_key(peer) {
                return Ok(Vec::new());
            }
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
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if let Some(attempts) = self.outgoing_allow_list.get_mut(&peer) {
            *attempts -= 1;

            if *attempts == 0 {
                self.outgoing_allow_list.remove(&peer);
            }

            return Ok(Self::ConnectionHandler {});
        }

        self.inner
            .handle_established_outbound_connection(connection_id, peer, addr, role_override)
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
