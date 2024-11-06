// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! `SyncingEngine` is the actor responsible for syncing Substrate chain
//! to tip and keep the blockchain up to date with network updates.

use futures::channel::oneshot;
use futures::StreamExt;
use sc_client_api::ProofProvider;
use sc_consensus::IncomingBlock;
use sc_network::types::ProtocolName;
use sc_network::{OutboundFailure, PeerId, RequestFailure};
use sc_network_sync::pending_responses::{PendingResponses, ResponseEvent};
use sc_network_sync::service::network::NetworkServiceHandle;
use sc_network_sync::state_request_handler::generate_protocol_name;
use sc_network_sync::strategy::state::StateStrategy;
use sc_network_sync::strategy::SyncingAction;
use sc_network_sync::types::BadPeer;
use sp_blockchain::{Error as ClientError, HeaderBackend};
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::sync::Arc;
use tracing::{debug, trace, warn};

mod rep {
    use sc_network::ReputationChange as Rep;
    /// Peer is on unsupported protocol version.
    pub(super) const BAD_PROTOCOL: Rep = Rep::new_fatal("Unsupported protocol");
    /// Reputation change when a peer refuses a request.
    pub(super) const REFUSED: Rep = Rep::new(-(1 << 10), "Request refused");
    /// Reputation change when a peer doesn't respond in time to our messages.
    pub(super) const TIMEOUT: Rep = Rep::new(-(1 << 10), "Request timeout");
}

pub struct SnapSyncingEngine<'a, Block>
where
    Block: BlockT,
{
    /// Syncing strategy
    strategy: StateStrategy<Block>,
    /// Pending responses
    pending_responses: PendingResponses,
    /// Protocol name used to send out state requests
    state_request_protocol_name: ProtocolName,
    network_service_handle: &'a NetworkServiceHandle,
}

impl<'a, Block> SnapSyncingEngine<'a, Block>
where
    Block: BlockT,
{
    pub fn new<Client>(
        client: Arc<Client>,
        fork_id: Option<&str>,
        target_header: Block::Header,
        skip_proof: bool,
        current_sync_peer: (PeerId, NumberFor<Block>),
        network_service_handle: &'a NetworkServiceHandle,
    ) -> Result<Self, ClientError>
    where
        Client: HeaderBackend<Block> + ProofProvider<Block> + Send + Sync + 'static,
    {
        let state_request_protocol_name =
            ProtocolName::from(generate_protocol_name(client.info().genesis_hash, fork_id));

        // Initialize syncing strategy.
        let strategy = StateStrategy::new(
            client,
            target_header,
            // We only care about the state, this value is just forwarded back into block to
            // import that is thrown away below
            None,
            // We only care about the state, this value is just forwarded back into block to
            // import that is thrown away below
            None,
            skip_proof,
            vec![current_sync_peer].into_iter(),
            state_request_protocol_name.clone(),
        );

        Ok(Self {
            strategy,
            pending_responses: PendingResponses::new(),
            state_request_protocol_name,
            network_service_handle,
        })
    }

    // Downloads state and returns incoming block with state pre-populated and ready for importing
    pub async fn download_state(mut self) -> Result<IncomingBlock<Block>, ClientError> {
        debug!("Starting state downloading");

        loop {
            // Process actions requested by a syncing strategy.
            let mut actions = self
                .strategy
                .actions(self.network_service_handle)
                .peekable();
            if actions.peek().is_none() {
                return Err(ClientError::Backend(
                    "Sync state download failed: no further actions".into(),
                ));
            }

            for action in actions {
                match action {
                    SyncingAction::StartRequest {
                        peer_id,
                        key,
                        request,
                        // State sync doesn't use this
                        remove_obsolete: _,
                    } => {
                        self.pending_responses.insert(peer_id, key, request);
                    }
                    SyncingAction::CancelRequest { .. } => {
                        return Err(ClientError::Application(
                            "Unexpected SyncingAction::CancelRequest".into(),
                        ));
                    }
                    SyncingAction::DropPeer(BadPeer(peer_id, rep)) => {
                        self.pending_responses
                            .remove(peer_id, StateStrategy::<Block>::STRATEGY_KEY);

                        trace!(%peer_id, "Peer dropped: {rep:?}");
                    }
                    SyncingAction::ImportBlocks { blocks, .. } => {
                        return blocks.into_iter().next().ok_or_else(|| {
                            ClientError::Application(
                                "SyncingAction::ImportBlocks didn't contain any blocks to import"
                                    .into(),
                            )
                        });
                    }
                    SyncingAction::ImportJustifications { .. } => {
                        return Err(ClientError::Application(
                            "Unexpected SyncingAction::ImportJustifications".into(),
                        ));
                    }
                    SyncingAction::Finished => {
                        return Err(ClientError::Backend(
                            "Sync state finished without blocks to import".into(),
                        ));
                    }
                }
            }

            let response_event = self.pending_responses.select_next_some().await;
            self.process_response_event(response_event);
        }
    }

    fn process_response_event(&mut self, response_event: ResponseEvent) {
        let ResponseEvent {
            peer_id,
            key: _,
            response: response_result,
        } = response_event;

        match response_result {
            Ok(Ok((response, _protocol_name))) => {
                let Ok(response) = response.downcast::<Vec<u8>>() else {
                    warn!("Failed to downcast state response");
                    debug_assert!(false);
                    return;
                };

                self.strategy.on_state_response(&peer_id, *response);
            }
            Ok(Err(e)) => {
                debug!("Request to peer {peer_id:?} failed: {e:?}.");

                match e {
                    RequestFailure::Network(OutboundFailure::Timeout) => {
                        self.network_service_handle
                            .report_peer(peer_id, rep::TIMEOUT);
                        self.network_service_handle
                            .disconnect_peer(peer_id, self.state_request_protocol_name.clone());
                    }
                    RequestFailure::Network(OutboundFailure::UnsupportedProtocols) => {
                        self.network_service_handle
                            .report_peer(peer_id, rep::BAD_PROTOCOL);
                        self.network_service_handle
                            .disconnect_peer(peer_id, self.state_request_protocol_name.clone());
                    }
                    RequestFailure::Network(OutboundFailure::DialFailure) => {
                        self.network_service_handle
                            .disconnect_peer(peer_id, self.state_request_protocol_name.clone());
                    }
                    RequestFailure::Refused => {
                        self.network_service_handle
                            .report_peer(peer_id, rep::REFUSED);
                        self.network_service_handle
                            .disconnect_peer(peer_id, self.state_request_protocol_name.clone());
                    }
                    RequestFailure::Network(OutboundFailure::ConnectionClosed)
                    | RequestFailure::NotConnected => {
                        self.network_service_handle
                            .disconnect_peer(peer_id, self.state_request_protocol_name.clone());
                    }
                    RequestFailure::UnknownProtocol => {
                        debug_assert!(false, "Block request protocol should always be known.");
                    }
                    RequestFailure::Obsolete => {
                        debug_assert!(
                            false,
                            "Can not receive `RequestFailure::Obsolete` after dropping the \
                            response receiver.",
                        );
                    }
                }
            }
            Err(oneshot::Canceled) => {
                trace!("Request to peer {peer_id:?} failed due to oneshot being canceled.");
                self.network_service_handle
                    .disconnect_peer(peer_id, self.state_request_protocol_name.clone());
            }
        }
    }
}
