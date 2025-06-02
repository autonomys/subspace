//! Compact block implementation.

use crate::protocol::{ClientBackend, ProtocolUnitInfo, Resolved, ServerBackend};
use crate::types::RelayError;
use crate::utils::NetworkPeerHandle;
use derive_more::From;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeMap;
use tracing::{trace, warn};

/// The initial request(currently we don't need to do send anything
/// as part of the initial download request for compact blocks).
#[derive(From, Encode, Decode)]
pub(crate) enum CompactBlockInitialRequest {
    #[codec(index = 0)]
    V0,
    // Next version/variant goes here:
    // #[codec(index = 1)]
}

/// The compact block initial response from the server.
#[derive(Encode, Decode)]
pub(crate) struct CompactBlockInitialResponse<DownloadUnitId, ProtocolUnitId, ProtocolUnit> {
    /// The download unit
    download_unit_id: DownloadUnitId,

    /// List of the protocol units Ids.
    protocol_units: Vec<ProtocolUnitInfo<ProtocolUnitId, ProtocolUnit>>,
}

/// The handshake messages from the client.
#[derive(From, Encode, Decode)]
pub(crate) enum CompactBlockHandshake<DownloadUnitId, ProtocolUnitId> {
    /// Request for missing transactions
    #[codec(index = 0)]
    MissingEntriesV0(MissingEntriesRequest<DownloadUnitId, ProtocolUnitId>),
    // Next version/variant goes here:
    // #[codec(index = 1)]
}

/// The handshake reply from the server.
#[derive(From, Encode, Decode)]
pub(crate) enum CompactBlockHandshakeResponse<ProtocolUnit> {
    /// Response for missing transactions
    #[codec(index = 0)]
    MissingEntriesV0(MissingEntriesResponse<ProtocolUnit>),
    // Next version/variant goes here:
    // #[codec(index = 1)]
}

/// Request for missing transactions
#[derive(Encode, Decode)]
pub(crate) struct MissingEntriesRequest<DownloadUnitId, ProtocolUnitId> {
    /// The download unit
    download_unit_id: DownloadUnitId,

    /// Map of missing entry Id ->  protocol unit Id.
    /// The missing entry Id is an opaque identifier used by the client
    /// side. The server side just returns it as is with the response.
    protocol_unit_ids: BTreeMap<u64, ProtocolUnitId>,
}

/// Response for missing transactions
#[derive(Encode, Decode)]
pub(crate) struct MissingEntriesResponse<ProtocolUnit> {
    /// Map of missing entry Id ->  protocol unit.
    protocol_units: BTreeMap<u64, ProtocolUnit>,
}

struct ResolveContext<ProtocolUnitId, ProtocolUnit> {
    resolved: BTreeMap<u64, Resolved<ProtocolUnitId, ProtocolUnit>>,
    local_miss: BTreeMap<u64, ProtocolUnitId>,
}

pub(crate) struct CompactBlockClient<DownloadUnitId, ProtocolUnitId, ProtocolUnit> {
    _phantom_data: std::marker::PhantomData<(DownloadUnitId, ProtocolUnitId, ProtocolUnit)>,
}

impl<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
    CompactBlockClient<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
where
    DownloadUnitId: Send + Sync + Encode + Decode + Clone + std::fmt::Debug,
    ProtocolUnitId: Send + Sync + Encode + Decode + Clone,
    ProtocolUnit: Send + Sync + Encode + Decode + Clone,
{
    /// Creates the client.
    pub(crate) fn new() -> Self {
        Self {
            _phantom_data: Default::default(),
        }
    }

    /// Builds the initial request.
    pub(crate) fn build_initial_request(
        &self,
        _backend: &dyn ClientBackend<ProtocolUnitId, ProtocolUnit>,
    ) -> CompactBlockInitialRequest {
        CompactBlockInitialRequest::V0
    }

    /// Resolves the initial response to produce the protocol units.
    pub(crate) async fn resolve_initial_response<Request>(
        &self,
        compact_response: CompactBlockInitialResponse<DownloadUnitId, ProtocolUnitId, ProtocolUnit>,
        network_peer_handle: &NetworkPeerHandle,
        backend: &dyn ClientBackend<ProtocolUnitId, ProtocolUnit>,
    ) -> Result<(DownloadUnitId, Vec<Resolved<ProtocolUnitId, ProtocolUnit>>), RelayError>
    where
        Request: From<CompactBlockHandshake<DownloadUnitId, ProtocolUnitId>> + Encode + Send + Sync,
    {
        // Try to resolve the hashes locally first.
        let context = self.resolve_local(&compact_response, backend)?;
        if context.resolved.len() == compact_response.protocol_units.len() {
            trace!(
                "relay::resolve: {:?}: resolved locally[{}]",
                compact_response.download_unit_id,
                compact_response.protocol_units.len()
            );
            return Ok((
                compact_response.download_unit_id,
                context.resolved.into_values().collect(),
            ));
        }

        // Resolve the misses from the server
        let misses = context.local_miss.len();
        let download_unit_id = compact_response.download_unit_id.clone();
        let resolved = self
            .resolve_misses::<Request>(compact_response, context, network_peer_handle)
            .await?;
        trace!(
            "relay::resolve: {:?}: resolved by server[{},{}]",
            download_unit_id,
            resolved.len(),
            misses,
        );
        Ok((download_unit_id, resolved))
    }

    /// Tries to resolve the entries in InitialResponse locally.
    fn resolve_local(
        &self,
        compact_response: &CompactBlockInitialResponse<
            DownloadUnitId,
            ProtocolUnitId,
            ProtocolUnit,
        >,
        backend: &dyn ClientBackend<ProtocolUnitId, ProtocolUnit>,
    ) -> Result<ResolveContext<ProtocolUnitId, ProtocolUnit>, RelayError> {
        let mut context = ResolveContext {
            resolved: BTreeMap::new(),
            local_miss: BTreeMap::new(),
        };

        for (index, entry) in compact_response.protocol_units.iter().enumerate() {
            let ProtocolUnitInfo { id, unit } = entry;
            if let Some(unit) = unit {
                // The full protocol unit was returned
                context.resolved.insert(
                    index as u64,
                    Resolved {
                        protocol_unit_id: id.clone(),
                        protocol_unit: unit.clone(),
                        locally_resolved: true,
                    },
                );
                continue;
            }

            match backend.protocol_unit(id) {
                Some(ret) => {
                    context.resolved.insert(
                        index as u64,
                        Resolved {
                            protocol_unit_id: id.clone(),
                            protocol_unit: ret,
                            locally_resolved: true,
                        },
                    );
                }
                None => {
                    context.local_miss.insert(index as u64, id.clone());
                }
            }
        }

        Ok(context)
    }

    /// Fetches the missing entries from the server.
    async fn resolve_misses<Request>(
        &self,
        compact_response: CompactBlockInitialResponse<DownloadUnitId, ProtocolUnitId, ProtocolUnit>,
        context: ResolveContext<ProtocolUnitId, ProtocolUnit>,
        network_peer_handle: &NetworkPeerHandle,
    ) -> Result<Vec<Resolved<ProtocolUnitId, ProtocolUnit>>, RelayError>
    where
        Request: From<CompactBlockHandshake<DownloadUnitId, ProtocolUnitId>> + Encode + Send + Sync,
    {
        let ResolveContext {
            mut resolved,
            local_miss,
        } = context;
        let missing = local_miss.len();
        // Request the missing entries from the server
        let request = CompactBlockHandshake::from(MissingEntriesRequest {
            download_unit_id: compact_response.download_unit_id.clone(),
            protocol_unit_ids: local_miss.clone(),
        });

        let response: CompactBlockHandshakeResponse<ProtocolUnit> =
            network_peer_handle.request(Request::from(request)).await?;
        let CompactBlockHandshakeResponse::MissingEntriesV0(missing_entries_response) = response;

        if missing_entries_response.protocol_units.len() != missing {
            return Err(RelayError::ResolveMismatch {
                expected: missing,
                actual: missing_entries_response.protocol_units.len(),
            });
        }

        // Merge the resolved entries from the server
        for (missing_key, protocol_unit_id) in local_miss.into_iter() {
            if let Some(protocol_unit) = missing_entries_response.protocol_units.get(&missing_key) {
                resolved.insert(
                    missing_key,
                    Resolved {
                        protocol_unit_id,
                        protocol_unit: protocol_unit.clone(),
                        locally_resolved: false,
                    },
                );
            } else {
                return Err(RelayError::ResolvedNotFound(missing));
            }
        }

        Ok(resolved.into_values().collect())
    }
}

pub(crate) struct CompactBlockServer<DownloadUnitId, ProtocolUnitId, ProtocolUnit> {
    _phantom_data: std::marker::PhantomData<(DownloadUnitId, ProtocolUnitId, ProtocolUnit)>,
}

impl<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
    CompactBlockServer<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
where
    DownloadUnitId: Encode + Decode + Clone,
    ProtocolUnitId: Encode + Decode + Clone,
    ProtocolUnit: Encode + Decode,
{
    /// Creates the server.
    pub(crate) fn new() -> Self {
        Self {
            _phantom_data: Default::default(),
        }
    }

    /// Builds the protocol response to the initial request.
    pub(crate) fn build_initial_response(
        &self,
        download_unit_id: &DownloadUnitId,
        _initial_request: CompactBlockInitialRequest,
        backend: &dyn ServerBackend<DownloadUnitId, ProtocolUnitId, ProtocolUnit>,
    ) -> Result<CompactBlockInitialResponse<DownloadUnitId, ProtocolUnitId, ProtocolUnit>, RelayError>
    {
        // Return the info of the members in the download unit.
        Ok(CompactBlockInitialResponse {
            download_unit_id: download_unit_id.clone(),
            protocol_units: backend.download_unit_members(download_unit_id)?,
        })
    }

    /// Handles the additional client messages during the reconcile phase.
    pub(crate) fn on_protocol_message(
        &self,
        message: CompactBlockHandshake<DownloadUnitId, ProtocolUnitId>,
        backend: &dyn ServerBackend<DownloadUnitId, ProtocolUnitId, ProtocolUnit>,
    ) -> Result<CompactBlockHandshakeResponse<ProtocolUnit>, RelayError> {
        let CompactBlockHandshake::MissingEntriesV0(request) = message;

        let mut protocol_units = BTreeMap::new();
        let total_len = request.protocol_unit_ids.len();
        for (missing_id, protocol_unit_id) in request.protocol_unit_ids {
            if let Some(protocol_unit) =
                backend.protocol_unit(&request.download_unit_id, &protocol_unit_id)
            {
                protocol_units.insert(missing_id, protocol_unit);
            } else {
                warn!("relay::on_request: missing entry not found");
            }
        }
        if total_len != protocol_units.len() {
            warn!(
                "relay::compact_blocks::on_request: could not resolve all entries: {total_len}/{}",
                protocol_units.len()
            );
        }
        Ok(CompactBlockHandshakeResponse::from(
            MissingEntriesResponse { protocol_units },
        ))
    }
}
