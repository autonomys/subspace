//! Compact block implementation.

use crate::utils::decode_response;
use crate::{
    NetworkStub, ProtocolBackend, ProtocolClient, ProtocolServer, RelayError, Resolved, LOG_TARGET,
};
use async_trait::async_trait;
use codec::{Decode, Encode};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::{trace, warn};

/// If the encoded size of the protocol unit is less than the threshold,
/// return the full protocol unit along with the protocol unit Id in the
/// compact response. This catches the common cases like inherents with
/// no segment headers. Since inherents are not gossiped, this causes
/// a local miss/extra round trip. This threshold based scheme could be
/// replaced by using the is_inherent() API if needed
const PROTOCOL_UNIT_SIZE_THRESHOLD: NonZeroUsize = NonZeroUsize::new(32).expect("Not zero; qed");

/// The protocol unit info carried in the compact response
#[derive(Encode, Decode)]
struct ProtocolUnitInfo<ProtocolUnitId, ProtocolUnit>
where
    ProtocolUnitId: Encode + Decode,
    ProtocolUnit: Encode + Decode,
{
    /// The protocol unit Id
    id: ProtocolUnitId,

    /// The server can optionally return the protocol unit
    /// as part of the initial response. No further
    /// action is needed on client side to resolve it
    unit: Option<ProtocolUnit>,
}

/// The compact response
#[derive(Encode, Decode)]
struct CompactResponse<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
where
    DownloadUnitId: Encode + Decode,
    ProtocolUnitId: Encode + Decode,
    ProtocolUnit: Encode + Decode,
{
    /// The download unit
    download_unit_id: DownloadUnitId,

    /// List of the protocol units Ids.
    protocol_units: Vec<ProtocolUnitInfo<ProtocolUnitId, ProtocolUnit>>,
}

/// Request for missing transactions
#[derive(Encode, Decode)]
struct MissingEntriesRequest<DownloadUnitId, ProtocolUnitId>
where
    DownloadUnitId: Encode + Decode,
    ProtocolUnitId: Encode + Decode,
{
    /// The download unit
    download_unit_id: DownloadUnitId,

    /// Map of missing entry Id ->  protocol unit Id.
    /// The missing entry Id is an opaque identifier used by the client
    /// side. The server side just returns it as is with the response.
    protocol_unit_ids: BTreeMap<u64, ProtocolUnitId>,
}

/// Response for missing transactions
#[derive(Encode, Decode)]
struct MissingEntriesResponse<ProtocolUnit>
where
    ProtocolUnit: Encode + Decode,
{
    /// Map of missing entry Id ->  protocol unit.
    protocol_units: BTreeMap<u64, ProtocolUnit>,
}

struct ResolveContext<ProtocolUnitId, ProtocolUnit> {
    resolved: BTreeMap<u64, Resolved<ProtocolUnitId, ProtocolUnit>>,
    local_miss: BTreeMap<u64, ProtocolUnitId>,
}

pub(crate) struct CompactBlockClient<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
where
    DownloadUnitId: Encode + Decode,
    ProtocolUnitId: Encode + Decode,
    ProtocolUnit: Encode + Decode,
{
    pub(crate) backend: Arc<
        dyn ProtocolBackend<DownloadUnitId, ProtocolUnitId, ProtocolUnit> + Send + Sync + 'static,
    >,
}

impl<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
    CompactBlockClient<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
where
    DownloadUnitId: Encode + Decode + Clone,
    ProtocolUnitId: Encode + Decode + Clone,
    ProtocolUnit: Encode + Decode + Clone,
{
    /// Tries to resolve the entries in CompactResponse locally
    fn resolve_local(
        &self,
        compact_response: &CompactResponse<DownloadUnitId, ProtocolUnitId, ProtocolUnit>,
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

            match self
                .backend
                .protocol_unit(&compact_response.download_unit_id, id)
            {
                Ok(Some(ret)) => {
                    context.resolved.insert(
                        index as u64,
                        Resolved {
                            protocol_unit_id: id.clone(),
                            protocol_unit: ret,
                            locally_resolved: true,
                        },
                    );
                }
                Ok(None) => {
                    context.local_miss.insert(index as u64, id.clone());
                }
                Err(err) => {
                    return Err(format!("resolve_local: protocol unit lookup: {err:?}").into())
                }
            }
        }

        Ok(context)
    }

    /// Fetches the missing entries from the server
    async fn resolve_misses(
        &self,
        compact_response: CompactResponse<DownloadUnitId, ProtocolUnitId, ProtocolUnit>,
        context: ResolveContext<ProtocolUnitId, ProtocolUnit>,
        stub: &dyn NetworkStub,
    ) -> Result<Vec<Resolved<ProtocolUnitId, ProtocolUnit>>, RelayError> {
        let ResolveContext {
            mut resolved,
            local_miss,
        } = context;
        let missing = local_miss.len();
        // Request the missing entries from the server
        let request = MissingEntriesRequest {
            download_unit_id: compact_response.download_unit_id.clone(),
            protocol_unit_ids: local_miss.clone(),
        }
        .encode();
        let missing_entries_response: MissingEntriesResponse<ProtocolUnit> =
            decode_response(stub.request_response(request, true).await)?;

        if missing_entries_response.protocol_units.len() != missing {
            return Err(format!(
                "resolve_misses: missing entries response mismatch: {}, {}",
                missing_entries_response.protocol_units.len(),
                missing
            )
            .into());
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
                return Err(format!(
                    "resolve_misses: response missing {missing_key}: {}",
                    missing
                )
                .into());
            }
        }

        Ok(resolved.into_values().collect())
    }
}

#[async_trait]
impl<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
    ProtocolClient<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
    for CompactBlockClient<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
where
    DownloadUnitId: Encode + Decode + Send + Clone + std::fmt::Debug,
    ProtocolUnitId: Encode + Decode + Send + Clone,
    ProtocolUnit: Encode + Decode + Send + Clone,
{
    fn build_initial_request(&self) -> Option<Vec<u8>> {
        // Nothing to do for compact blocks
        None
    }

    async fn resolve(
        &self,
        response: Vec<u8>,
        stub: Arc<dyn NetworkStub>,
    ) -> Result<(DownloadUnitId, Vec<Resolved<ProtocolUnitId, ProtocolUnit>>), RelayError> {
        let compact_response: CompactResponse<DownloadUnitId, ProtocolUnitId, ProtocolUnit> =
            Decode::decode(&mut response.as_ref())
                .map_err(|err| format!("resolve: decode compact_response: {err:?}"))?;

        // Try to resolve the hashes locally first.
        let context = self.resolve_local(&compact_response)?;
        if context.resolved.len() == compact_response.protocol_units.len() {
            trace!(
                target: LOG_TARGET,
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
            .resolve_misses(compact_response, context, stub.as_ref())
            .await?;
        trace!(
            target: LOG_TARGET,
            "relay::resolve: {:?}: resolved by server[{},{}]",
            download_unit_id,
            resolved.len(),
            misses,
        );
        Ok((download_unit_id, resolved))
    }
}

pub(crate) struct CompactBlockServer<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
where
    DownloadUnitId: Encode + Decode,
    ProtocolUnitId: Encode + Decode,
    ProtocolUnit: Encode + Decode,
{
    pub(crate) backend: Arc<
        dyn ProtocolBackend<DownloadUnitId, ProtocolUnitId, ProtocolUnit> + Send + Sync + 'static,
    >,
}

#[async_trait]
impl<DownloadUnitId, ProtocolUnitId, ProtocolUnit> ProtocolServer<DownloadUnitId>
    for CompactBlockServer<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
where
    DownloadUnitId: Encode + Decode + Clone,
    ProtocolUnitId: Encode + Decode + Clone,
    ProtocolUnit: Encode + Decode,
{
    fn build_initial_response(
        &self,
        download_unit_id: &DownloadUnitId,
        _initial_request: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, RelayError> {
        // Return the hash of the members in the download unit.
        let members = self.backend.download_unit_members(download_unit_id)?;
        let response = CompactResponse {
            download_unit_id: download_unit_id.clone(),
            protocol_units: members
                .into_iter()
                .map(|(id, unit)| {
                    let unit = if unit.encoded_size() <= PROTOCOL_UNIT_SIZE_THRESHOLD.get() {
                        Some(unit)
                    } else {
                        None
                    };
                    ProtocolUnitInfo { id, unit }
                })
                .collect(),
        };
        Ok(response.encode())
    }

    fn on_request(&self, request: Vec<u8>) -> Result<Vec<u8>, RelayError> {
        let req: MissingEntriesRequest<DownloadUnitId, ProtocolUnitId> =
            match Decode::decode(&mut request.as_ref()) {
                Ok(req) => req,
                Err(err) => {
                    return Err(RelayError::from(format!(
                        "on_request: decode missing entries: {err:?}"
                    )))
                }
            };

        let mut protocol_units = BTreeMap::new();
        let total_len = req.protocol_unit_ids.len();
        for (missing_id, protocol_unit_id) in req.protocol_unit_ids {
            match self
                .backend
                .protocol_unit(&req.download_unit_id, &protocol_unit_id)
            {
                Ok(Some(ret)) => {
                    protocol_units.insert(missing_id, ret);
                }
                Ok(None) => {
                    warn!(
                        target: LOG_TARGET,
                        "relay::on_request: missing entry not found"
                    );
                }
                Err(err) => return Err(format!("on_request: missing entry lookup: {err:?}").into()),
            }
        }
        if total_len != protocol_units.len() {
            warn!(
                target: LOG_TARGET,
                "relay::compact_blocks::on_request: could not resolve all entries: {total_len}/{}",
                protocol_units.len()
            );
        }
        let response = MissingEntriesResponse { protocol_units };

        Ok(response.encode())
    }
}
