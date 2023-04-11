//! Compact block implementation.

use crate::protocol::{ProtocolBackend, ProtocolClient, ProtocolServer, Resolved};
use crate::utils::RequestResponseStub;
use crate::{RelayError, LOG_TARGET};
use async_trait::async_trait;
use codec::{Decode, Encode};
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::{info, warn};

/// The compact response
#[derive(Encode, Decode)]
struct CompactResponse<DownloadUnitId, ProtocolUnitId>
where
    DownloadUnitId: Encode + Decode,
    ProtocolUnitId: Encode + Decode,
{
    /// The download unit
    download_unit_id: DownloadUnitId,

    /// List of the protocol units Ids.
    protocol_unit_ids: Vec<ProtocolUnitId>,
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
        stub: RequestResponseStub,
    ) -> Result<(DownloadUnitId, Vec<Resolved<ProtocolUnitId, ProtocolUnit>>), RelayError> {
        let compact_response: CompactResponse<DownloadUnitId, ProtocolUnitId> =
            Decode::decode(&mut response.as_ref())
                .map_err(|err| format!("resolve: decode compact_response: {err:?}"))?;

        // Look up the protocol units from the backend
        let mut protocol_units = BTreeMap::new();
        let mut missing_ids = BTreeMap::new();
        let total_len = compact_response.protocol_unit_ids.len();
        for (index, protocol_unit_id) in compact_response.protocol_unit_ids.iter().enumerate() {
            match self.backend.protocol_unit(
                &compact_response.download_unit_id,
                protocol_unit_id,
                true,
            ) {
                Ok(Some(ret)) => {
                    protocol_units.insert(
                        index as u64,
                        Resolved {
                            protocol_unit_id: protocol_unit_id.clone(),
                            protocol_unit: ret,
                            locally_resolved: true,
                        },
                    );
                }
                Ok(None) => {
                    missing_ids.insert(index as u64, protocol_unit_id.clone());
                }
                Err(err) => return Err(format!("resolve: protocol unit lookup: {err:?}").into()),
            }
        }
        let missing_ids_len = missing_ids.len();

        // All the entries could be resolved locally
        if protocol_units.len() == total_len {
            info!(
                target: LOG_TARGET,
                "relay::resolve: {:?}: resolved locally[{total_len}]",
                compact_response.download_unit_id,
            );
            return Ok((
                compact_response.download_unit_id,
                protocol_units.into_values().collect(),
            ));
        }

        // Request the missing entries
        let request = MissingEntriesRequest {
            download_unit_id: compact_response.download_unit_id.clone(),
            protocol_unit_ids: missing_ids.clone(),
        };
        let missing_entries_response = stub
            .request_response::<MissingEntriesRequest<DownloadUnitId, ProtocolUnitId>,
                MissingEntriesResponse<ProtocolUnit>>(request, true)
            .await?;

        if missing_entries_response.protocol_units.len() != missing_ids.len() {
            return Err(format!(
                "resolve: missing entries response mismatch: {}, {}",
                missing_entries_response.protocol_units.len(),
                missing_ids_len
            )
            .into());
        }

        // Merge the resolved entries from the server
        for (missing_key, protocol_unit_id) in missing_ids.into_iter() {
            if let Some(protocol_unit) = missing_entries_response.protocol_units.get(&missing_key) {
                // TODO: avoid clone
                protocol_units.insert(
                    missing_key,
                    Resolved {
                        protocol_unit_id,
                        protocol_unit: protocol_unit.clone(),
                        locally_resolved: false,
                    },
                );
            } else {
                return Err(format!(
                    "resolve: missing entries response missing {missing_key}: {}",
                    missing_ids_len
                )
                .into());
            }
        }

        info!(
            target: LOG_TARGET,
            "relay::resolve: {:?}: resolved by server[{total_len},{},{}]",
            compact_response.download_unit_id,
            protocol_units.len(),
            missing_ids_len
        );
        Ok((
            compact_response.download_unit_id,
            protocol_units.into_values().collect(),
        ))
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
            protocol_unit_ids: members.iter().map(|(id, _)| id.clone()).collect(),
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
                .protocol_unit(&req.download_unit_id, &protocol_unit_id, false)
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
            info!(
                target: LOG_TARGET,
                "relay::compact_blocks::on_request: could not resolve all entries: {total_len}/{}",
                protocol_units.len()
            );
        }
        let response = MissingEntriesResponse { protocol_units };

        Ok(response.encode())
    }
}
