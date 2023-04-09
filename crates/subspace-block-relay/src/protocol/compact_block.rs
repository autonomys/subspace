//! Compact block implementation.

use crate::protocol::{ProtocolBackend, ProtocolClient, ProtocolServer};
use crate::utils::RequestResponseStub;
use crate::{RelayError, LOG_TARGET};
use async_trait::async_trait;
use codec::{Decode, Encode};
use std::sync::Arc;
use tracing::{info, trace, warn};

/// The compact response
#[derive(Encode, Decode)]
struct CompactResponse {
    /// The download unit
    download_unit_id: Vec<u8>,

    /// List of the protocol units Ids.
    protocol_unit_ids: Vec<Vec<u8>>,
}

/// Request for missing transactions
#[derive(Encode, Decode)]
struct MissingEntriesRequest {
    /// The download unit
    download_unit_id: Vec<u8>,

    /// List of the protocol units Ids.
    protocol_unit_ids: Vec<Vec<u8>>,
}

/// Response for missing transactions
#[derive(Encode, Decode)]
struct MissingEntriesResponse {
    /// List of the protocol units.
    protocol_units: Vec<Vec<u8>>,
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
impl<DownloadUnitId, ProtocolUnitId, ProtocolUnit> ProtocolClient<DownloadUnitId, ProtocolUnit>
    for CompactBlockClient<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
where
    DownloadUnitId: Encode + Decode + Send + std::fmt::Debug,
    ProtocolUnitId: Encode + Decode,
    ProtocolUnit: Encode + Decode + Send,
{
    fn build_initial_request(&self) -> Option<Vec<u8>> {
        // Nothing to do for compact blocks
        None
    }

    async fn resolve(
        &self,
        response: Vec<u8>,
        stub: RequestResponseStub,
    ) -> Result<Vec<ProtocolUnit>, RelayError> {
        let compact_response: CompactResponse = Decode::decode(&mut response.as_ref())
            .map_err(|err| format!("resolve: decode compact_response: {err:?}"))?;
        let download_unit_id_encoded = compact_response.download_unit_id.clone();
        let download_unit_id: DownloadUnitId =
            Decode::decode(&mut compact_response.download_unit_id.as_ref())
                .map_err(|err| format!("resolve: decode download_unit_id: {err:?}"))?;

        // Look up the protocol units from the backend
        let mut protocol_units = Vec::new();
        let mut missing_ids = Vec::new();
        let total_len = compact_response.protocol_unit_ids.len();
        for protocol_unit_id in compact_response.protocol_unit_ids {
            let pid = protocol_unit_id.clone();
            let id: ProtocolUnitId = Decode::decode(&mut protocol_unit_id.as_ref())
                .map_err(|err| format!("resolve: decode protocol_unit_id: {err:?}"))?;
            match self.backend.protocol_unit(&download_unit_id, &id, true) {
                Ok(Some(ret)) => protocol_units.push(ret),
                Ok(None) => missing_ids.push(pid),
                Err(err) => return Err(format!("resolve: protocol unit lookup: {err:?}").into()),
            }
        }

        // All the entries could be resolved locally
        if protocol_units.len() == total_len {
            trace!(
                target: LOG_TARGET,
                "relay::resolve: {download_unit_id:?}: resolved locally[{total_len}]",
            );
            return Ok(protocol_units);
        }

        // Request the missing entries
        let request = MissingEntriesRequest {
            download_unit_id: download_unit_id_encoded,
            protocol_unit_ids: missing_ids.clone(),
        };
        let missing_entries_response = stub
            .request_response::<MissingEntriesRequest, MissingEntriesResponse>(request, true)
            .await?;

        if missing_entries_response.protocol_units.len() != missing_ids.len() {
            return Err(format!(
                "resolve: missing entries response mismatch: {}, {}",
                missing_entries_response.protocol_units.len(),
                missing_ids.len()
            )
            .into());
        }
        trace!(
            target: LOG_TARGET,
            "relay::resolve: {download_unit_id:?}: resolved by server[{total_len},{},{}]",
            protocol_units.len(),
            missing_ids.len()
        );

        // TODO: reorder to match the order in compact_response
        for entry in missing_entries_response.protocol_units {
            let protocol_unit: ProtocolUnit = Decode::decode(&mut entry.as_ref())
                .map_err(|err| format!("resolve: decode protocol_unit: {err:?}"))?;
            protocol_units.push(protocol_unit);
        }

        Ok(protocol_units)
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
    DownloadUnitId: Encode + Decode,
    ProtocolUnitId: Encode + Decode,
    ProtocolUnit: Encode + Decode,
{
    fn build_initial_response(
        &self,
        id: &DownloadUnitId,
        _initial_request: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, RelayError> {
        // Return the hash of the members in the download unit.
        let members = self.backend.download_unit_members(id)?;
        let response = CompactResponse {
            download_unit_id: id.encode(),
            protocol_unit_ids: members.iter().map(|(id, _)| id.encode()).collect(),
        };
        Ok(response.encode())
    }

    fn on_request(&self, request: Vec<u8>) -> Result<Vec<u8>, RelayError> {
        let req: MissingEntriesRequest = match Decode::decode(&mut request.as_ref()) {
            Ok(req) => req,
            Err(err) => {
                return Err(RelayError::from(format!(
                    "on_request: decode missing entries: {err:?}"
                )))
            }
        };
        let download_unit_id: DownloadUnitId =
            Decode::decode(&mut req.download_unit_id.as_ref())
                .map_err(|err| format!("on_request: decode download_unit_id: {err:?}"))?;

        let mut protocol_units = Vec::new();
        let total_len = req.protocol_unit_ids.len();
        for protocol_unit_id in req.protocol_unit_ids {
            let id: ProtocolUnitId = Decode::decode(&mut protocol_unit_id.as_ref())
                .map_err(|err| format!("on_request: decode missing protocol_unit_id: {err:?}"))?;
            match self.backend.protocol_unit(&download_unit_id, &id, false) {
                Ok(Some(ret)) => protocol_units.push(ret.encode()),
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
