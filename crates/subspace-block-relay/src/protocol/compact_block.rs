//! Compact block implementation.

use crate::protocol::{
    ProtocolBackend, ProtocolClient, ProtocolRequest, ProtocolResponse, ProtocolServer,
};
use crate::utils::RequestResponseStub;
use crate::RelayError;
use async_trait::async_trait;
use codec::{Decode, Encode};
use std::sync::Arc;

/// The compact response
#[derive(Encode, Decode)]
struct CompactResponse {
    /// List of the protocol units Ids.
    protocol_unit_ids: Vec<Vec<u8>>,
}

/// Request for missing transactions
#[derive(Encode, Decode)]
struct MissingEntriesRequest {
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
    DownloadUnitId: Encode + Decode,
    ProtocolUnitId: Encode + Decode,
    ProtocolUnit: Encode + Decode,
{
    fn build_request(&self) -> Option<ProtocolRequest> {
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

        // Look up the protocol units from the backend
        let mut protocol_units = Vec::new();
        let mut missing_ids = Vec::new();
        for protocol_unit_id in compact_response.protocol_unit_ids {
            let id: ProtocolUnitId = Decode::decode(&mut protocol_unit_id.as_ref())
                .map_err(|err| format!("resolve: decode protocol_unit_id: {err:?}"))?;
            match self.backend.protocol_unit(&id) {
                Ok(Some(ret)) => protocol_units.push(ret),
                Ok(None) => missing_ids.push(id.encode()),
                Err(err) => return Err(format!("resolve: protocol unit lookup: {err:?}")),
            }
        }

        // All the entries could be resolved locally
        if missing_ids.is_empty() {
            return Ok(protocol_units);
        }

        // Slow path, request the missing entries
        let request = MissingEntriesRequest {
            protocol_unit_ids: missing_ids.clone(),
        }
        .encode();
        // Send the request, wait for response

        let mut response = Vec::<u8>::new();
        let missing_entries_response: MissingEntriesResponse =
            Decode::decode(&mut response.as_ref())
                .map_err(|err| format!("resolve: decode missing_entries_response: {err:?}"))?;
        if missing_entries_response.protocol_units.len() != missing_ids.len() {
            return Err(format!(
                "resolve: missing entries response mismatch: {}, {}",
                missing_entries_response.protocol_units.len(),
                missing_ids.len()
            ));
        }
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
    fn build_response(
        &self,
        id: &DownloadUnitId,
        _initial_request: Option<ProtocolRequest>,
    ) -> Result<Vec<u8>, RelayError> {
        // Return the hash of the members in the download unit.
        let members = self.backend.download_unit_members(id)?;
        let response = CompactResponse {
            protocol_unit_ids: members.iter().map(|(id, _)| id.encode()).collect(),
        };
        Ok(response.encode())
    }

    fn on_message(&self) {
        // look up the missing hashes for the block, send back the contents
        unimplemented!()
    }
}
