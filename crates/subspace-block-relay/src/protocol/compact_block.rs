//! Compact block implementation.

use crate::protocol::{ProtocolBackend, ProtocolClient, ProtocolInitialRequest, ProtocolServer};
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
impl<DownloadUnitId, ProtocolUnitId, ProtocolUnit> ProtocolClient<DownloadUnitId>
    for CompactBlockClient<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
where
    DownloadUnitId: Encode + Decode,
    ProtocolUnitId: Encode + Decode,
    ProtocolUnit: Encode + Decode,
{
    fn build_request(&self) -> ProtocolInitialRequest {
        // Nothing to do for compact blocks
        None
    }

    async fn resolve(&self, response: Vec<u8>) -> Result<Vec<u8>, RelayError> {
        let compact_response: CompactResponse =
            Decode::decode(&mut response.as_ref()).map_err(|err| {
                RelayError::InvalidInitialResponse(format!("Failed to decode: {err:?}"))
            })?;

        // Look up the protocol units from the backend
        for protocol_unit_id in compact_response.protocol_unit_ids {}
        Ok(vec![])
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
        _protocol_request: ProtocolInitialRequest,
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
