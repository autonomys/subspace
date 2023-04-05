//! Compact block implementation.

use crate::{PoolBackend, ProtocolClient, ProtocolInitialRequest, ProtocolServer, RelayError};
use async_trait::async_trait;
use codec::{Decode, Encode};
use std::sync::Arc;

/// The compact response
#[derive(Encode, Decode)]
struct CompactResponse {
    /// List of the protocol units Ids.
    protocol_unit_id: Vec<Vec<u8>>,
}

//type DownloadUnitId: Encode + Decode;
//type ProtocolUnitId: Encode + Decode;
pub(crate) struct CompactBlockClient<DownloadUnitId, ProtocolUnitId>
where
    DownloadUnitId: Encode + Decode,
    ProtocolUnitId: Encode + Decode,
{
    pub(crate) backend:
        Arc<dyn PoolBackend<DownloadUnitId, ProtocolUnitId> + Send + Sync + 'static>,
}

#[async_trait]
impl<DownloadUnitId, ProtocolUnitId> ProtocolClient<DownloadUnitId>
    for CompactBlockClient<DownloadUnitId, ProtocolUnitId>
where
    DownloadUnitId: Encode + Decode,
    ProtocolUnitId: Encode + Decode,
{
    fn build_request(&self) -> ProtocolInitialRequest {
        // Nothing to do for compact blocks
        None
    }

    async fn resolve(&self) -> Vec<u8> {
        // look up the list of hashes
        // send request for missing hashes
        // make union of both
        unimplemented!()
    }
}

pub(crate) struct CompactBlockServer;

#[async_trait]
impl<DownloadUnitId> ProtocolServer<DownloadUnitId> for CompactBlockServer
where
    DownloadUnitId: Encode + Decode,
{
    fn build_response(
        &self,
        id: &DownloadUnitId,
        _protocol_request: ProtocolInitialRequest,
    ) -> Result<Vec<u8>, RelayError> {
        // Walk the extrinsics in the block, fill the list of hashes.
        panic!("xxx");
    }

    fn on_message(&self) {
        // look up the missing hashes for the block, send back the contents
        unimplemented!()
    }
}
