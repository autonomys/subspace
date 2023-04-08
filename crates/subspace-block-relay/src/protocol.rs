//! Relay protocol defines

use crate::utils::RequestResponseStub;
use crate::RelayError;
use async_trait::async_trait;
use codec::{Decode, Encode};

pub(crate) mod compact_block;

/// The client side of the protocol used by RelayClient
#[async_trait]
pub(crate) trait ProtocolClient<DownloadUnitId, ProtocolUnit>: Send + Sync
where
    DownloadUnitId: Encode + Decode,
    ProtocolUnit: Encode + Decode,
{
    /// Builds the protocol portion of the initial request
    fn build_initial_request(&self) -> Option<Vec<u8>>;

    /// Resolve the initial response to produce the protocol units.
    async fn resolve(
        &self,
        response: Vec<u8>,
        stub: RequestResponseStub,
    ) -> Result<Vec<ProtocolUnit>, RelayError>;
}

/// The server side of the protocol used by RelayServer
pub(crate) trait ProtocolServer<DownloadUnitId>
where
    DownloadUnitId: Encode + Decode,
{
    /// Builds the protocol response for the request from the protocol client.
    fn build_initial_response(
        &self,
        id: &DownloadUnitId,
        initial_request: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, RelayError>;

    /// Handles the additional client messages during the reconcile phase.
    fn on_request(&self, request: Vec<u8>) -> Result<Vec<u8>, RelayError>;
}

/// The backend interface to read the relevant data
pub(crate) trait ProtocolBackend<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
where
    DownloadUnitId: Encode + Decode,
    ProtocolUnitId: Encode + Decode,
    ProtocolUnit: Encode + Decode,
{
    /// Returns all the protocol units for the given download unit.
    fn download_unit_members(
        &self,
        id: &DownloadUnitId,
    ) -> Result<Vec<(ProtocolUnitId, Vec<u8>)>, RelayError>;

    /// Returns the protocol unit contents with the given Id.
    fn protocol_unit(
        &self,
        download_unit_id: &DownloadUnitId,
        protocol_unit_id: &ProtocolUnitId,
    ) -> Result<Option<ProtocolUnit>, RelayError>;
}
