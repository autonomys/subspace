//! Relay protocol defines

use crate::utils::RequestResponseStub;
use crate::RelayError;
use async_trait::async_trait;
use codec::{Decode, Encode};

pub(crate) mod compact_block;

/// The resolved protocol unit and meta info
pub(crate) struct Resolved<ProtocolUnitId, ProtocolUnit> {
    /// The protocol unit Id.
    pub(crate) protocol_unit_id: ProtocolUnitId,

    /// The protocol unit
    pub(crate) protocol_unit: ProtocolUnit,

    /// If it was resolved from the local pool or if
    /// it had to be fetched from the server
    pub(crate) locally_resolved: bool,
}

/// The client side of the protocol used by RelayClient
#[async_trait]
pub(crate) trait ProtocolClient<DownloadUnitId, ProtocolUnitId, ProtocolUnit>:
    Send + Sync
where
    DownloadUnitId: Encode + Decode,
    ProtocolUnitId: Encode + Decode,
    ProtocolUnit: Encode + Decode,
{
    /// Builds the protocol portion of the initial request
    fn build_initial_request(&self) -> Option<Vec<u8>>;

    /// Resolve the initial response to produce the protocol units.
    async fn resolve(
        &self,
        response: Vec<u8>,
        stub: RequestResponseStub,
    ) -> Result<(DownloadUnitId, Vec<Resolved<ProtocolUnitId, ProtocolUnit>>), RelayError>;
}

/// The server side of the protocol used by RelayServer
pub(crate) trait ProtocolServer<DownloadUnitId>
where
    DownloadUnitId: Encode + Decode,
{
    /// Builds the protocol response for the request from the protocol client.
    fn build_initial_response(
        &self,
        download_unit_id: &DownloadUnitId,
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
    /// Returns the protocol units Ids for the given download unit.
    fn download_unit_members(&self, id: &DownloadUnitId)
        -> Result<Vec<ProtocolUnitId>, RelayError>;

    /// Returns the protocol unit contents with the given Id.
    fn protocol_unit(
        &self,
        download_unit_id: &DownloadUnitId,
        protocol_unit_id: &ProtocolUnitId,
        client: bool,
    ) -> Result<Option<ProtocolUnit>, RelayError>;
}
