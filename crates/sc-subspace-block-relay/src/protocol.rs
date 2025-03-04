//! Relay protocol defines.

//!
//! The components in the system:
//! 1. Relay users like consensus, execution. They implement the use case
//!    specific logic that drives the relay protocol. This has a client
//!    side stub, and a server side task to process incoming requests.
//! 2. Relay protocol that is agnostic to the relay user. The protocol
//!    is abstracted to be reused for different use cases. The protocol
//!    also has corresponding client/server side components.
//! 3. Protocol backend: relay user specific abstraction used by the relay
//!    protocol to populate the protocol messages
//!
//! Nodes advertise/exchange DownloadUnits with each other. DownloadUnit has
//! two parts:
//! - ProtocolUnits: the part fetched by the relay protocol. This is bulk of
//!   the data transfer that we would like to optimize
//! - Rest of the download unit, handled directly by the relay user
//!
//! Examples:
//! 1. Consensus
//!    DownloadUnit = Block, ProtocolUnit = extrinsics
//!    The extrinsics are handled by the protocol, remaining block
//!    fields are directly filled by the caller. The protocol backend
//!    helps fetch blocks/transactions from the substrate backend
//! 2. Execution
//!    TODO
//! 3. Other possible use cases (e.g) reconcile/sync the transaction pool
//!    between two nodes. In this case, DownloadUnit = transaction pool,
//!    ProtocolUnit = transaction
//!
//! The download has two phases:
//! -  Initial request/response
//!    Ideally, download of all the protocol units in the download unit should
//!    be completed during this phase
//! -  Reconcile phase
//!    If the initial phase could not complete the download, additional
//!    request/response messages are initiated by the protocol to fetch the
//!    protocol units
//!

pub(crate) mod compact_block;

use crate::types::RelayError;
use parity_scale_codec::{Decode, Encode};

/// The resolved protocol unit related info
pub(crate) struct Resolved<ProtocolUnitId, ProtocolUnit> {
    /// The protocol unit Id.
    pub(crate) protocol_unit_id: ProtocolUnitId,

    /// The protocol unit
    pub(crate) protocol_unit: ProtocolUnit,

    /// If it was resolved locally, or if it had to be
    /// fetched from the server (local miss)
    pub(crate) locally_resolved: bool,
}

/// The relay user specific backend for the client side
pub(crate) trait ClientBackend<ProtocolUnitId, ProtocolUnit>: Send + Sync {
    /// Returns the protocol unit for the protocol unit id.
    fn protocol_unit(&self, protocol_unit_id: &ProtocolUnitId) -> Option<ProtocolUnit>;
}

/// The relay user specific backend for the server side
pub(crate) trait ServerBackend<DownloadUnitId, ProtocolUnitId, ProtocolUnit>:
    Send + Sync
{
    /// Returns the protocol units for the given download unit, to be returned
    /// with the initial response. Some of the items may have the full entry
    /// along with the Id (e.g) consensus may choose to return the full
    /// transaction for inherents/small transactions in the block. And return
    /// only the Tx hash for the remaining extrinsics. Further protocol
    /// handshake would be used only for resolving these remaining items.
    fn download_unit_members(
        &self,
        id: &DownloadUnitId,
    ) -> Result<Vec<ProtocolUnitInfo<ProtocolUnitId, ProtocolUnit>>, RelayError>;

    /// Returns the protocol unit for the given download/protocol unit.
    fn protocol_unit(
        &self,
        download_unit_id: &DownloadUnitId,
        protocol_unit_id: &ProtocolUnitId,
    ) -> Option<ProtocolUnit>;
}

/// The protocol unit info carried in the initial response
#[derive(Encode, Decode)]
pub(crate) struct ProtocolUnitInfo<ProtocolUnitId, ProtocolUnit> {
    /// The protocol unit Id
    pub(crate) id: ProtocolUnitId,

    /// The server can optionally return the protocol unit
    /// as part of the initial response. No further
    /// action is needed on client side to resolve it
    pub(crate) unit: Option<ProtocolUnit>,
}
