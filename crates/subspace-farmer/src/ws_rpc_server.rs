use crate::plot::Plot;
use async_trait::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::Error;
use log::debug;
use subspace_core_primitives::Piece;
use subspace_solving::SubspaceCodec;

#[rpc(server, client)]
pub trait Rpc {
    /// Get single piece by its index
    #[method(name = "getPiece")]
    async fn get_piece(&self, piece_index: u64) -> Result<Option<Piece>, Error>;
}

/// Farmer RPC server implementation.
///
/// Usage example:
/// ```rust
/// # async fn f() -> anyhow::Result<()> {
/// use jsonrpsee::ws_server::WsServerBuilder;
/// use subspace_farmer::{Identity, Plot};
/// use subspace_farmer::ws_rpc_server::{RpcServer, RpcServerImpl};
/// use subspace_solving::SubspaceCodec;
///
/// let base_directory = "/path/to/base/dir";
/// let ws_server_listen_addr = "127.0.0.1:0";
///
/// let identity = Identity::open_or_create(base_directory)?;
/// let plot = Plot::open_or_create(base_directory).await?;
/// let ws_server = WsServerBuilder::default().build(ws_server_listen_addr).await?;
/// let rpc_server = RpcServerImpl::new(plot, SubspaceCodec::new(&[0]));
/// let stop_handle = ws_server.start(rpc_server.into_rpc())?;
///
/// // Keep server running
///
/// Ok(())
/// # }
/// ```
pub struct RpcServerImpl {
    plot: Plot,
    subspace_codec: SubspaceCodec,
}

impl RpcServerImpl {
    pub fn new(plot: Plot, subspace_codec: SubspaceCodec) -> Self {
        Self {
            plot,
            subspace_codec,
        }
    }
}

#[async_trait]
impl RpcServer for RpcServerImpl {
    async fn get_piece(&self, piece_index: u64) -> Result<Option<Piece>, Error> {
        let mut piece = match self.plot.read(piece_index).await {
            Ok(encoding) => encoding,
            Err(error) => {
                debug!("Failed to find piece with index {}: {}", piece_index, error);

                return Ok(None);
            }
        };

        self.subspace_codec
            .decode(piece_index, &mut piece)
            .map_err(|error| {
                debug!(
                    "Failed to decode piece with index {}: {}",
                    piece_index, error
                );

                Error::Custom("Failed to decode piece".to_string())
            })?;

        Ok(Some(piece))
    }
}
