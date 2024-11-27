//! RPC API for the Subspace Gateway.

use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::{ErrorObject, ErrorObjectOwned};
use std::fmt;
use std::ops::{Deref, DerefMut};
use subspace_core_primitives::hashes::{blake3_hash, Blake3Hash};
use subspace_core_primitives::objects::GlobalObjectMapping;
use subspace_data_retrieval::object_fetcher::{self, ObjectFetcher};
use subspace_data_retrieval::piece_getter::ObjectPieceGetter;
use tracing::debug;

const SUBSPACE_ERROR: i32 = 9000;

/// The maximum number of objects that can be requested in a single RPC call.
///
/// If the returned objects are large, they could overflow the RPC server (or client) buffers,
/// despite this limit.
// TODO: turn this into a CLI option
const MAX_OBJECTS_PER_REQUEST: usize = 100;

/// Top-level error type for the RPC handler.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Too many mappings were supplied.
    #[error("Mapping count {count} exceeded request limit {MAX_OBJECTS_PER_REQUEST}")]
    TooManyMappings {
        /// The number of supplied mappings.
        count: usize,
    },

    /// The object fetcher failed.
    #[error(transparent)]
    ObjectFetcherError(#[from] object_fetcher::Error),

    /// The returned object data did not match the hash in the mapping.
    #[error(
        "Invalid object hash, mapping had {mapping_hash:?}, but fetched data had {data_hash:?}"
    )]
    InvalidObjectHash {
        /// The expected hash from the mapping.
        mapping_hash: Blake3Hash,
        /// The actual hash of the returned object data.
        data_hash: Blake3Hash,
    },
}

impl From<Error> for ErrorObjectOwned {
    fn from(error: Error) -> Self {
        ErrorObject::owned(SUBSPACE_ERROR + 1, format!("{error:?}"), None::<()>)
    }
}

/// Binary data, encoded as hex.
#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct HexData {
    #[serde(with = "hex")]
    pub data: Vec<u8>,
}

impl fmt::Debug for HexData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HexData({})", hex::encode(&self.data))
    }
}

impl fmt::Display for HexData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.data))
    }
}

impl From<Vec<u8>> for HexData {
    fn from(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl Deref for HexData {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for HexData {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

/// Provides rpc methods for interacting with a Subspace DSN Gateway.
#[rpc(client, server)]
pub trait SubspaceGatewayRpcApi {
    /// Get object data from DSN object mappings.
    /// Returns an error if any object fetch was unsuccessful.
    #[method(name = "subspace_fetchObject")]
    async fn fetch_object(&self, mappings: GlobalObjectMapping) -> Result<Vec<HexData>, Error>;
}

/// Subspace Gateway RPC configuration
pub struct SubspaceGatewayRpcConfig<PG>
where
    PG: ObjectPieceGetter + Send + Sync + 'static,
{
    /// DSN object fetcher instance.
    pub object_fetcher: ObjectFetcher<PG>,
}

/// Implements the [`SubspaceGatewayRpcApiServer`] trait for interacting with the Subspace Gateway.
pub struct SubspaceGatewayRpc<PG>
where
    PG: ObjectPieceGetter + Send + Sync + 'static,
{
    /// DSN object fetcher instance.
    object_fetcher: ObjectFetcher<PG>,
}

/// [`SubspaceGatewayRpc`] is used to fetch objects from the DSN.
impl<PG> SubspaceGatewayRpc<PG>
where
    PG: ObjectPieceGetter + Send + Sync + 'static,
{
    /// Creates a new instance of the `SubspaceGatewayRpc` handler.
    pub fn new(config: SubspaceGatewayRpcConfig<PG>) -> Self {
        Self {
            object_fetcher: config.object_fetcher,
        }
    }
}

#[async_trait]
impl<PG> SubspaceGatewayRpcApiServer for SubspaceGatewayRpc<PG>
where
    PG: ObjectPieceGetter + Send + Sync + 'static,
{
    async fn fetch_object(&self, mappings: GlobalObjectMapping) -> Result<Vec<HexData>, Error> {
        let count = mappings.objects().len();
        if count > MAX_OBJECTS_PER_REQUEST {
            debug!(%count, %MAX_OBJECTS_PER_REQUEST, "Too many mappings in request");
            return Err(Error::TooManyMappings { count });
        }

        let mut objects = Vec::with_capacity(count);
        // TODO: fetch concurrently
        for mapping in mappings.objects() {
            let data = self
                .object_fetcher
                .fetch_object(mapping.piece_index, mapping.offset)
                .await?;

            let data_hash = blake3_hash(&data);
            if data_hash != mapping.hash {
                debug!(?data_hash, ?mapping.hash, "Retrieved data did not match mapping hash");
                return Err(Error::InvalidObjectHash {
                    mapping_hash: mapping.hash,
                    data_hash,
                });
            }

            objects.push(data.into());
        }

        Ok(objects)
    }
}
