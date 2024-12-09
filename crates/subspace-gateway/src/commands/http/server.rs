use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Deserializer, Serialize};
use std::default::Default;
use std::sync::Arc;
use subspace_core_primitives::hashes::{blake3_hash, Blake3Hash};
use subspace_core_primitives::pieces::PieceIndex;
use subspace_core_primitives::BlockNumber;
use subspace_data_retrieval::object_fetcher::ObjectFetcher;
use subspace_data_retrieval::piece_getter::PieceGetter;
use tracing::{debug, error, trace};

pub(crate) struct ServerParameters<PG>
where
    PG: PieceGetter + Send + Sync + 'static,
{
    pub(crate) object_fetcher: ObjectFetcher<PG>,
    pub(crate) indexer_endpoint: String,
    pub(crate) http_endpoint: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct ObjectMapping {
    hash: Blake3Hash,
    piece_index: PieceIndex,
    piece_offset: u32,
    #[serde(deserialize_with = "string_to_u32")]
    block_number: BlockNumber,
}

fn string_to_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    s.parse::<u32>().map_err(serde::de::Error::custom)
}

/// Requests an object mapping with `key` from the indexer service.
async fn request_object_mapping(endpoint: &str, key: Blake3Hash) -> anyhow::Result<ObjectMapping> {
    let client = reqwest::Client::new();
    let object_mappings_url = format!("http://{}/objects/{}", endpoint, hex::encode(key));

    debug!(?key, ?object_mappings_url, "Requesting object mapping...");

    let response = client
        .get(&object_mappings_url)
        .send()
        .await?
        .json::<ObjectMapping>()
        .await;
    match &response {
        Ok(json) => {
            trace!(?key, ?json, "Received object mapping");
        }
        Err(err) => {
            error!(?key, ?err, ?object_mappings_url, "Request failed");
        }
    }

    response.map_err(|err| err.into())
}

/// Fetches a DSN object with `key`, using the mapping indexer service.
async fn serve_object<PG>(
    key: web::Path<Blake3Hash>,
    additional_data: web::Data<Arc<ServerParameters<PG>>>,
) -> impl Responder
where
    PG: PieceGetter + Send + Sync + 'static,
{
    let server_params = additional_data.into_inner();
    let key = key.into_inner();

    let Ok(object_mapping) = request_object_mapping(&server_params.indexer_endpoint, key).await
    else {
        return HttpResponse::BadRequest().finish();
    };

    if object_mapping.hash != key {
        error!(
            ?object_mapping,
            ?key,
            "Returned object mapping doesn't match requested hash"
        );
        return HttpResponse::ServiceUnavailable().finish();
    }

    let object_fetcher_result = server_params
        .object_fetcher
        .fetch_object(object_mapping.piece_index, object_mapping.piece_offset)
        .await;

    let object = match object_fetcher_result {
        Ok(object) => {
            trace!(?key, size=%object.len(), "Object fetched successfully");

            let data_hash = blake3_hash(&object);
            if data_hash != key {
                error!(
                    ?data_hash,
                    ?key,
                    "Retrieved data doesn't match requested mapping hash"
                );
                return HttpResponse::ServiceUnavailable().finish();
            }

            object
        }
        Err(err) => {
            error!(?key, ?err, "Failed to fetch object");
            return HttpResponse::ServiceUnavailable().finish();
        }
    };

    HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body(object)
}

pub async fn start_server<PG>(server_params: ServerParameters<PG>) -> std::io::Result<()>
where
    PG: PieceGetter + Send + Sync + 'static,
{
    let server_params = Arc::new(server_params);
    let http_endpoint = server_params.http_endpoint.clone();
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(server_params.clone()))
            .route("/data/{hash}", web::get().to(serve_object::<PG>))
    })
    .bind(http_endpoint)?
    .run()
    .await
}
