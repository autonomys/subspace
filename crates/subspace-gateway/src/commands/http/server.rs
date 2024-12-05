use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Deserializer, Serialize};
use std::default::Default;
use std::sync::Arc;
use subspace_core_primitives::hashes::{blake3_hash, Blake3Hash};
use subspace_core_primitives::pieces::PieceIndex;
use subspace_core_primitives::BlockNumber;
use subspace_data_retrieval::object_fetcher::ObjectFetcher;
use subspace_data_retrieval::piece_getter::ObjectPieceGetter;
use tracing::{debug, error, trace};

pub(crate) struct ServerParameters<PG>
where
    PG: ObjectPieceGetter + Send + Sync + 'static,
{
    pub(crate) object_fetcher: ObjectFetcher<PG>,
    pub(crate) indexer_endpoint: String,
    pub(crate) http_endpoint: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct ObjectMapping {
    hash: String,
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

async fn request_object_mappings(endpoint: String, key: String) -> anyhow::Result<ObjectMapping> {
    let client = reqwest::Client::new();
    let object_mappings_url = format!("http://{}/objects/{}", endpoint, key,);

    debug!(?key, ?object_mappings_url, "Requesting object mapping...");

    let response = client
        .get(object_mappings_url.clone())
        .send()
        .await?
        .json::<ObjectMapping>()
        .await;
    match &response {
        Ok(json) => {
            trace!(?key, ?json, "Requested object mapping.");
        }
        Err(err) => {
            error!(?key, ?err, ?object_mappings_url, "Request failed");
        }
    }

    response.map_err(|err| err.into())
}

async fn serve_object<PG>(
    key: web::Path<String>,
    additional_data: web::Data<Arc<ServerParameters<PG>>>,
) -> impl Responder
where
    PG: ObjectPieceGetter + Send + Sync + 'static,
{
    let server_params = additional_data.into_inner();
    let key = key.into_inner();

    // Validate object hash
    let decode_result = hex::decode(key.clone());
    let object_hash = match decode_result {
        Ok(hash) => {
            if hash.len() != Blake3Hash::SIZE {
                error!(?key, ?hash, "Invalid hash provided.");
                return HttpResponse::BadRequest().finish();
            }

            hash
        }
        Err(err) => {
            error!(?key, ?err, "Invalid hash provided.");
            return HttpResponse::BadRequest().finish();
        }
    };

    let Ok(object_mapping) =
        request_object_mappings(server_params.indexer_endpoint.clone(), key.clone()).await
    else {
        return HttpResponse::BadRequest().finish();
    };

    if object_mapping.hash != key {
        error!(
            ?key,
            object_mapping_hash=?object_mapping.hash,
            "Requested hash doesn't match object mapping."
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

            let data_hash = {
                let data_hash = blake3_hash(&object);
                <Blake3Hash as AsRef<[u8]>>::as_ref(&data_hash).to_vec()
            };
            if data_hash != object_hash {
                error!(
                    ?data_hash,
                    ?object_hash,
                    "Retrieved data did not match mapping hash"
                );
                return HttpResponse::ServiceUnavailable().finish();
            }

            object
        }
        Err(err) => {
            error!(?key, ?err, "Failed to fetch object.");
            return HttpResponse::ServiceUnavailable().finish();
        }
    };

    HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body(object)
}

pub async fn start_server<PG>(server_params: ServerParameters<PG>) -> std::io::Result<()>
where
    PG: ObjectPieceGetter + Send + Sync + 'static,
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
