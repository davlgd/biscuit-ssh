//! The REST API.
//!
//! - `POST /v1/sandboxes` `{"image": "alpine:3.20", "ttl": 3600}` → 201,
//!   a [`LeaseResponse`];
//! - `POST /v1/sandboxes/{name}/renew` `{"ttl": 3600}` (body optional) →
//!   200, a new [`LeaseResponse`], the previous token being revoked;
//! - `DELETE /v1/sandboxes/{name}` → 204, the token revoked and the
//!   container removed;
//! - `GET /v1/sandboxes` → 200, the sandboxes, without tokens.
//!
//! Only allowed client addresses may call it: any other request, whatever
//! it is, gets `401 {"error": "authentication failed"}` before its body is
//! read. Errors are `{"error": "..."}` with fixed messages.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::image::ImageRef;
use crate::lifecycle::{Failure, Lease, Sandboxes};
use crate::state::Status;

/// Largest request body accepted.
const MAX_BODY: usize = 4 * 1024;

/// Body of `POST /v1/sandboxes`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    /// Docker Hub image, e.g. `alpine:3.20`.
    image: String,
    /// Lifetime in seconds, at most the configured one (the default).
    ttl: Option<u64>,
}

/// Body of `POST /v1/sandboxes/{name}/renew`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewRequest {
    /// Lifetime in seconds from now.
    ttl: Option<u64>,
}

/// A sandbox and how to reach it. Contains the token: never cached.
#[derive(Debug, Serialize)]
struct LeaseResponse {
    name: String,
    image: String,
    image_id: String,
    /// First second the token no longer allows, since the Unix epoch.
    expires_at: u64,
    /// The address the token is restricted to: connect to the bastion from it.
    client_ip: IpAddr,
    /// Login for the bastion, `account@name`.
    login: String,
    bastion: String,
    bastion_host_key: String,
    token: String,
    /// The command to connect, once the token is saved to `sandbox.token`.
    command: String,
}

/// A sandbox, as listed.
#[derive(Debug, Serialize)]
struct Summary {
    name: String,
    image: String,
    status: Status,
    expires_at: u64,
    client_ip: IpAddr,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

/// Builds the API router.
pub fn router(sandboxes: Arc<Sandboxes>) -> Router {
    Router::new()
        .route("/v1/sandboxes", post(create).get(list))
        .route("/v1/sandboxes/{name}", axum::routing::delete(delete))
        .route("/v1/sandboxes/{name}/renew", post(renew))
        .fallback(|| async { error(StatusCode::NOT_FOUND, "not found") })
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(Arc::clone(&sandboxes), authenticate))
        .with_state(sandboxes)
}

/// Lets allowed clients through, and marks responses as not cacheable.
async fn authenticate(
    State(sandboxes): State<Arc<Sandboxes>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let allowed = &sandboxes.settings().allowed_clients;
    let mut response = match allowed.contains(&peer.ip().to_canonical()) {
        true => next.run(request).await,
        false => {
            tracing::warn!(client = %peer.ip(), "request refused: client not allowed");
            error(StatusCode::UNAUTHORIZED, "authentication failed")
        }
    };
    let no_store = HeaderValue::from_static("no-store");
    response.headers_mut().insert(header::CACHE_CONTROL, no_store);
    response
}

async fn create(
    State(sandboxes): State<Arc<Sandboxes>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Result<Json<CreateRequest>, JsonRejection>,
) -> Response {
    let Ok(Json(body)) = body else {
        return error(StatusCode::BAD_REQUEST, "invalid request");
    };
    let Ok(image) = body.image.parse::<ImageRef>() else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid image reference: only Docker Hub images are accepted",
        );
    };
    let client = peer.ip().to_canonical();
    match sandboxes.create(&image, body.ttl, client).await {
        Ok(lease) => (StatusCode::CREATED, Json(lease_response(&sandboxes, lease))).into_response(),
        Err(failure) => failure_response(&failure),
    }
}

async fn renew(
    State(sandboxes): State<Arc<Sandboxes>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    // The body is optional; when present, it must be a valid request,
    // whatever its content type says.
    let body = match body.is_empty() {
        true => Ok(RenewRequest::default()),
        false => serde_json::from_slice::<RenewRequest>(&body),
    };
    let Ok(RenewRequest { ttl }) = body else {
        return error(StatusCode::BAD_REQUEST, "invalid request");
    };
    match sandboxes.renew(&name, ttl, peer.ip().to_canonical()).await {
        Ok(lease) => Json(lease_response(&sandboxes, lease)).into_response(),
        Err(failure) => failure_response(&failure),
    }
}

async fn delete(State(sandboxes): State<Arc<Sandboxes>>, Path(name): Path<String>) -> Response {
    match sandboxes.delete(&name).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(failure) => failure_response(&failure),
    }
}

async fn list(State(sandboxes): State<Arc<Sandboxes>>) -> Response {
    let summaries: Vec<Summary> = sandboxes
        .list()
        .await
        .into_iter()
        .map(|(name, sandbox)| Summary {
            name,
            image: sandbox.image,
            status: sandbox.status,
            expires_at: sandbox.expires_at,
            client_ip: sandbox.client,
        })
        .collect();
    Json(summaries).into_response()
}

fn lease_response(sandboxes: &Sandboxes, lease: Lease) -> LeaseResponse {
    let settings = sandboxes.settings();
    let login = format!("{}@{}", settings.account, lease.name);
    // The token only accepts the client's address: keep ssh on its family.
    let family = if lease.client.is_ipv4() { "-4" } else { "-6" };
    let command = format!(
        "biscuit-ssh ssh --bastion {} -t sandbox.token {login} {family}",
        settings.bastion.address
    );
    LeaseResponse {
        name: lease.name,
        image: lease.image,
        image_id: lease.image_id,
        expires_at: lease.expires_at,
        client_ip: lease.client,
        login,
        bastion: settings.bastion.address.clone(),
        bastion_host_key: settings.bastion.host_key.clone(),
        token: lease.token,
        command,
    }
}

fn failure_response(failure: &Failure) -> Response {
    let status = match failure {
        Failure::NotFound | Failure::ImageNotFound => StatusCode::NOT_FOUND,
        Failure::Conflict(_) => StatusCode::CONFLICT,
        Failure::TooMany => StatusCode::TOO_MANY_REQUESTS,
        Failure::Ttl(_) => StatusCode::BAD_REQUEST,
        Failure::ImageUnusable => StatusCode::UNPROCESSABLE_ENTITY,
        Failure::Registry => StatusCode::BAD_GATEWAY,
        Failure::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    };
    error(status, &failure.to_string())
}

fn error(status: StatusCode, message: &str) -> Response {
    let body = ErrorBody {
        error: message.to_owned(),
    };
    (status, Json(body)).into_response()
}
