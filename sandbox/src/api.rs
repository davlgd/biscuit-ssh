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
//! read. Every error is `{"error": "..."}`, never Docker's own words.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::de::DeserializeOwned;
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
    /// Fingerprint of the bastion's host key.
    bastion_host_key: String,
    /// The bastion's `known_hosts` line, to trust it without a prompt.
    bastion_known_hosts: String,
    token: String,
    /// The command to connect, once the token is saved to `<name>.token`.
    command: String,
}

/// A sandbox, as listed.
#[derive(Debug, Serialize)]
struct Summary {
    name: String,
    image: String,
    status: Status,
    /// Unset while the sandbox is being created.
    expires_at: Option<u64>,
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
        .method_not_allowed_fallback(|| async { error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed") })
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(Arc::clone(&sandboxes), authenticate))
        .with_state(sandboxes)
}

/// Lets allowed clients through, and marks responses as not cacheable;
/// errors raised by the framework itself get the JSON form too.
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
    let json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes().starts_with(b"application/json"));
    let status = response.status();
    if (status.is_client_error() || status.is_server_error()) && !json {
        let reason = status.canonical_reason().unwrap_or("error").to_lowercase();
        response = error(status, &reason);
    }
    let no_store = HeaderValue::from_static("no-store");
    response.headers_mut().insert(header::CACHE_CONTROL, no_store);
    response
}

/// Parses a JSON body, whatever its content type says; an empty body is the
/// default request when there is one.
fn parse<T: DeserializeOwned>(
    body: Result<Bytes, BytesRejection>,
    default: Option<T>,
) -> Result<T, (StatusCode, String)> {
    let body = body.map_err(|rejection| match rejection.status() {
        StatusCode::PAYLOAD_TOO_LARGE => (StatusCode::PAYLOAD_TOO_LARGE, "request too large".to_owned()),
        _ => (StatusCode::BAD_REQUEST, "invalid request".to_owned()),
    })?;
    match (body.is_empty(), default) {
        (true, Some(default)) => Ok(default),
        _ => serde_json::from_slice(&body).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid request: {e}"))),
    }
}

async fn create(
    State(sandboxes): State<Arc<Sandboxes>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: CreateRequest = match parse(body, None) {
        Ok(body) => body,
        Err((status, message)) => return error(status, &message),
    };
    let image = match body.image.parse::<ImageRef>() {
        Ok(image) => image,
        Err(e) => return error(StatusCode::BAD_REQUEST, &format!("invalid image reference: {e}")),
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
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let RenewRequest { ttl } = match parse(body, Some(RenewRequest::default())) {
        Ok(body) => body,
        Err((status, message)) => return error(status, &message),
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
            expires_at: (sandbox.status != Status::Creating).then_some(sandbox.expires_at),
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
        "biscuit-ssh ssh --bastion {} -t {}.token {login} {family}",
        settings.bastion.address, lease.name
    );
    LeaseResponse {
        name: lease.name,
        image: lease.image,
        image_id: lease.image_id,
        expires_at: lease.expires_at,
        client_ip: lease.client,
        login,
        bastion: settings.bastion.address.clone(),
        bastion_host_key: settings.bastion.fingerprint.clone(),
        bastion_known_hosts: settings.bastion.known_hosts.clone(),
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
        Failure::ImageUnusable(_) => StatusCode::UNPROCESSABLE_ENTITY,
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
