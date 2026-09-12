//! HTTP API, see [`biscuit_ssh_core::api`].

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use biscuit_ssh_core::api::{CertificateRequest, CertificateResponse, ErrorResponse};
use tokio::sync::Semaphore;

use crate::issue::{IssueError, Issuer};

/// Largest accepted request body: a maximal token plus a public key.
const MAX_BODY: usize = 32 * 1024;

struct AppState {
    issuer: Issuer,
    /// Proxies allowed to report the client address in `X-Forwarded-For`.
    trusted_proxies: Vec<IpAddr>,
    /// Bounds concurrent issuances, which are CPU-bound. Requests beyond it
    /// are refused rather than queued, so load cannot pile up in memory.
    workers: Arc<Semaphore>,
}

/// Builds the API router.
pub fn router(issuer: Issuer, trusted_proxies: &[IpAddr]) -> Router {
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get());
    let state = Arc::new(AppState {
        issuer,
        trusted_proxies: trusted_proxies.iter().map(IpAddr::to_canonical).collect(),
        workers: Arc::new(Semaphore::new(workers)),
    });
    Router::new()
        .route("/v1/certificates", post(certificates))
        .route("/v1/ca", get(ca))
        .route("/v1/root-key", get(root_key))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

async fn certificates(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CertificateRequest>,
) -> Result<Json<CertificateResponse>, IssueError> {
    let source_ip = client_ip(peer.ip(), &headers, &state.trusted_proxies)?;
    let permit = Arc::clone(&state.workers)
        .try_acquire_owned()
        .map_err(|_| IssueError::Busy)?;
    let task_state = Arc::clone(&state);
    // The permit moves into the task: a blocking task keeps running when the
    // request is cancelled, and must keep holding its slot until it ends.
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        task_state.issuer.issue(&body, source_ip)
    })
    .await
    .map_err(|_| IssueError::Internal)?
    .map(Json)
}

async fn ca(State(state): State<Arc<AppState>>) -> Result<String, IssueError> {
    state
        .issuer
        .authority
        .ca
        .public_key()
        .to_openssh()
        .map_err(|_| IssueError::Internal)
}

async fn root_key(State(state): State<Arc<AppState>>) -> String {
    state.issuer.authority.verifier.root_key().to_string()
}

/// The address certificates are bound to.
///
/// It is the TCP peer, unless the peer is a trusted proxy: then it is the
/// last `X-Forwarded-For` entry, the one that proxy appended. Earlier
/// entries come from the client and are ignored, so this supports exactly
/// one proxy in front of the issuer, not a chain of them.
fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted_proxies: &[IpAddr]) -> Result<IpAddr, IssueError> {
    if !trusted_proxies.contains(&peer.to_canonical()) {
        return Ok(peer);
    }
    let missing = || IssueError::BadRequest("missing or invalid X-Forwarded-For from trusted proxy".to_owned());
    headers
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(|last| last.trim().parse().ok())
        .ok_or_else(missing)
}

impl IntoResponse for IssueError {
    fn into_response(self) -> Response {
        let (status, error) = match &self {
            Self::BadRequest(reason) => (StatusCode::BAD_REQUEST, reason.as_str()),
            Self::Forbidden { kind, .. } => (StatusCode::FORBIDDEN, *kind),
            Self::Busy => (StatusCode::SERVICE_UNAVAILABLE, "busy, retry later"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };
        let (source_ip, time) = match self {
            Self::Forbidden { source_ip, time, .. } => (Some(source_ip), Some(time)),
            _ => (None, None),
        };
        let body = ErrorResponse {
            error: error.to_owned(),
            source_ip,
            time,
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn trusts_forwarded_for_only_from_trusted_proxies() {
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        let client: IpAddr = "192.0.2.7".parse().unwrap();
        let spoofed = headers(&["203.0.113.9"]);

        assert_eq!(client_ip(client, &spoofed, &[proxy]).unwrap(), client);
        assert_eq!(client_ip(client, &spoofed, &[]).unwrap(), client);

        let forwarded = headers(&["203.0.113.9, 192.0.2.7"]);
        assert_eq!(client_ip(proxy, &forwarded, &[proxy]).unwrap(), client);
        let split = headers(&["203.0.113.9", "192.0.2.7"]);
        assert_eq!(client_ip(proxy, &split, &[proxy]).unwrap(), client);
        let mapped_proxy = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(client_ip(mapped_proxy, &forwarded, &[proxy]).unwrap(), client);

        assert!(client_ip(proxy, &headers(&[]), &[proxy]).is_err());
        assert!(client_ip(proxy, &headers(&["192.0.2.7, junk"]), &[proxy]).is_err());
    }
}
