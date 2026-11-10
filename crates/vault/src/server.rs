use crate::extension::Issuer;
use crate::{
    crypto::*,
    protocol::*,
    store::Gate,
    witness::{WitnessAuthority, WitnessCommand},
};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
#[derive(Clone)]
struct App {
    gate: Arc<Gate>,
    issuer: Option<Arc<dyn Issuer>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Install {
    pub grant: Signed<Grant>,
    pub record: CiphertextRecord,
}
pub fn router(gate: Arc<Gate>) -> Router {
    router_with_issuer(gate, None)
}
pub fn router_with_issuer(gate: Arc<Gate>, issuer: Option<Arc<dyn Issuer>>) -> Router {
    Router::new()
        .route("/v1/install", post(install))
        .route("/v1/challenge", post(challenge))
        .route("/v1/release", post(release))
        .route("/v1/revoke", post(revoke))
        .route("/v1/issue", post(issue))
        .route("/v1/checkpoint", post(checkpoint))
        .route("/v1/quarantine", post(quarantine))
        .layer(DefaultBodyLimit::max(256 * 1024))
        .layer(middleware::from_fn(no_store))
        .with_state(App { gate, issuer })
}
pub fn witness_router(authority: Arc<WitnessAuthority>) -> Router {
    Router::new()
        .route("/v1/witness", post(witness))
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn(no_store))
        .with_state(authority)
}
async fn no_store(req: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}
type ApiError = (StatusCode, &'static str);
fn denied(_: impl std::fmt::Display) -> ApiError {
    (StatusCode::FORBIDDEN, "request denied")
}
fn now() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|n| n.as_secs())
        .map_err(denied)
}
fn current_time() -> anyhow::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn still_current(operation: &Operation) -> anyhow::Result<()> {
    let time = current_time()?;
    anyhow::ensure!(
        operation.not_before <= time && time < operation.expires,
        "operation expired during processing"
    );
    Ok(())
}
async fn install(State(a): State<App>, Json(i): Json<Install>) -> Result<StatusCode, ApiError> {
    let g = a.gate;
    tokio::task::spawn_blocking(move || g.install(&i.grant, &i.record))
        .await
        .map_err(denied)?
        .map_err(denied)?;
    Ok(StatusCode::CREATED)
}
async fn challenge(
    State(a): State<App>,
    Json(i): Json<Signed<Grant>>,
) -> Result<impl IntoResponse, ApiError> {
    let g = a.gate;
    let t = now()?;
    let c = tokio::task::spawn_blocking(move || g.challenge(&i, t))
        .await
        .map_err(denied)?
        .map_err(denied)?;
    Ok(Json(c))
}
async fn release(
    State(a): State<App>,
    Json(i): Json<ReleaseRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let g = a.gate;
    let c = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let result = g.release(&i, current_time()?)?;
        // Key UI, DB locks, witness and hardware calls may take time. A request
        // admitted before expiry cannot disclose after that deadline.
        still_current(&i.operation)?;
        Ok(result)
    })
    .await
    .map_err(denied)?
    .map_err(denied)?;
    Ok(Json(c))
}
async fn revoke(
    State(a): State<App>,
    Json(i): Json<Signed<Revocation>>,
) -> Result<StatusCode, ApiError> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        a.gate.revoke(&i)?;
        if let Some(issuer) = a.issuer {
            issuer.revoke_grant(i.payload.grant)?;
        }
        Ok(())
    })
    .await
    .map_err(denied)?
    .map_err(denied)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn issue(
    State(a): State<App>,
    Json(i): Json<ReleaseRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let issuer = a
        .issuer
        .ok_or((StatusCode::NOT_IMPLEMENTED, "issuer unavailable"))?;
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let permit = a
            .gate
            .prepare_issue(&i, current_time()?)
            .or_else(|_| a.gate.resume_issue(&i, current_time()?))?;
        let result = issuer.issue(&permit, current_time()?)?;
        if let Err(e) = a.gate.complete_issue(&permit) {
            issuer.revoke(permit.id())?;
            return Err(e);
        }
        if let Err(e) = still_current(&i.operation) {
            issuer.revoke(permit.id())?;
            return Err(e);
        }
        Ok(result)
    })
    .await
    .map_err(denied)?
    .map_err(denied)?;
    Ok(Json(result))
}
async fn witness(
    State(w): State<Arc<WitnessAuthority>>,
    Json(i): Json<Signed<WitnessCommand>>,
) -> Result<impl IntoResponse, ApiError> {
    let c = tokio::task::spawn_blocking(move || w.execute(i))
        .await
        .map_err(denied)?
        .map_err(denied)?;
    Ok(Json(c))
}

async fn checkpoint(
    State(a): State<App>,
    Json(grant): Json<Signed<Grant>>,
) -> Result<impl IntoResponse, ApiError> {
    let checkpoint = tokio::task::spawn_blocking(move || a.gate.checkpoint(&grant))
        .await
        .map_err(denied)?
        .map_err(denied)?;
    Ok(Json(checkpoint))
}
async fn quarantine(
    State(a): State<App>,
    Json(request): Json<Signed<Quarantine>>,
) -> Result<StatusCode, ApiError> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        a.gate.quarantine(&request)?;
        if let Some(issuer) = a.issuer {
            issuer.revoke_grant(request.payload.grant)?;
        }
        Ok(())
    })
    .await
    .map_err(denied)?
    .map_err(denied)?;
    Ok(StatusCode::NO_CONTENT)
}
