//! The admin API: a separate listener on loopback, every request carrying
//! `Authorization: Bearer <token>`. JSON in, JSON out; mutations are
//! idempotent (PUT twice or DELETE something absent is not an error).
//! Nothing here returns a credential: stream URLs are redacted.

use std::{future::Future, path::Path, sync::Arc};

use axum::{
    extract::{rejection::JsonRejection, Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::{
    db::{ActorCount, BlockKind, BlockRow, Follow, StreamRow},
    policy::{self, Policy, SourcePattern},
    stats::{CounterSnapshot, HostSnapshot},
    streams::{redact_url, stream_id, StreamState, StreamStatus},
};

// ---------------------------------------------------------------- token

/// The bearer token. `Debug` never shows it.
pub struct AdminToken(String);

impl std::fmt::Debug for AdminToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdminToken(..)")
    }
}

const MIN_TOKEN_LEN: usize = 32;

// The effective uid of this process.
//
// std has no `getuid()` and the crate does not depend on libc, so the one
// call it needs is declared here: std links the C library on every unix
// target this program runs on.
extern "C" {
    fn geteuid() -> u32;
}

/// The effective uid of this process: 0 for root.
fn effective_uid() -> u32 {
    // SAFETY: geteuid() takes no arguments, cannot fail and has no
    // preconditions.
    unsafe { geteuid() }
}

/// May this uid own the token file? Root may, and so may the process
/// itself. A file owned by anybody else is refused: its owner could
/// rewrite it and become the holder of the token.
fn owner_allowed(owner: u32, process: u32) -> bool {
    owner == 0 || owner == process
}

#[derive(Debug, PartialEq, Eq)]
pub enum TokenError {
    Unreadable(String),
    Symlink,
    NotAFile,
    /// any bit beyond owner read/write and group read (0640)
    TooOpen(u32),
    TooShort,
    Whitespace,
    /// owned by a user that is neither root nor this process
    ForeignOwner(u32),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Unreadable(e) => write!(f, "admin_token_file unreadable: {e}"),
            TokenError::Symlink => write!(f, "admin_token_file is a symlink"),
            TokenError::NotAFile => write!(f, "admin_token_file is not a regular file"),
            TokenError::TooOpen(mode) => write!(f, "admin_token_file mode {mode:04o} is too open: use 0600 or 0640"),
            TokenError::TooShort => write!(f, "admin_token_file holds fewer than {MIN_TOKEN_LEN} characters"),
            TokenError::Whitespace => write!(f, "admin_token_file must hold one token, no spaces"),
            TokenError::ForeignOwner(uid) => write!(f, "admin_token_file is owned by uid {uid}: only root or the service user may own it"),
        }
    }
}

impl AdminToken {
    /// Reads the token file. Refuses a symlink, anything but a regular file,
    /// any mode beyond 0640, and any owner but root or this process: the
    /// deployment owns it root:buzzrelay 0640 so the service can read but
    /// not rewrite it.
    pub fn from_file(path: &Path) -> Result<Self, TokenError> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let unreadable = |e: std::io::Error| TokenError::Unreadable(e.kind().to_string());
        let link = std::fs::symlink_metadata(path).map_err(unreadable)?;
        if link.file_type().is_symlink() {
            return Err(TokenError::Symlink);
        }
        if !link.is_file() {
            // before open: opening a FIFO would block
            return Err(TokenError::NotAFile);
        }
        let mut file = std::fs::File::open(path).map_err(unreadable)?;
        // checks apply to what was opened: a path swapped after the lstat
        // is a different inode and is refused
        let meta = file.metadata().map_err(unreadable)?;
        if (meta.dev(), meta.ino()) != (link.dev(), link.ino()) {
            return Err(TokenError::Symlink);
        }
        if !meta.is_file() {
            return Err(TokenError::NotAFile);
        }
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o7137 != 0 {
            return Err(TokenError::TooOpen(mode));
        }
        // the owner may rewrite the token: only root or the process itself
        let uid = meta.uid();
        if !owner_allowed(uid, effective_uid()) {
            return Err(TokenError::ForeignOwner(uid));
        }
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(unreadable)?;
        let token = text.trim();
        if token.chars().any(char::is_whitespace) {
            return Err(TokenError::Whitespace);
        }
        if token.len() < MIN_TOKEN_LEN {
            return Err(TokenError::TooShort);
        }
        Ok(AdminToken(token.to_string()))
    }

    #[cfg(test)]
    pub fn for_test(token: &str) -> Self {
        AdminToken(token.to_string())
    }

    /// Constant-time in the token's length.
    fn matches(&self, presented: &str) -> bool {
        let (a, b) = (self.0.as_bytes(), presented.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

async fn require_bearer(State(token): State<Arc<AdminToken>>, req: Request, next: Next) -> Response {
    let presented = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, t)| t.trim());
    match presented {
        Some(t) if token.matches(t) => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(ErrorBody { error: "unauthorized".into() }),
        ).into_response(),
    }
}

// ---------------------------------------------------------------- backend

#[derive(Debug)]
pub struct BackendError(pub String);

impl<E: std::fmt::Display> From<E> for BackendError {
    fn from(e: E) -> Self {
        BackendError(e.to_string())
    }
}

pub type BackendResult<T> = Result<T, BackendError>;

/// What the admin API needs from the relay. The real implementation is
/// `admin_backend::RelayAdmin`; tests use a mock.
pub trait AdminBackend: Clone + Send + Sync + 'static {
    fn database_ok(&self) -> impl Future<Output = bool> + Send;
    fn policy(&self) -> Arc<Policy>;
    fn follows(&self, actor: Option<String>) -> impl Future<Output = BackendResult<Vec<Follow>>> + Send;
    /// Deletes the follower's follows and sends each a signed Reject.
    fn remove_subscriber(&self, id: String, actor: Option<String>) -> impl Future<Output = BackendResult<SubscribersRemoved>> + Send;
    fn actor_counts(&self) -> impl Future<Output = BackendResult<Vec<ActorCount>>> + Send;
    fn blocks(&self, kind: BlockKind) -> impl Future<Output = BackendResult<Vec<BlockRow>>> + Send;
    /// (created, follows removed)
    fn block_domain(&self, domain: String, reason: String) -> impl Future<Output = BackendResult<(bool, u64)>> + Send;
    fn block_source(&self, pattern: String, reason: String) -> impl Future<Output = BackendResult<bool>> + Send;
    fn unblock(&self, kind: BlockKind, key: String) -> impl Future<Output = BackendResult<bool>> + Send;
    fn streams(&self) -> impl Future<Output = BackendResult<Vec<StreamRow>>> + Send;
    fn stream_statuses(&self) -> Vec<(String, StreamStatus)>;
    fn put_stream(&self, url: String, enabled: bool) -> impl Future<Output = BackendResult<bool>> + Send;
    fn delete_stream(&self, url: String) -> impl Future<Output = BackendResult<bool>> + Send;
    fn set_paused(&self, paused: bool) -> impl Future<Output = BackendResult<()>> + Send;
    fn counters(&self) -> CounterSnapshot;
    fn hosts(&self) -> Vec<HostSnapshot>;
    fn metrics(&self) -> String;
}

// ---------------------------------------------------------------- JSON types

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorBody {
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Health {
    /// "ok" or "degraded"
    pub status: String,
    pub version: String,
    pub paused: bool,
    pub database: bool,
    pub streams_enabled: usize,
    pub streams_running: usize,
    pub streams_connected: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subscriber {
    /// the follower's actor id
    pub id: String,
    pub inbox: String,
    /// the relay actor followed
    pub actor: String,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoveSubscriber {
    pub id: String,
    /// one relay actor; absent = every follow of this follower
    pub actor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscribersRemoved {
    pub removed: usize,
    pub rejects_sent: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainBlock {
    pub domain: String,
    pub reason: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceBlock {
    pub pattern: String,
    pub reason: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PutDomainBlock {
    pub domain: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainBlocked {
    pub domain: String,
    pub created: bool,
    pub removed_follows: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeleteDomainBlock {
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PutSourceBlock {
    pub pattern: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceBlocked {
    pub pattern: String,
    pub created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeleteSourceBlock {
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Deleted {
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamInfo {
    pub id: String,
    /// credentials redacted
    pub url: String,
    pub enabled: bool,
    pub created_at: String,
    /// absent when not running
    pub state: Option<StreamState>,
    pub since: Option<i64>,
    pub posts: Option<u64>,
    pub connects: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PutStream {
    pub url: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamChanged {
    pub id: String,
    pub url: String,
    pub enabled: bool,
    pub created: bool,
}

/// Delete by `id` (from GET /admin/streams) or by the full `url`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeleteStream {
    pub id: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Paused {
    pub paused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorInfo {
    pub actor: String,
    pub followers: i64,
    pub inboxes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainCount {
    pub domain: String,
    pub followers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Followers {
    pub follows: usize,
    pub followers: usize,
    pub inboxes: usize,
    pub by_actor: Vec<ActorInfo>,
    pub by_domain: Vec<DomainCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stats {
    pub paused: bool,
    pub followers: Followers,
    pub counters: CounterSnapshot,
    pub hosts: Vec<HostSnapshot>,
    pub streams: Vec<StreamInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriberFilter {
    pub actor: Option<String>,
    pub domain: Option<String>,
}

// ---------------------------------------------------------------- handlers

type ApiResult<T> = Result<Json<T>, ApiError>;

pub enum ApiError {
    BadRequest(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::BadRequest(e) => (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })).into_response(),
            ApiError::Internal(e) => {
                tracing::error!("admin: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorBody { error: "internal error".into() })).into_response()
            }
        }
    }
}

impl From<BackendError> for ApiError {
    fn from(e: BackendError) -> Self {
        ApiError::Internal(e.0)
    }
}

impl From<JsonRejection> for ApiError {
    fn from(e: JsonRejection) -> Self {
        ApiError::BadRequest(e.body_text())
    }
}

fn bad(msg: &str) -> ApiError {
    ApiError::BadRequest(msg.to_string())
}

fn domain_of(url: &str) -> Option<String> {
    policy::host_of(url)
}

fn stream_infos(rows: Vec<StreamRow>, statuses: &[(String, StreamStatus)]) -> Vec<StreamInfo> {
    rows.into_iter().map(|row| {
        let status = statuses.iter().find(|(url, _)| *url == row.url).map(|(_, s)| s);
        StreamInfo {
            id: stream_id(&row.url),
            url: redact_url(&row.url),
            enabled: row.enabled,
            created_at: row.created_at,
            state: status.map(|s| s.state),
            since: status.map(|s| s.since),
            posts: status.map(|s| s.posts),
            connects: status.map(|s| s.connects),
            last_error: status.and_then(|s| s.last_error.clone()),
        }
    }).collect()
}

async fn health<B: AdminBackend>(State(b): State<B>) -> Response {
    let database = b.database_ok().await;
    let statuses = b.stream_statuses();
    let streams = b.streams().await;
    // a stream list that cannot be read is not an empty stream list
    let streams_ok = streams.is_ok();
    let enabled = streams.map(|rows| rows.iter().filter(|s| s.enabled).count()).unwrap_or(0);
    let ok = database && streams_ok;
    let body = Health {
        status: if ok { "ok" } else { "degraded" }.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        paused: b.policy().paused,
        database,
        streams_enabled: enabled,
        streams_running: statuses.len(),
        streams_connected: statuses.iter().filter(|(_, s)| s.state == StreamState::Connected).count(),
    };
    let code = if ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (code, Json(body)).into_response()
}

async fn stats<B: AdminBackend>(State(b): State<B>) -> ApiResult<Stats> {
    let follows = b.follows(None).await?;
    let mut followers: Vec<&str> = follows.iter().map(|f| f.id.as_str()).collect();
    followers.sort_unstable();
    followers.dedup();
    let mut inboxes: Vec<&str> = follows.iter().map(|f| f.inbox.as_str()).collect();
    inboxes.sort_unstable();
    inboxes.dedup();
    let mut by_domain: std::collections::BTreeMap<String, usize> = Default::default();
    for id in &followers {
        *by_domain.entry(domain_of(id).unwrap_or_default()).or_default() += 1;
    }
    let mut by_domain: Vec<DomainCount> = by_domain.into_iter()
        .map(|(domain, followers)| DomainCount { domain, followers })
        .collect();
    by_domain.sort_by(|a, b| b.followers.cmp(&a.followers).then(a.domain.cmp(&b.domain)));
    let by_actor = b.actor_counts().await?.into_iter()
        .map(|c| ActorInfo { actor: c.actor, followers: c.followers, inboxes: c.inboxes })
        .collect();
    let streams = stream_infos(b.streams().await?, &b.stream_statuses());
    Ok(Json(Stats {
        paused: b.policy().paused,
        followers: Followers {
            follows: follows.len(),
            followers: followers.len(),
            inboxes: inboxes.len(),
            by_actor,
            by_domain,
        },
        counters: b.counters(),
        hosts: b.hosts(),
        streams,
    }))
}

async fn subscribers<B: AdminBackend>(State(b): State<B>, Query(filter): Query<SubscriberFilter>) -> ApiResult<Vec<Subscriber>> {
    let only = match filter.domain.as_deref().filter(|d| !d.is_empty()) {
        Some(d) => Some(Policy::new([policy::normalize_domain(d).ok_or_else(|| bad("invalid domain"))?], [], false)),
        None => None,
    };
    let actor = filter.actor.filter(|a| !a.is_empty());
    let rows = b.follows(actor).await?;
    Ok(Json(rows.into_iter()
        .filter(|f| only.as_ref().is_none_or(|p| p.follower_matches(&f.id, &f.inbox)))
        .map(|f| Subscriber { domain: domain_of(&f.id), id: f.id, inbox: f.inbox, actor: f.actor })
        .collect()))
}

async fn remove_subscriber<B: AdminBackend>(State(b): State<B>, body: Result<Json<RemoveSubscriber>, JsonRejection>) -> ApiResult<SubscribersRemoved> {
    let Json(req) = body?;
    if req.id.trim().is_empty() {
        return Err(bad("id is required"));
    }
    Ok(Json(b.remove_subscriber(req.id, req.actor.filter(|a| !a.is_empty())).await?))
}

async fn list_domain_blocks<B: AdminBackend>(State(b): State<B>) -> ApiResult<Vec<DomainBlock>> {
    Ok(Json(b.blocks(BlockKind::Domain).await?.into_iter()
        .map(|r| DomainBlock { domain: r.key, reason: r.reason, created_at: r.created_at })
        .collect()))
}

async fn put_domain_block<B: AdminBackend>(State(b): State<B>, body: Result<Json<PutDomainBlock>, JsonRejection>) -> ApiResult<DomainBlocked> {
    let Json(req) = body?;
    let domain = policy::normalize_domain(&req.domain).ok_or_else(|| bad("invalid domain"))?;
    let (created, removed_follows) = b.block_domain(domain.clone(), req.reason).await?;
    Ok(Json(DomainBlocked { domain, created, removed_follows }))
}

async fn delete_domain_block<B: AdminBackend>(State(b): State<B>, body: Result<Json<DeleteDomainBlock>, JsonRejection>) -> ApiResult<Deleted> {
    let Json(req) = body?;
    let domain = policy::normalize_domain(&req.domain).ok_or_else(|| bad("invalid domain"))?;
    Ok(Json(Deleted { deleted: b.unblock(BlockKind::Domain, domain).await? }))
}

async fn list_source_blocks<B: AdminBackend>(State(b): State<B>) -> ApiResult<Vec<SourceBlock>> {
    Ok(Json(b.blocks(BlockKind::Source).await?.into_iter()
        .map(|r| SourceBlock { pattern: r.key, reason: r.reason, created_at: r.created_at })
        .collect()))
}

async fn put_source_block<B: AdminBackend>(State(b): State<B>, body: Result<Json<PutSourceBlock>, JsonRejection>) -> ApiResult<SourceBlocked> {
    let Json(req) = body?;
    let pattern = SourcePattern::parse(&req.pattern).ok_or_else(|| bad("invalid pattern: host or user@host"))?.key();
    let created = b.block_source(pattern.clone(), req.reason).await?;
    Ok(Json(SourceBlocked { pattern, created }))
}

async fn delete_source_block<B: AdminBackend>(State(b): State<B>, body: Result<Json<DeleteSourceBlock>, JsonRejection>) -> ApiResult<Deleted> {
    let Json(req) = body?;
    let pattern = SourcePattern::parse(&req.pattern).ok_or_else(|| bad("invalid pattern: host or user@host"))?.key();
    Ok(Json(Deleted { deleted: b.unblock(BlockKind::Source, pattern).await? }))
}

async fn list_streams<B: AdminBackend>(State(b): State<B>) -> ApiResult<Vec<StreamInfo>> {
    Ok(Json(stream_infos(b.streams().await?, &b.stream_statuses())))
}

fn valid_stream_url(url: &str) -> bool {
    // https only: stream URLs carry access tokens
    reqwest::Url::parse(url).is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some_and(|h| !h.is_empty()))
}

async fn put_stream<B: AdminBackend>(State(b): State<B>, body: Result<Json<PutStream>, JsonRejection>) -> ApiResult<StreamChanged> {
    let Json(req) = body?;
    let url = req.url.trim().to_string();
    if !valid_stream_url(&url) {
        return Err(bad("invalid url: https streaming endpoint"));
    }
    let created = b.put_stream(url.clone(), req.enabled).await?;
    Ok(Json(StreamChanged { id: stream_id(&url), url: redact_url(&url), enabled: req.enabled, created }))
}

async fn delete_stream<B: AdminBackend>(State(b): State<B>, body: Result<Json<DeleteStream>, JsonRejection>) -> ApiResult<Deleted> {
    let Json(req) = body?;
    let url = match (req.id, req.url) {
        (_, Some(url)) => Some(url.trim().to_string()),
        (Some(id), None) => b.streams().await?.into_iter()
            .map(|s| s.url)
            .find(|url| stream_id(url) == id.trim()),
        (None, None) => return Err(bad("id or url is required")),
    };
    let deleted = match url {
        Some(url) => b.delete_stream(url).await?,
        None => false,
    };
    Ok(Json(Deleted { deleted }))
}

async fn pause<B: AdminBackend>(State(b): State<B>) -> ApiResult<Paused> {
    b.set_paused(true).await?;
    Ok(Json(Paused { paused: true }))
}

async fn resume<B: AdminBackend>(State(b): State<B>) -> ApiResult<Paused> {
    b.set_paused(false).await?;
    Ok(Json(Paused { paused: false }))
}

async fn actors<B: AdminBackend>(State(b): State<B>) -> ApiResult<Vec<ActorInfo>> {
    Ok(Json(b.actor_counts().await?.into_iter()
        .map(|c| ActorInfo { actor: c.actor, followers: c.followers, inboxes: c.inboxes })
        .collect()))
}

async fn metrics<B: AdminBackend>(State(b): State<B>) -> Response {
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], b.metrics()).into_response()
}

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(ErrorBody { error: "not found".into() })).into_response()
}

/// Every admin route, all behind the bearer.
pub fn router<B: AdminBackend>(backend: B, token: Arc<AdminToken>) -> Router {
    Router::new()
        .route("/admin/health", get(health::<B>))
        .route("/admin/stats", get(stats::<B>))
        .route("/admin/subscribers", get(subscribers::<B>).delete(remove_subscriber::<B>))
        .route("/admin/blocks/domains", get(list_domain_blocks::<B>).put(put_domain_block::<B>).delete(delete_domain_block::<B>))
        .route("/admin/blocks/sources", get(list_source_blocks::<B>).put(put_source_block::<B>).delete(delete_source_block::<B>))
        .route("/admin/streams", get(list_streams::<B>).put(put_stream::<B>).delete(delete_stream::<B>))
        .route("/admin/pause", post(pause::<B>))
        .route("/admin/resume", post(resume::<B>))
        .route("/admin/actors", get(actors::<B>))
        .route("/metrics", get(metrics::<B>))
        .fallback(not_found)
        .with_state(backend)
        .layer(middleware::from_fn_with_state(token, require_bearer))
}

#[cfg(test)]
mod test;
