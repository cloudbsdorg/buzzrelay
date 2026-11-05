use super::*;
use std::sync::Mutex;
use axum::body::Body;
use http_body_util::BodyExt;
use tower::ServiceExt;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[derive(Clone, Default)]
struct Mock {
    calls: Arc<Mutex<Vec<String>>>,
    db_down: bool,
    streams_down: bool,
    streams: Vec<StreamRow>,
    follows: Vec<Follow>,
}

impl Mock {
    fn log(&self, call: String) {
        self.calls.lock().unwrap().push(call);
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl AdminBackend for Mock {
    async fn database_ok(&self) -> bool { !self.db_down }
    fn policy(&self) -> Arc<Policy> { Arc::new(Policy::default()) }
    async fn follows(&self, actor: Option<String>) -> BackendResult<Vec<Follow>> {
        self.log(format!("follows {actor:?}"));
        Ok(self.follows.iter().filter(|f| actor.as_ref().is_none_or(|a| *a == f.actor)).cloned().collect())
    }
    async fn remove_subscriber(&self, id: String, actor: Option<String>) -> BackendResult<SubscribersRemoved> {
        self.log(format!("remove {id} {actor:?}"));
        Ok(SubscribersRemoved { removed: 1, rejects_sent: 1 })
    }
    async fn actor_counts(&self) -> BackendResult<Vec<ActorCount>> {
        Ok(vec![ActorCount { actor: "https://relay.test/tag/bsd".into(), followers: 2, inboxes: 1 }])
    }
    async fn blocks(&self, kind: BlockKind) -> BackendResult<Vec<BlockRow>> {
        self.log(format!("blocks {kind:?}"));
        Ok(vec![BlockRow { key: "spam.example".into(), reason: "r".into(), created_at: "2026-11-04T00:00:00Z".into() }])
    }
    async fn block_domain(&self, domain: String, reason: String) -> BackendResult<(bool, u64)> {
        self.log(format!("block_domain {domain} {reason}"));
        Ok((true, 3))
    }
    async fn block_source(&self, pattern: String, reason: String) -> BackendResult<bool> {
        self.log(format!("block_source {pattern} {reason}"));
        Ok(false)
    }
    async fn unblock(&self, kind: BlockKind, key: String) -> BackendResult<bool> {
        self.log(format!("unblock {kind:?} {key}"));
        Ok(false)
    }
    async fn streams(&self) -> BackendResult<Vec<StreamRow>> {
        if self.streams_down {
            return Err(BackendError("streams: down".into()));
        }
        Ok(self.streams.clone())
    }
    fn stream_statuses(&self) -> Vec<(String, StreamStatus)> {
        self.streams.iter().take(1).map(|s| (s.url.clone(), StreamStatus {
            state: StreamState::Connected, since: 1, posts: 5, connects: 1, last_error: None,
        })).collect()
    }
    async fn put_stream(&self, url: String, enabled: bool) -> BackendResult<bool> {
        self.log(format!("put_stream {url} {enabled}"));
        Ok(true)
    }
    async fn delete_stream(&self, url: String) -> BackendResult<bool> {
        self.log(format!("delete_stream {url}"));
        Ok(true)
    }
    async fn set_paused(&self, paused: bool) -> BackendResult<()> {
        self.log(format!("paused {paused}"));
        Ok(())
    }
    fn counters(&self) -> CounterSnapshot { CounterSnapshot::default() }
    fn hosts(&self) -> Vec<HostSnapshot> { vec![] }
    fn metrics(&self) -> String { "# metrics\n".into() }
}

const SECRET_URL: &str = "https://m.example/api/v1/streaming/public?access_token=s3cr3t";

fn mock() -> Mock {
    Mock {
        streams: vec![
            StreamRow { url: SECRET_URL.into(), enabled: true, created_at: "2026-11-04T00:00:00Z".into() },
            StreamRow { url: "https://fedi.buzz/api/v1/streaming/public".into(), enabled: false, created_at: "2026-11-04T00:00:00Z".into() },
        ],
        follows: vec![
            Follow { id: "https://a.example/users/alice".into(), inbox: "https://a.example/inbox".into(), actor: "https://relay.test/tag/bsd".into(), follow_id: None },
            Follow { id: "https://a.example/users/bob".into(), inbox: "https://a.example/inbox".into(), actor: "https://relay.test/tag/bsd".into(), follow_id: None },
            Follow { id: "https://m.b.example/users/c".into(), inbox: "https://m.b.example/inbox".into(), actor: "https://relay.test/tag/rust".into(), follow_id: None },
        ],
        ..Mock::default()
    }
}

async fn call(backend: Mock, method: &str, path: &str, auth: Option<&str>, body: Option<serde_json::Value>) -> (StatusCode, String) {
    let app = router(backend, Arc::new(AdminToken::for_test(TOKEN)));
    let mut req = Request::builder().method(method).uri(path);
    if let Some(auth) = auth {
        req = req.header(header::AUTHORIZATION, auth);
    }
    let req = match body {
        Some(body) => req.header(header::CONTENT_TYPE, "application/json").body(Body::from(body.to_string())),
        None => req.body(Body::empty()),
    }.unwrap();
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn bearer() -> Option<&'static str> {
    Some("Bearer 0123456789abcdef0123456789abcdef")
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap()
}

#[tokio::test]
async fn every_route_requires_the_bearer() {
    for (method, path) in [("GET", "/admin/health"), ("GET", "/admin/stats"), ("GET", "/metrics"), ("POST", "/admin/pause"), ("DELETE", "/admin/subscribers"), ("GET", "/nowhere")] {
        for auth in [None, Some("Bearer wrong"), Some("Basic 0123456789abcdef0123456789abcdef"), Some("Bearer 0123456789abcdef0123456789abcdeX"), Some("Bearer")] {
            let m = mock();
            let (status, _) = call(m.clone(), method, path, auth, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path} {auth:?}");
            assert!(m.calls().is_empty(), "the backend was reached without auth");
        }
    }
    let (status, body) = call(mock(), "GET", "/admin/health", Some("bearer 0123456789abcdef0123456789abcdef"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn health_reports_and_degrades() {
    let (status, body) = call(mock(), "GET", "/admin/health", bearer(), None).await;
    assert_eq!(status, StatusCode::OK);
    let health: Health = serde_json::from_str(&body).unwrap();
    assert_eq!((health.status.as_str(), health.database, health.streams_enabled, health.streams_running, health.streams_connected), ("ok", true, 1, 1, 1));
    let down = Mock { db_down: true, ..mock() };
    let (status, body) = call(down, "GET", "/admin/health", bearer(), None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json(&body)["status"], "degraded");
}

#[tokio::test]
async fn health_is_degraded_when_the_streams_query_fails() {
    let down = Mock { streams_down: true, ..mock() };
    let (status, body) = call(down, "GET", "/admin/health", bearer(), None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let health: Health = serde_json::from_str(&body).unwrap();
    assert_eq!(health.status, "degraded", "a stream list that cannot be read is not an empty one");
    assert!(health.database, "the database is fine");
}

#[tokio::test]
async fn metrics_are_served_here() {
    let (status, body) = call(mock(), "GET", "/metrics", bearer(), None).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "# metrics\n"));
}

#[tokio::test]
async fn domain_blocks_are_validated_and_normalized() {
    let m = mock();
    let (status, body) = call(m.clone(), "PUT", "/admin/blocks/domains", bearer(), Some(serde_json::json!({"domain": "https://spam.example/"}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "invalid domain");
    let (status, body) = call(m.clone(), "PUT", "/admin/blocks/domains", bearer(), Some(serde_json::json!({"domain": "Spam.Example.", "reason": "spam"}))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(serde_json::from_str::<DomainBlocked>(&body).unwrap(), DomainBlocked { domain: "spam.example".into(), created: true, removed_follows: 3 });
    let (status, body) = call(m.clone(), "DELETE", "/admin/blocks/domains", bearer(), Some(serde_json::json!({"domain": "spam.example"}))).await;
    assert_eq!((status, json(&body)["deleted"].clone()), (StatusCode::OK, serde_json::json!(false)));
    let (_, body) = call(m.clone(), "GET", "/admin/blocks/domains", bearer(), None).await;
    assert_eq!(json(&body)[0]["domain"], "spam.example");
    assert_eq!(m.calls(), vec!["block_domain spam.example spam", "unblock Domain spam.example", "blocks Domain"]);
}

#[tokio::test]
async fn source_blocks_take_host_or_acct() {
    let m = mock();
    let (status, _) = call(m.clone(), "PUT", "/admin/blocks/sources", bearer(), Some(serde_json::json!({"pattern": "not a pattern"}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = call(m.clone(), "PUT", "/admin/blocks/sources", bearer(), Some(serde_json::json!({"pattern": "@Bot@A.Example"}))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_str::<SourceBlocked>(&body).unwrap(), SourceBlocked { pattern: "bot@a.example".into(), created: false });
    let (_, body) = call(m.clone(), "GET", "/admin/blocks/sources", bearer(), None).await;
    assert_eq!(json(&body)[0]["pattern"], "spam.example");
    assert_eq!(m.calls()[0], "block_source bot@a.example ");
}

#[tokio::test]
async fn malformed_bodies_are_bad_requests() {
    for (method, path) in [("PUT", "/admin/blocks/domains"), ("DELETE", "/admin/subscribers"), ("PUT", "/admin/streams")] {
        let (status, body) = call(mock(), method, path, bearer(), Some(serde_json::json!({"nope": 1}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {path}");
        assert!(json(&body)["error"].is_string());
    }
    let (status, _) = call(mock(), "DELETE", "/admin/subscribers", bearer(), Some(serde_json::json!({"id": " "}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn subscribers_filter_by_actor_and_domain() {
    let (_, body) = call(mock(), "GET", "/admin/subscribers?domain=b.example", bearer(), None).await;
    let subs: Vec<Subscriber> = serde_json::from_str(&body).unwrap();
    assert_eq!(subs.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(), vec!["https://m.b.example/users/c"]);
    assert_eq!(subs[0].domain.as_deref(), Some("m.b.example"));
    let m = mock();
    let (_, body) = call(m.clone(), "GET", "/admin/subscribers?actor=https%3A%2F%2Frelay.test%2Ftag%2Fbsd", bearer(), None).await;
    assert_eq!(serde_json::from_str::<Vec<Subscriber>>(&body).unwrap().len(), 2);
    assert_eq!(m.calls(), vec![r#"follows Some("https://relay.test/tag/bsd")"#]);
    let (status, _) = call(mock(), "GET", "/admin/subscribers?domain=not%20a%20domain", bearer(), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn removing_a_subscriber_reaches_the_backend() {
    let m = mock();
    let (status, body) = call(m.clone(), "DELETE", "/admin/subscribers", bearer(), Some(serde_json::json!({"id": "https://a.example/users/alice"}))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_str::<SubscribersRemoved>(&body).unwrap(), SubscribersRemoved { removed: 1, rejects_sent: 1 });
    assert_eq!(m.calls(), vec!["remove https://a.example/users/alice None"]);
}

#[tokio::test]
async fn stream_urls_never_leave_unredacted() {
    let m = mock();
    for path in ["/admin/streams", "/admin/stats"] {
        let (status, body) = call(m.clone(), "GET", path, bearer(), None).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(!body.contains("s3cr3t"), "{path} leaked the token: {body}");
        assert!(body.contains("access_token=REDACTED"), "{path}: {body}");
    }
    let (_, body) = call(m.clone(), "GET", "/admin/streams", bearer(), None).await;
    let streams: Vec<StreamInfo> = serde_json::from_str(&body).unwrap();
    assert_eq!(streams[0].state, Some(StreamState::Connected));
    assert_eq!(streams[1].state, None);
    let (status, body) = call(m.clone(), "PUT", "/admin/streams", bearer(), Some(serde_json::json!({"url": "https://x.example/s?access_token=t0k3n"}))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("t0k3n"), "{body}");
    assert_eq!(json(&body)["enabled"], true);
}

#[tokio::test]
async fn streams_are_validated_and_deleted_by_id() {
    for url in ["ftp://x.example/s", "http://x.example/s?access_token=t", "https://", "not a url"] {
        let (status, _) = call(mock(), "PUT", "/admin/streams", bearer(), Some(serde_json::json!({"url": url}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{url}: https with a host only");
    }
    let m = mock();
    let id = stream_id(SECRET_URL);
    let (status, body) = call(m.clone(), "DELETE", "/admin/streams", bearer(), Some(serde_json::json!({"id": id}))).await;
    assert_eq!((status, json(&body)["deleted"].clone()), (StatusCode::OK, serde_json::json!(true)));
    let (_, body) = call(m.clone(), "DELETE", "/admin/streams", bearer(), Some(serde_json::json!({"id": "0000000000000000"}))).await;
    assert_eq!(json(&body)["deleted"], false, "an unknown id is not an error");
    assert_eq!(m.calls(), vec![format!("delete_stream {SECRET_URL}")]);
    let (status, _) = call(mock(), "DELETE", "/admin/streams", bearer(), Some(serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pause_and_resume() {
    let m = mock();
    let (_, body) = call(m.clone(), "POST", "/admin/pause", bearer(), None).await;
    assert_eq!(json(&body)["paused"], true);
    let (_, body) = call(m.clone(), "POST", "/admin/resume", bearer(), None).await;
    assert_eq!(json(&body)["paused"], false);
    assert_eq!(m.calls(), vec!["paused true", "paused false"]);
}

#[tokio::test]
async fn stats_count_followers_by_actor_and_domain() {
    let (_, body) = call(mock(), "GET", "/admin/stats", bearer(), None).await;
    let stats: Stats = serde_json::from_str(&body).unwrap();
    assert_eq!((stats.followers.follows, stats.followers.followers, stats.followers.inboxes), (3, 3, 2));
    assert_eq!(stats.followers.by_domain, vec![
        DomainCount { domain: "a.example".into(), followers: 2 },
        DomainCount { domain: "m.b.example".into(), followers: 1 },
    ]);
    assert_eq!(stats.followers.by_actor[0].followers, 2);
    let (_, body) = call(mock(), "GET", "/admin/actors", bearer(), None).await;
    assert_eq!(json(&body)[0]["actor"], "https://relay.test/tag/bsd");
}

// ------------------------------------------------------------ token file

fn token_file(name: &str, contents: &str, mode: u32) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("buzzrelay-admin-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, contents).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[test]
fn token_files_must_be_owned_by_root_or_by_this_process() {
    use std::os::unix::fs::MetadataExt;
    let good = format!("{TOKEN}\n");
    // a file this process owns is fine
    let own = token_file("own", &good, 0o600);
    assert!(AdminToken::from_file(&own).is_ok(), "a file we own is allowed");
    // the process uid is the owner of a file it creates
    let meta = std::fs::metadata(&own).unwrap();
    assert_eq!(meta.uid(), effective_uid());
    // and nobody else may own it
    assert!(owner_allowed(0, 1000), "root may own the token file");
    assert!(owner_allowed(1000, 1000), "the process may own it");
    assert!(!owner_allowed(4242, 1000), "another user may not");
}

#[test]
fn token_files_must_be_private_regular_files() {
    let good = format!("{TOKEN}\n");
    assert!(AdminToken::from_file(&token_file("a", &good, 0o600)).unwrap().matches(TOKEN), "trailing newline trimmed");
    assert!(AdminToken::from_file(&token_file("b", &good, 0o640)).is_ok(), "root:buzzrelay 0640 is the deployed shape");
    assert_eq!(AdminToken::from_file(&token_file("c", &good, 0o644)).unwrap_err(), TokenError::TooOpen(0o644));
    assert_eq!(AdminToken::from_file(&token_file("d", &good, 0o660)).unwrap_err(), TokenError::TooOpen(0o660));
    assert_eq!(AdminToken::from_file(&token_file("e", &good, 0o604)).unwrap_err(), TokenError::TooOpen(0o604));
    assert_eq!(AdminToken::from_file(&token_file("f", "short\n", 0o600)).unwrap_err(), TokenError::TooShort);
    assert_eq!(AdminToken::from_file(&token_file("g", "", 0o600)).unwrap_err(), TokenError::TooShort);
    assert_eq!(AdminToken::from_file(&token_file("w", &format!("{TOKEN} {TOKEN}\n"), 0o600)).unwrap_err(), TokenError::Whitespace);
    assert_eq!(AdminToken::from_file(&token_file("x", &good, 0o700)).unwrap_err(), TokenError::TooOpen(0o700));
    let target = token_file("h", &good, 0o600);
    let link = target.with_file_name("link");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_eq!(AdminToken::from_file(&link).unwrap_err(), TokenError::Symlink);
    assert_eq!(AdminToken::from_file(target.parent().unwrap()).unwrap_err(), TokenError::NotAFile);
    assert!(matches!(AdminToken::from_file(&target.with_file_name("absent")), Err(TokenError::Unreadable(_))));
    assert_eq!(format!("{:?}", AdminToken::for_test(TOKEN)), "AdminToken(..)");
    let _ = std::fs::remove_dir_all(target.parent().unwrap());
}
