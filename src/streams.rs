//! Runtime-managed firehose sources. The `streams` table says which SSE
//! streams should run; the supervisor starts and stops tasks to match it,
//! every `RECONCILE_PERIOD` and whenever the admin API asks.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use serde::{Deserialize, Serialize};
use tokio::{sync::Notify, task::JoinHandle};

pub const RECONCILE_PERIOD: Duration = Duration::from_secs(30);

/// Stream URLs may carry an access token (Mastodon 4.2+). Anything shown
/// outside the process goes through this: every query value but the ones
/// on the allowlist is replaced, and the userinfo is replaced as well,
/// name and password alike.
pub fn redact_url(url: &str) -> String {
    const REDACTED: &str = "REDACTED";
    /// The query values that carry no secret and are worth showing.
    const ALLOWED: &[&str] = &["local", "remote", "only_media", "tag", "list"];
    let Ok(mut parsed) = reqwest::Url::parse(url) else {
        return REDACTED.to_string();
    };
    // the userinfo name may be the token
    if !parsed.username().is_empty() {
        let _ = parsed.set_username(REDACTED);
    }
    if parsed.password().is_some() {
        let _ = parsed.set_password(Some(REDACTED));
    }
    if parsed.query().is_some() {
        let pairs: Vec<(String, String)> = parsed.query_pairs()
            .map(|(k, v)| {
                let name = k.to_ascii_lowercase();
                let keep = ALLOWED.contains(&name.as_str());
                (k.into_owned(), if keep { v.into_owned() } else { REDACTED.to_string() })
            })
            .collect();
        parsed.query_pairs_mut().clear().extend_pairs(pairs);
    }
    parsed.to_string()
}

/// A short stable handle for a stream, so a client can delete one it only
/// knows in redacted form.
pub fn stream_id(url: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(url.as_bytes())[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamState {
    Connecting,
    Connected,
    Retrying,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamStatus {
    pub state: StreamState,
    /// unix seconds of the last state change
    pub since: i64,
    pub posts: u64,
    pub connects: u64,
    /// terse, URL-free
    pub last_error: Option<String>,
}

impl Default for StreamStatus {
    fn default() -> Self {
        StreamStatus { state: StreamState::Connecting, since: now(), posts: 0, connects: 0, last_error: None }
    }
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

pub type StatusCell = Arc<Mutex<StreamStatus>>;
pub type Spawner = Arc<dyn Fn(String, StatusCell) -> JoinHandle<()> + Send + Sync>;

/// Which URLs to start and which to stop, each sorted.
pub fn plan(running: &HashSet<String>, desired: &HashSet<String>) -> (Vec<String>, Vec<String>) {
    let mut start: Vec<String> = desired.difference(running).cloned().collect();
    let mut stop: Vec<String> = running.difference(desired).cloned().collect();
    start.sort();
    stop.sort();
    (start, stop)
}

pub struct Supervisor {
    spawner: Spawner,
    running: Mutex<HashMap<String, (JoinHandle<()>, StatusCell)>>,
    wake: Notify,
}

impl Supervisor {
    pub fn new(spawner: Spawner) -> Arc<Self> {
        Arc::new(Supervisor { spawner, running: Mutex::new(HashMap::new()), wake: Notify::new() })
    }

    /// Makes the running set equal `desired`. A task that ended (it should
    /// not) is started again and reported only as started. Returns
    /// (started, stopped).
    pub fn reconcile(&self, desired: &[String]) -> (Vec<String>, Vec<String>) {
        let desired: HashSet<String> = desired.iter().cloned().collect();
        let mut running = self.running.lock().unwrap();
        running.retain(|_, (handle, _)| !handle.is_finished());
        let current: HashSet<String> = running.keys().cloned().collect();
        let (start, stop) = plan(&current, &desired);
        for url in &stop {
            if let Some((handle, _)) = running.remove(url) {
                handle.abort();
            }
        }
        for url in &start {
            let status: StatusCell = Arc::default();
            let handle = (self.spawner)(url.clone(), status.clone());
            running.insert(url.clone(), (handle, status));
        }
        (start, stop)
    }

    /// Status of every running stream, by URL (unredacted: callers redact).
    pub fn statuses(&self) -> Vec<(String, StreamStatus)> {
        let running = self.running.lock().unwrap();
        let mut out: Vec<_> = running.iter()
            .map(|(url, (_, status))| (url.clone(), status.lock().unwrap().clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Asks the supervisor loop to reconcile now.
    pub fn request_reconcile(&self) {
        self.wake.notify_one();
    }

    /// Waits for the next period or an explicit request.
    pub async fn wait(&self) {
        tokio::select! {
            () = tokio::time::sleep(RECONCILE_PERIOD) => {}
            () = self.wake.notified() => {}
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn credentials_are_redacted() {
        assert_eq!(redact_url("https://fedi.buzz/api/v1/streaming/public"), "https://fedi.buzz/api/v1/streaming/public");
        assert_eq!(
            redact_url("https://m.example/api/v1/streaming/public?access_token=s3cr3t&local=true"),
            "https://m.example/api/v1/streaming/public?access_token=REDACTED&local=true",
        );
        assert_eq!(redact_url("https://u:pw@m.example/s?apiKey=k"), "https://REDACTED:REDACTED@m.example/s?apiKey=REDACTED");
        assert!(!redact_url("not a url with s3cr3t").contains("s3cr3t"));
    }

    #[test]
    fn every_query_value_is_redacted_except_the_allowlist() {
        // a value whose name does not look like a credential is one anyway
        assert_eq!(redact_url("https://m.example/s?jwt=x"), "https://m.example/s?jwt=REDACTED");
        assert_eq!(redact_url("https://m.example/s?code=x"), "https://m.example/s?code=REDACTED");
        assert_eq!(redact_url("https://m.example/s?anything=else"), "https://m.example/s?anything=REDACTED");
        // the allowlist keeps the values the relay needs to show
        assert_eq!(redact_url("https://m.example/s?local=true"), "https://m.example/s?local=true");
        assert_eq!(
            redact_url("https://m.example/s?remote=true&only_media=false&tag=bsd&list=mods"),
            "https://m.example/s?remote=true&only_media=false&tag=bsd&list=mods",
        );
        // the userinfo name is a secret as well
        assert_eq!(redact_url("https://user:mypass@m.example/s"), "https://REDACTED:REDACTED@m.example/s");
    }

    #[test]
    fn stream_ids_are_stable_and_distinct() {
        let a = stream_id("https://a.example/s?access_token=1");
        assert_eq!(a, stream_id("https://a.example/s?access_token=1"));
        assert_ne!(a, stream_id("https://a.example/s?access_token=2"));
        assert_eq!(a.len(), 16);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    fn set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn plan_starts_missing_and_stops_extra() {
        assert_eq!(plan(&set(&["a", "b"]), &set(&["b", "d", "c"])), (vec!["c".into(), "d".into()], vec!["a".into()]));
        assert_eq!(plan(&set(&["a"]), &set(&["a"])), (vec![], vec![]));
    }

    fn pending_spawner(log: Arc<Mutex<Vec<String>>>) -> Spawner {
        Arc::new(move |url, _status| {
            log.lock().unwrap().push(url);
            tokio::spawn(std::future::pending())
        })
    }

    #[tokio::test]
    async fn reconcile_follows_the_desired_set() {
        let log = Arc::new(Mutex::new(vec![]));
        let sup = Supervisor::new(pending_spawner(log.clone()));
        assert_eq!(sup.reconcile(&["a".into(), "b".into()]), (vec!["a".into(), "b".into()], vec![]));
        assert_eq!(sup.reconcile(&["b".into(), "c".into()]), (vec!["c".into()], vec!["a".into()]));
        assert_eq!(sup.reconcile(&["b".into(), "c".into()]), (vec![], vec![]));
        assert_eq!(sup.statuses().iter().map(|(u, _)| u.as_str()).collect::<Vec<_>>(), vec!["b", "c"]);
        assert_eq!(*log.lock().unwrap(), vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn a_dead_stream_task_is_restarted() {
        let sup = Supervisor::new(Arc::new(|_url, _status| tokio::spawn(async {})));
        sup.reconcile(&["a".into()]);
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(sup.reconcile(&["a".into()]), (vec!["a".into()], vec![]));
    }

    #[tokio::test]
    async fn a_request_wakes_the_loop_early() {
        let sup = Supervisor::new(pending_spawner(Arc::new(Mutex::new(vec![]))));
        sup.request_reconcile();
        tokio::time::timeout(Duration::from_secs(1), sup.wait()).await
            .expect("woken before the period");
    }
}
