use std::{sync::{Arc, atomic::Ordering}, collections::{HashSet, HashMap}, time::Instant};
use futures::{channel::mpsc::{channel, Sender}, StreamExt};
use metrics::{counter, histogram};
use serde::Deserialize;
use serde_json::json;
use sigh::PrivateKey;
use tokio::sync::mpsc::Receiver;
use crate::{send, actor, state::State, policy::{self, Policy}, stats::{bump, Counters, HostState, RelayStats}};

#[derive(Deserialize)]
struct Post<'a> {
    pub url: Option<&'a str>,
    pub uri: &'a str,
    pub tags: Option<Vec<Tag<'a>>>,
    pub language: Option<&'a str>,
    /// The account as the sender wrote it: it may be missing, null, or
    /// not an object at all. A broken one no longer fails the whole parse;
    /// `author` says what it is worth.
    pub account: Option<serde_json::Value>,
}

/// What a post says about its author.
#[derive(Debug, PartialEq, Eq)]
pub enum Author<'a> {
    /// no account, or an account without an acct: no account filter applies
    Absent,
    Acct(&'a str),
    /// an account or acct that is there but cannot be read
    Unreadable,
}

impl Post<'_> {
    pub fn author(&self) -> Author<'_> {
        let Some(account) = self.account.as_ref().filter(|a| !a.is_null()) else {
            return Author::Absent;
        };
        let Some(object) = account.as_object() else {
            return Author::Unreadable;
        };
        match object.get("acct") {
            None => Author::Absent,
            Some(serde_json::Value::String(acct)) => Author::Acct(acct),
            Some(_) => Author::Unreadable,
        }
    }

    /// The author's acct, when the post names one that can be read.
    pub fn acct(&self) -> Option<&str> {
        match self.author() {
            Author::Acct(acct) => Some(acct),
            _ => None,
        }
    }

    pub fn host(&self) -> Option<String> {
        reqwest::Url::parse(self.url?)
            .ok()
            .and_then(|url| url.domain()
                      .map(str::to_lowercase)
            )
    }

    pub fn tags(&self) -> Vec<String> {
        match &self.tags {
            None =>
                vec![],
            Some(tags) =>
                tags.iter()
                .map(|tag| tag.name.to_string())
                .collect()
        }
    }

    fn relay_target_kinds(&self) -> impl Iterator<Item = actor::ActorKind> {
        self.host()
            .into_iter()
            .map(actor::ActorKind::InstanceRelay)
            .chain(
                self.tags()
                    .into_iter()
                    .flat_map(|ref s| tag_kinds(s))
            )
            .chain(
                self.language
                    .and_then(actor::ActorKind::from_language)
            )
    }

    pub fn relay_targets(&self, hostname: Arc<String>) -> impl Iterator<Item = actor::Actor> {
        self.relay_target_kinds()
            .map(move |kind| actor::Actor {
                host: hostname.clone(),
                kind,
            })
    }
}

/// Whether a post from the firehose is relayed at all.
#[derive(Debug, PartialEq, Eq)]
enum PostVerdict {
    Relay,
    Paused,
    SourceBlocked,
}

fn post_verdict(policy: &Policy, post: &Post) -> PostVerdict {
    if policy.paused {
        return PostVerdict::Paused;
    }
    // an author that is there but cannot be read cannot be shown not to be
    // a blocked account: fail closed, as the domain rules do
    if post.author() == Author::Unreadable {
        return PostVerdict::SourceBlocked;
    }
    let host = post.host();
    let acct = post.acct().and_then(|acct| policy::full_acct(acct, host.as_deref()));
    // url and uri are both the sender's to choose: either naming a blocked host drops the post
    let uri_host = policy::host_of(post.uri);
    if policy.source_blocked(host.as_deref(), acct.as_deref())
        || uri_host.is_some_and(|h| policy.source_blocked(Some(&h), None))
    {
        PostVerdict::SourceBlocked
    } else {
        PostVerdict::Relay
    }
}

/// Whether one subscriber inbox gets a post.
#[derive(Debug, PartialEq, Eq)]
enum InboxVerdict {
    Deliver,
    /// back to the instance the post came from
    Origin,
    DomainBlocked,
}

fn inbox_verdict(policy: &Policy, inbox_host: Option<&str>, post_host: Option<&str>) -> InboxVerdict {
    match inbox_host {
        Some(inbox_host) if Some(inbox_host) == post_host => InboxVerdict::Origin,
        Some(inbox_host) if policy.domain_blocked(inbox_host) => InboxVerdict::DomainBlocked,
        _ => InboxVerdict::Deliver,
    }
}

/// The relay actors a hashtag is delivered to. Hashtags that end in a
/// date also go to followers of the hashtag with the date stripped.
/// Example: #dd1302 -> #dd
fn tag_kinds(s: &str) -> Vec<actor::ActorKind> {
    // Don't handle the empty hashtag `#`
    if s.is_empty() {
        return vec![];
    }
    let actor1 = actor::ActorKind::from_tag(s);
    let digits = s.bytes().rev().take_while(u8::is_ascii_digit).count();
    let first_trailing_digit = s.len() - digits;
    if digits > 0 && first_trailing_digit > 0 {
        vec![actor1, actor::ActorKind::from_tag(&s[..first_trailing_digit])]
    } else {
        vec![actor1]
    }
}

#[derive(Deserialize)]
struct Tag<'a> {
    pub name: &'a str,
}

struct Job {
    post_url: Arc<String>,
    actor_id: Arc<String>,
    body: Arc<Vec<u8>>,
    key_id: String,
    private_key: Arc<PrivateKey>,
    inbox_url: reqwest::Url,
}

fn spawn_worker(client: Arc<reqwest::Client>, host: Arc<HostState>, stats: Arc<RelayStats>) -> Sender<Job> {
    let (tx, mut rx) = channel(512);

    tokio::spawn(async move {
        while let Some(Job { post_url, actor_id, key_id, private_key, body, inbox_url }) = rx.next().await {
            host.queued.fetch_sub(1, Ordering::Relaxed);
            if host.backoff().is_some() {
                // there have been errors, skip for time proportional
                // to the number of subsequent errors
                tracing::trace!("skip {} from {} to {}", post_url, actor_id, inbox_url);
                bump(&stats.counters.deliveries_skipped_backoff);
                continue;
            }

            tracing::debug!("relay {} from {} to {}", post_url, actor_id, inbox_url);
            *host.last_request.lock().unwrap() = Some(tokio::time::Instant::now());
            if let Err(e) = send::send_raw(
                &client, inbox_url.as_str(),
                &key_id, &private_key, body
            ).await {
                tracing::error!("relay::send {:?}", e);
                bump(&stats.counters.deliveries_failed);
                let _ = host.consecutive_errors.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |e| Some(e.saturating_add(1)));
            } else {
                bump(&stats.counters.deliveries_ok);
                host.consecutive_errors.store(0, Ordering::Relaxed);
                crate::notify::watchdog();
            }
        }

        panic!("Worker dead");
    });

    tx
}

/// Hands one Announce to the worker queue of the inbox's host.
/// True when the queue took the job.
fn enqueue(state: &State, workers: &mut HashMap<String, Sender<Job>>, job: Job) -> bool {
    let host_name = job.inbox_url.host_str().unwrap_or("").to_string();
    let host = state.stats.host(&host_name);
    let tx = workers.entry(host_name)
        .or_insert_with(|| spawn_worker(state.client.clone(), host.clone(), state.stats.clone()));
    try_queue(tx, job, &host, &state.stats.counters)
}

/// Puts one job on a queue: true when it was taken, false when the queue
/// was full and the job was dropped.
fn try_queue<T>(tx: &mut Sender<T>, job: T, host: &HostState, counters: &Counters) -> bool {
    host.queued.fetch_add(1, Ordering::Relaxed);
    if tx.try_send(job).is_ok() {
        bump(&counters.deliveries_enqueued);
        true
    } else {
        host.queued.fetch_sub(1, Ordering::Relaxed);
        bump(&counters.deliveries_dropped_queue_full);
        false
    }
}

fn announce(state: &State, actor_id: &str, published: &str, post: &Post, post_url: &str) -> Arc<Vec<u8>> {
    let announce_id = format!("https://{}/announce/{}", state.hostname, urlencoding::encode(post_url));
    let body = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Announce",
        "actor": actor_id,
        "published": published,
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
        "object": &post.uri,
        "id": announce_id,
    });
    Arc::new(serde_json::to_vec(&body).unwrap())
}

struct Delivery<'a> {
    post_url: &'a Arc<String>,
    post_host: Option<&'a str>,
    body: Arc<Vec<u8>>,
    policy: &'a Policy,
}

/// Queues the Announce from one relay actor to each of its followers'
/// inboxes not yet served for this post.
async fn deliver(
    state: &State,
    workers: &mut HashMap<String, Sender<Job>>,
    actor: &actor::Actor,
    delivery: &Delivery<'_>,
    seen_inboxes: &mut HashSet<String>,
) -> usize {
    let mut queued = 0;
    let actor_id = Arc::new(actor.uri());
    let inboxes = match state.database.get_following_inboxes(&actor_id).await {
        Ok(inboxes) => inboxes,
        Err(e) => {
            tracing::error!("get_following_inboxes: {e}");
            return 0;
        }
    };
    for inbox in inboxes {
        let Ok(inbox_url) = reqwest::Url::parse(&inbox) else { continue; };
        // Avoid duplicate processing.
        if !seen_inboxes.insert(inbox) {
            continue;
        }
        match inbox_verdict(delivery.policy, inbox_url.host_str(), delivery.post_host) {
            InboxVerdict::Deliver => {}
            // Prevent relaying back to the originating instance.
            InboxVerdict::Origin => continue,
            InboxVerdict::DomainBlocked => {
                bump(&state.stats.counters.deliveries_skipped_domain_blocked);
                continue;
            }
        }
        if enqueue(state, workers, Job {
            post_url: delivery.post_url.clone(),
            actor_id: actor_id.clone(),
            body: delivery.body.clone(),
            key_id: actor.key_id(),
            private_key: state.priv_key.clone(),
            inbox_url,
        }) {
            // only a job the queue took counts as a delivery
            queued += 1;
        }
    }
    queued
}

/// Relays one firehose post to every subscribed inbox the policy allows.
async fn relay_post(state: &State, workers: &mut HashMap<String, Sender<Job>>, data: &str) {
    let post: Post = match serde_json::from_str(data) {
        Ok(post) => post,
        Err(e) => {
            tracing::error!("parse error: {}", e);
            tracing::trace!("data: {}", data);
            return;
        }
    };
    let Some(url) = post.url else {
        // skip reposts
        counter!("relay_posts_total", "action" => "skip").increment(1);
        bump(&state.stats.counters.posts_skipped_repost);
        return;
    };
    let post_url = Arc::new(url.to_string());
    let policy = state.policy();
    match post_verdict(&policy, &post) {
        PostVerdict::Relay => {}
        PostVerdict::Paused => {
            counter!("relay_posts_total", "action" => "paused").increment(1);
            bump(&state.stats.counters.posts_skipped_paused);
            return;
        }
        PostVerdict::SourceBlocked => {
            counter!("relay_posts_total", "action" => "source_blocked").increment(1);
            bump(&state.stats.counters.posts_skipped_source_blocked);
            return;
        }
    }
    let Ok(post_url_url) = reqwest::Url::parse(&post_url) else { return; };
    let mut seen_actors = HashSet::new();
    let mut seen_inboxes = HashSet::new();
    let mut queued = 0;
    let published = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    for actor in post.relay_targets(state.hostname.clone()) {
        if !seen_actors.insert(actor.clone()) {
            continue;
        }
        let body = announce(state, &actor.uri(), &published, &post, &post_url);
        let delivery = Delivery { post_url: &post_url, post_host: post_url_url.host_str(), body, policy: &policy };
        queued += deliver(state, workers, &actor, &delivery, &mut seen_inboxes).await;
    }
    // relayed = handed to at least one inbox queue, not merely matched
    count_post(&state.stats.counters, queued);
}

/// Counts one relayed post: it counts as relayed only when at least one
/// job was accepted by a queue.
fn count_post(counters: &Counters, accepted: usize) {
    if accepted == 0 {
        counter!("relay_posts_total", "action" => "no_relay").increment(1);
        bump(&counters.posts_without_followers);
    } else {
        counter!("relay_posts_total", "action" => "relay").increment(1);
        bump(&counters.posts_relayed);
    }
}

pub fn spawn(
    state: State,
    mut stream_rx: Receiver<String>
) {
    tokio::spawn(async move {
        let mut workers = HashMap::new();

        while let Some(data) = stream_rx.recv().await {
            let t1 = Instant::now();
            relay_post(&state, &mut workers, &data).await;
            let t2 = Instant::now();
            histogram!("relay_post_duration").record(t2 - t1);
        }
    });
}

#[cfg(test)]
mod test {
    use super::*;
    use actor::ActorKind;

    #[test]
    fn post_relay_kind() {
        let post = Post {
            url: Some("http://example.com/post/1"),
            uri: "http://example.com/post/1",
            tags: Some(vec![Tag {
                name: "foo",
            }]),
            language: Some("en"),
            account: None,
        };
        let mut kinds = post.relay_target_kinds();
        assert_eq!(kinds.next(), Some(ActorKind::InstanceRelay("example.com".to_string())));
        assert_eq!(kinds.next(), Some(ActorKind::TagRelay("foo".to_string())));
        assert_eq!(kinds.next(), Some(ActorKind::LanguageRelay("en".to_string())));
        assert_eq!(kinds.next(), None);
    }

    #[test]
    fn post_relay_kind_empty() {
        let post = Post {
            url: Some("http://example.com/post/1"),
            uri: "http://example.com/post/1",
            tags: Some(vec![Tag {
                name: "",
            }]),
            language: None,
            account: None,
        };
        let mut kinds = post.relay_target_kinds();
        assert_eq!(kinds.next(), Some(ActorKind::InstanceRelay("example.com".to_string())));
        assert_eq!(kinds.next(), None);
    }

    #[test]
    fn post_relay_kind_numeric() {
        let post = Post {
            url: Some("http://example.com/post/1"),
            uri: "http://example.com/post/1",
            tags: Some(vec![Tag {
                name: "23",
            }]),
            language: None,
            account: None,
        };
        let mut kinds = post.relay_target_kinds();
        assert_eq!(kinds.next(), Some(ActorKind::InstanceRelay("example.com".to_string())));
        assert_eq!(kinds.next(), Some(ActorKind::TagRelay("23".to_string())));
        assert_eq!(kinds.next(), None);
    }

    #[test]
    fn post_relay_kind_date() {
        let post = Post {
            url: Some("http://example.com/post/1"),
            uri: "http://example.com/post/1",
            tags: Some(vec![Tag {
                name: "dd1302",
            }]),
            language: None,
            account: None,
        };
        let mut kinds = post.relay_target_kinds();
        assert_eq!(kinds.next(), Some(ActorKind::InstanceRelay("example.com".to_string())));
        assert_eq!(kinds.next(), Some(ActorKind::TagRelay("dd1302".to_string())));
        assert_eq!(kinds.next(), Some(ActorKind::TagRelay("dd".to_string())));
        assert_eq!(kinds.next(), None);
    }

    #[test]
    fn post_relay_kind_ja() {
        let post = Post {
            url: Some("http://example.com/post/1"),
            uri: "http://example.com/post/1",
            tags: Some(vec![Tag {
                name: "スコティッシュ・フォールド・ロングヘアー",
            }]),
            language: Some("ja"),
            account: None,
        };
        let mut kinds = post.relay_target_kinds();
        assert_eq!(kinds.next(), Some(ActorKind::InstanceRelay("example.com".to_string())));
        assert_eq!(kinds.next(), Some(ActorKind::TagRelay("sukoteitusiyuhuorudoronguhea".to_string())));
        assert_eq!(kinds.next(), Some(ActorKind::LanguageRelay("ja".to_string())));
        assert_eq!(kinds.next(), None);
    }

    #[test]
    fn post_relay_language_long() {
        let post = Post {
            url: Some("http://example.com/post/1"),
            uri: "http://example.com/post/1",
            tags: None,
            language: Some("de_CH"),
            account: None,
        };
        let mut kinds = post.relay_target_kinds();
        assert_eq!(kinds.next(), Some(ActorKind::InstanceRelay("example.com".to_string())));
        assert_eq!(kinds.next(), Some(ActorKind::LanguageRelay("de".to_string())));
        assert_eq!(kinds.next(), None);
    }

    #[test]
    fn post_relay_language_invalid() {
        let post = Post {
            url: Some("http://example.com/post/1"),
            uri: "http://example.com/post/1",
            tags: None,
            language: Some("23q"),
            account: None,
        };
        let mut kinds = post.relay_target_kinds();
        assert_eq!(kinds.next(), Some(ActorKind::InstanceRelay("example.com".to_string())));
        assert_eq!(kinds.next(), None);
    }

    fn post<'a>(url: &'a str, acct: Option<&str>) -> Post<'a> {
        Post {
            url: Some(url),
            uri: url,
            tags: None,
            language: None,
            account: acct.map(|acct| serde_json::json!({"acct": acct})),
        }
    }

    #[test]
    fn posts_relay_unless_paused_or_source_blocked() {
        let open = Policy::default();
        assert_eq!(post_verdict(&open, &post("https://a.example/@alice/1", Some("alice"))), PostVerdict::Relay);
        let paused = Policy::new([], [], true);
        assert_eq!(post_verdict(&paused, &post("https://a.example/@alice/1", Some("alice"))), PostVerdict::Paused);
        let blocked = Policy::new([], [
            policy::SourcePattern::parse("spam.example").unwrap(),
            policy::SourcePattern::parse("bot@a.example").unwrap(),
        ], false);
        assert_eq!(post_verdict(&blocked, &post("https://spam.example/@x/1", None)), PostVerdict::SourceBlocked);
        // a local author's bare acct is completed with the post's host
        assert_eq!(post_verdict(&blocked, &post("https://a.example/@bot/1", Some("bot"))), PostVerdict::SourceBlocked);
        assert_eq!(post_verdict(&blocked, &post("https://b.example/@bot/1", Some("bot@a.example"))), PostVerdict::SourceBlocked);
        assert_eq!(post_verdict(&blocked, &post("https://a.example/@alice/1", Some("alice"))), PostVerdict::Relay);
        // a post whose uri names a blocked host is dropped even if its url does not
        let mut p = post("https://ok.example/@x/1", None);
        p.uri = "https://spam.example/users/x/statuses/1";
        assert_eq!(post_verdict(&blocked, &p), PostVerdict::SourceBlocked);
    }

    #[test]
    fn inboxes_on_blocked_domains_or_the_origin_are_skipped() {
        let policy = Policy::new(["spam.example".to_string()], [], false);
        assert_eq!(inbox_verdict(&policy, Some("ok.example"), Some("a.example")), InboxVerdict::Deliver);
        assert_eq!(inbox_verdict(&policy, Some("a.example"), Some("a.example")), InboxVerdict::Origin);
        assert_eq!(inbox_verdict(&policy, Some("m.spam.example"), Some("a.example")), InboxVerdict::DomainBlocked);
        assert_eq!(inbox_verdict(&policy, None, Some("a.example")), InboxVerdict::Deliver);
    }

    #[test]
    fn posts_parse_the_author_acct() {
        let data = r#"{"url":"https://a.example/@alice/1","uri":"https://a.example/users/alice/statuses/1","account":{"acct":"alice","id":"1"}}"#;
        let post: Post = serde_json::from_str(data).unwrap();
        assert_eq!(post.acct(), Some("alice"));
        let odd = r#"{"url":"https://a.example/@alice/1","uri":"https://a.example/1","account":{"id":"1"}}"#;
        let post: Post = serde_json::from_str(odd).unwrap();
        assert_eq!(post.acct(), None, "an account without acct must not drop the post");
    }

    #[test]
    fn a_post_with_a_broken_account_still_parses() {
        // the post parses; what it is worth depends on the account field
        let policy = Policy::new([], [
            policy::SourcePattern::parse("bot@a.example").unwrap(),
        ], false);
        for (data, want) in [
            // no account, or no acct in it: no account filter applies, as upstream
            (r#"{"url":"https://a.example/@bot/1","uri":"https://a.example/1"}"#, PostVerdict::Relay),
            (r#"{"url":"https://a.example/@bot/1","uri":"https://a.example/1","account":null}"#, PostVerdict::Relay),
            (r#"{"url":"https://a.example/@bot/1","uri":"https://a.example/1","account":{"id":"1"}}"#, PostVerdict::Relay),
            // an account that is there but cannot be read cannot be shown
            // not to be a blocked one: dropped, so a blocked account cannot
            // slip through by sending a broken acct
            (r#"{"url":"https://a.example/@bot/1","uri":"https://a.example/1","account":{"acct":null}}"#, PostVerdict::SourceBlocked),
            (r#"{"url":"https://a.example/@bot/1","uri":"https://a.example/1","account":{"acct":7}}"#, PostVerdict::SourceBlocked),
            (r#"{"url":"https://a.example/@bot/1","uri":"https://a.example/1","account":"bot"}"#, PostVerdict::SourceBlocked),
        ] {
            let post: Post = serde_json::from_str(data)
                .unwrap_or_else(|e| panic!("{data} must parse: {e}"));
            assert_eq!(post_verdict(&policy, &post), want, "{data}");
        }
    }

    #[test]
    fn a_job_is_only_counted_when_the_queue_takes_it() {
        let (mut tx, _rx) = channel(0);
        let host = HostState::default();
        let counters = Counters::default();
        assert!(try_queue(&mut tx, 1u8, &host, &counters), "the first job fits into the queue");
        assert!(!try_queue(&mut tx, 2u8, &host, &counters), "the queue is full now");
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.deliveries_enqueued, 1);
        assert_eq!(snapshot.deliveries_dropped_queue_full, 1);
        assert_eq!(host.queued.load(Ordering::Relaxed), 1, "the dropped job is not queued");
    }

    #[test]
    fn a_post_counts_as_relayed_only_when_a_job_was_accepted() {
        let counters = Counters::default();
        count_post(&counters, 0);
        assert_eq!(counters.snapshot().posts_relayed, 0);
        assert_eq!(counters.snapshot().posts_without_followers, 1);
        count_post(&counters, 2);
        assert_eq!(counters.snapshot().posts_relayed, 1);
        assert_eq!(counters.snapshot().posts_without_followers, 1);
    }
}
