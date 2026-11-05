use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};

use futures::Future;
use lru::LruCache;
use tokio::sync::{Mutex, oneshot};
use tokio::time::Instant;

use crate::activitypub::Actor;
use crate::error::Error;


/// How long a fetched actor is trusted before it is fetched again (key
/// rotation, moved inbox).
const ACTOR_TTL: Duration = Duration::from_secs(3600);
/// How long a failed lookup is remembered, so a broken remote is not
/// refetched on every request but recovers quickly.
const FAILURE_TTL: Duration = Duration::from_secs(60);

type Entry = (Instant, Result<Arc<Actor>, Error>);

fn fresh(entry: &Entry) -> bool {
    let ttl = if entry.1.is_ok() { ACTOR_TTL } else { FAILURE_TTL };
    entry.0.elapsed() < ttl
}

#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct ActorCache {
    cache: Arc<Mutex<LruCache<String, Entry>>>,
    queues: Arc<Mutex<HashMap<String, Vec<oneshot::Sender<Result<Arc<Actor>, Error>>>>>>,
}

impl Default for ActorCache {
    fn default() -> Self {
        ActorCache {
            cache: Arc::new(Mutex::new(
                LruCache::new(std::num::NonZeroUsize::new(64).unwrap())
            )),
            queues: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl ActorCache {
    pub async fn get<F, R>(&self, k: &str, f: F) -> Result<Arc<Actor>, Error>
    where
        F: (FnOnce() -> R) + Send + 'static,
        R: Future<Output = Result<Actor, Error>> + Send,
    {
        let begin = Instant::now();

        let mut lru = self.cache.lock().await;
        match lru.get(k) {
            Some(entry) if fresh(entry) => return entry.1.clone(),
            Some(_) => { lru.pop(k); }
            None => {}
        }
        drop(lru);

        let (tx, rx) = oneshot::channel();
        let mut new = false;
        let mut queues = self.queues.lock().await;
        let queue = queues.entry(k.to_string())
            .or_insert_with(|| {
                new = true;
                Vec::with_capacity(1)
            });
        queue.push(tx);
        drop(queues);

        if new {
            let k = k.to_string();
            let cache = self.cache.clone();
            let queues = self.queues.clone();
            tokio::spawn(async move {
                let result = f().await
                    .map(Arc::new);

                let mut lru = cache.lock().await;
                lru.put(k.clone(), (Instant::now(), result.clone()));
                drop(lru);

                let mut queues = queues.lock().await;
                let queue = queues.remove(&k)
                    .expect("queues.remove");
                let queue_len = queue.len();
                let mut notified = 0usize;
                for tx in queue {
                    if let Ok(()) = tx.send(result.clone()) {
                        notified += 1;
                    }
                }

                let end = Instant::now();
                tracing::info!("Notified {notified}/{queue_len} endpoint verifications for actor {k} in {:?}", end - begin);
            });
        }

        rx.await.unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn actor(id: &str) -> Actor {
        serde_json::from_value(serde_json::json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "type": "Person",
            "id": id,
            "inbox": format!("{id}/inbox"),
            "publicKey": { "id": format!("{id}#key"), "publicKeyPem": "" },
        })).unwrap()
    }

    async fn lookup(cache: &ActorCache, calls: &Arc<AtomicUsize>, ok: bool) -> Result<Arc<Actor>, Error> {
        let calls = calls.clone();
        cache.get("https://a.example/users/alice", move || async move {
            calls.fetch_add(1, Ordering::SeqCst);
            if ok { Ok(actor("https://a.example/users/alice")) } else { Err(Error::InvalidUri) }
        }).await
    }

    #[tokio::test(start_paused = true)]
    async fn actors_are_cached_for_an_hour() {
        let cache = ActorCache::default();
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(lookup(&cache, &calls, true).await.is_ok());
        tokio::time::advance(Duration::from_secs(3500)).await;
        assert!(lookup(&cache, &calls, true).await.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1, "served from cache within the hour");
        tokio::time::advance(Duration::from_secs(200)).await;
        assert!(lookup(&cache, &calls, true).await.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 2, "refetched after the hour");
    }

    #[tokio::test(start_paused = true)]
    async fn failures_are_cached_for_a_minute_only() {
        let cache = ActorCache::default();
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(lookup(&cache, &calls, false).await.is_err());
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(lookup(&cache, &calls, true).await.is_err(), "failure still cached");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(31)).await;
        assert!(lookup(&cache, &calls, true).await.is_ok(), "retried after a minute");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
