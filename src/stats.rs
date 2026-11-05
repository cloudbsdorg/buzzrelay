//! In-process counters for the admin API: what was relayed or skipped, and
//! each destination host's delivery queue and backoff. Prometheus metrics
//! stay as they were; these are the numbers a person asks for.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

/// After `errors` consecutive failures a host is skipped for 10 s per error,
/// counted from the last attempt (upstream's rule). `None` when not backing
/// off.
pub fn backoff_remaining(errors: u32, since_last_request: Option<Duration>) -> Option<Duration> {
    let since = since_last_request?;
    if errors == 0 {
        return None;
    }
    let window = Duration::from_secs(10).saturating_mul(errors);
    window.checked_sub(since).filter(|d| !d.is_zero())
}

macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        #[derive(Debug, Default)]
        pub struct Counters {
            $(pub $name: AtomicU64,)*
        }

        #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
        pub struct CounterSnapshot {
            $(pub $name: u64,)*
        }

        impl Counters {
            pub fn snapshot(&self) -> CounterSnapshot {
                CounterSnapshot {
                    $($name: self.$name.load(Ordering::Relaxed),)*
                }
            }
        }
    };
}

counters!(
    posts_relayed,
    posts_without_followers,
    posts_skipped_repost,
    posts_skipped_paused,
    posts_skipped_source_blocked,
    deliveries_enqueued,
    deliveries_skipped_domain_blocked,
    deliveries_dropped_queue_full,
    deliveries_skipped_backoff,
    deliveries_ok,
    deliveries_failed,
    follows_accepted,
    follows_rejected,
    subscribers_removed,
    rejects_sent,
    rejects_failed,
);

impl Counters {
    /// Records that `removed` follow rows are gone: the counter counts the
    /// rows, not the Rejects that were sent for them.
    pub fn record_removed(&self, removed: usize) {
        self.subscribers_removed.fetch_add(removed as u64, Ordering::Relaxed);
    }

    /// Records one Reject to a removed follower: delivered or failed.
    pub fn record_reject(&self, delivered: bool) {
        if delivered {
            self.rejects_sent.fetch_add(1, Ordering::Relaxed);
        } else {
            self.rejects_failed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

#[derive(Debug, Default)]
pub struct HostState {
    pub queued: AtomicU64,
    pub consecutive_errors: AtomicU32,
    pub last_request: Mutex<Option<Instant>>,
}

impl HostState {
    pub fn backoff(&self) -> Option<Duration> {
        let since = self.last_request.lock().unwrap().map(|t| t.elapsed());
        backoff_remaining(self.consecutive_errors.load(Ordering::Relaxed), since)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSnapshot {
    pub host: String,
    pub queued: u64,
    pub consecutive_errors: u32,
    pub backoff_seconds: u64,
}

#[derive(Debug, Default)]
pub struct RelayStats {
    pub counters: Counters,
    hosts: Mutex<HashMap<String, Arc<HostState>>>,
}

impl RelayStats {
    pub fn host(&self, host: &str) -> Arc<HostState> {
        self.hosts.lock().unwrap()
            .entry(host.to_string())
            .or_default()
            .clone()
    }

    /// Hosts with something queued or backing off, busiest first.
    pub fn hosts(&self) -> Vec<HostSnapshot> {
        let hosts = self.hosts.lock().unwrap();
        let mut out: Vec<HostSnapshot> = hosts.iter()
            .map(|(host, state)| HostSnapshot {
                host: host.clone(),
                queued: state.queued.load(Ordering::Relaxed),
                consecutive_errors: state.consecutive_errors.load(Ordering::Relaxed),
                backoff_seconds: state.backoff().map_or(0, |d| d.as_secs().max(1)),
            })
            .filter(|h| h.queued > 0 || h.consecutive_errors > 0)
            .collect();
        out.sort_by(|a, b| b.queued.cmp(&a.queued).then(a.host.cmp(&b.host)));
        out
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn backoff_grows_with_errors_and_expires() {
        assert_eq!(backoff_remaining(0, Some(Duration::from_secs(1))), None);
        assert_eq!(backoff_remaining(1, None), None);
        assert_eq!(backoff_remaining(1, Some(Duration::from_secs(4))), Some(Duration::from_secs(6)));
        assert_eq!(backoff_remaining(3, Some(Duration::from_secs(4))), Some(Duration::from_secs(26)));
        assert_eq!(backoff_remaining(1, Some(Duration::from_secs(10))), None);
        assert!(backoff_remaining(u32::MAX, Some(Duration::ZERO)).is_some());
    }

    #[test]
    fn idle_hosts_are_not_listed() {
        let stats = RelayStats::default();
        stats.host("idle.example");
        stats.host("busy.example").queued.store(3, Ordering::Relaxed);
        let failing = stats.host("failing.example");
        failing.consecutive_errors.store(2, Ordering::Relaxed);
        *failing.last_request.lock().unwrap() = Some(Instant::now());
        let hosts = stats.hosts();
        assert_eq!(hosts.iter().map(|h| h.host.as_str()).collect::<Vec<_>>(), vec!["busy.example", "failing.example"]);
        assert!(hosts[1].backoff_seconds > 0 && hosts[1].backoff_seconds <= 20);
        bump(&stats.counters.posts_relayed);
        assert_eq!(stats.counters.snapshot().posts_relayed, 1);
    }

    #[test]
    fn a_removal_counts_the_rows_and_both_kinds_of_reject() {
        let counters = Counters::default();
        counters.record_removed(3);
        counters.record_reject(true);
        counters.record_reject(true);
        counters.record_reject(false);
        let snapshot = counters.snapshot();
        // the rows that are gone, not the rejects that were sent
        assert_eq!(snapshot.subscribers_removed, 3);
        assert_eq!(snapshot.rejects_sent, 2);
        assert_eq!(snapshot.rejects_failed, 1);
        // the counters are serialised for the admin API
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("\"rejects_failed\":1"), "{json}");
        assert!(json.contains("\"rejects_sent\":2"), "{json}");
    }
}
