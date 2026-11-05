//! The admin API's view of the running relay.

use std::sync::Arc;

use metrics_exporter_prometheus::PrometheusHandle;

use crate::{
    activitypub::{self, FollowResponse},
    admin::{AdminBackend, BackendResult, SubscribersRemoved},
    db::{ActorCount, BlockKind, BlockRow, Follow, StreamRow},
    policy::Policy,
    send,
    state::State,
    stats::{CounterSnapshot, HostSnapshot},
    streams::{StreamStatus, Supervisor},
};

#[derive(Clone)]
pub struct RelayAdmin {
    pub state: State,
    pub supervisor: Arc<Supervisor>,
    pub metrics: PrometheusHandle,
}

impl RelayAdmin {
    async fn reload(&self) -> BackendResult<()> {
        self.state.reload_policy().await?;
        Ok(())
    }

    /// A signed Reject{Follow} from the relay actor to the removed follower.
    /// True when it was delivered.
    async fn send_reject(&self, follow: &Follow) -> bool {
        let reject = activitypub::follow_response(
            FollowResponse::Reject,
            &self.state.hostname,
            &follow.actor,
            &follow.id,
            &follow.inbox,
            activitypub::embedded_follow(follow.follow_id.as_deref(), &follow.id, &follow.actor),
        );
        let key_id = format!("{}#key", follow.actor);
        match send::send(&self.state.client, &follow.inbox, &key_id, &self.state.priv_key, &reject).await {
            Ok(()) => {
                self.state.stats.counters.record_reject(true);
                true
            }
            Err(e) => {
                tracing::error!("reject to {}: {e}", follow.inbox);
                self.state.stats.counters.record_reject(false);
                false
            }
        }
    }
}

impl AdminBackend for RelayAdmin {
    async fn database_ok(&self) -> bool {
        self.state.database.ping().await.is_ok()
    }

    fn policy(&self) -> Arc<Policy> {
        self.state.policy()
    }

    async fn follows(&self, actor: Option<String>) -> BackendResult<Vec<Follow>> {
        Ok(self.state.database.list_follows(actor.as_deref()).await?)
    }

    async fn remove_subscriber(&self, id: String, actor: Option<String>) -> BackendResult<SubscribersRemoved> {
        let removed = self.state.database.remove_follows(&id, actor.as_deref()).await?;
        let mut rejects_sent = 0;
        for follow in &removed {
            if self.send_reject(follow).await {
                rejects_sent += 1;
            }
        }
        // the counter counts the rows that are gone, not the Rejects sent
        self.state.stats.counters.record_removed(removed.len());
        Ok(SubscribersRemoved { removed: removed.len(), rejects_sent })
    }

    async fn actor_counts(&self) -> BackendResult<Vec<ActorCount>> {
        Ok(self.state.database.actor_counts().await?)
    }

    async fn blocks(&self, kind: BlockKind) -> BackendResult<Vec<BlockRow>> {
        Ok(self.state.database.list_blocks(kind).await?)
    }

    async fn block_domain(&self, domain: String, reason: String) -> BackendResult<(bool, u64)> {
        let created = self.state.database.put_block(BlockKind::Domain, &domain, &reason).await?;
        // load the block before deleting: a Follow accepted in the few ms
        // before the reload is still deleted below
        self.reload().await?;
        let removed = self.state.database.remove_follows_on_domain(&domain).await?;
        // follows removed by a block are removed subscribers too
        self.state.stats.counters.record_removed(usize::try_from(removed).unwrap_or(0));
        Ok((created, removed))
    }

    async fn block_source(&self, pattern: String, reason: String) -> BackendResult<bool> {
        let created = self.state.database.put_block(BlockKind::Source, &pattern, &reason).await?;
        self.reload().await?;
        Ok(created)
    }

    async fn unblock(&self, kind: BlockKind, key: String) -> BackendResult<bool> {
        let deleted = self.state.database.delete_block(kind, &key).await?;
        self.reload().await?;
        Ok(deleted)
    }

    async fn streams(&self) -> BackendResult<Vec<StreamRow>> {
        Ok(self.state.database.list_streams().await?)
    }

    fn stream_statuses(&self) -> Vec<(String, StreamStatus)> {
        self.supervisor.statuses()
    }

    async fn put_stream(&self, url: String, enabled: bool) -> BackendResult<bool> {
        let created = self.state.database.put_stream(&url, enabled).await?;
        self.supervisor.request_reconcile();
        Ok(created)
    }

    async fn delete_stream(&self, url: String) -> BackendResult<bool> {
        let deleted = self.state.database.delete_stream(&url).await?;
        self.supervisor.request_reconcile();
        Ok(deleted)
    }

    async fn set_paused(&self, paused: bool) -> BackendResult<()> {
        self.state.database.set_paused(paused).await?;
        self.reload().await
    }

    fn counters(&self) -> CounterSnapshot {
        self.state.stats.counters.snapshot()
    }

    fn hosts(&self) -> Vec<HostSnapshot> {
        self.state.stats.hosts()
    }

    fn metrics(&self) -> String {
        self.metrics.render()
    }
}
