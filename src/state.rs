use axum::{
    extract::FromRef,
};
use sigh::{PrivateKey, PublicKey};
use std::sync::{Arc, RwLock};
use crate::{config::Config, db::Database, actor_cache::ActorCache, policy::Policy, stats::RelayStats};

#[derive(Clone)]
pub struct State {
    pub database: Database,
    pub redis: Option<(redis::aio::ConnectionManager, Arc<String>)>,
    pub client: Arc<reqwest::Client>,
    pub actor_cache: ActorCache,
    pub hostname: Arc<String>,
    pub priv_key: Arc<PrivateKey>,
    pub pub_key: Arc<PublicKey>,
    /// Snapshot of the policy tables; replaced on every admin change and
    /// every reconcile period.
    policy: Arc<RwLock<Arc<Policy>>>,
    pub stats: Arc<RelayStats>,
}


impl FromRef<State> for Arc<reqwest::Client> {
    fn from_ref(state: &State) -> Arc<reqwest::Client> {
        state.client.clone()
    }
}

impl State {
    pub fn new(config: Config, database: Database, redis: Option<(redis::aio::ConnectionManager, String)>, client: reqwest::Client) -> Self {
        let priv_key = Arc::new(config.priv_key());
        let pub_key = Arc::new(config.pub_key());
        State {
            database,
            redis: redis.map(|(connection, in_topic)| (connection, Arc::new(in_topic))),
            client: Arc::new(client),
            actor_cache: ActorCache::default(),
            hostname: Arc::new(config.hostname),
            priv_key,
            pub_key,
            policy: Arc::default(),
            stats: Arc::default(),
        }
    }

    pub fn policy(&self) -> Arc<Policy> {
        self.policy.read().unwrap().clone()
    }

    pub async fn reload_policy(&self) -> Result<(), tokio_postgres::Error> {
        let policy = Arc::new(self.database.load_policy().await?);
        *self.policy.write().unwrap() = policy;
        Ok(())
    }
}
