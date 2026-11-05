use std::{sync::Arc, time::Instant};
use metrics::histogram;
use tokio_postgres::{Client, Error, NoTls, Statement};
use crate::policy::{self, Policy, SourcePattern};


/// One schema version. Statements run in order inside one transaction,
/// together with recording the version, so a version is applied completely
/// or not at all.
pub struct Migration {
    pub version: i32,
    pub statements: &'static [&'static str],
    /// Fill the `streams` table from the config file's `streams`, once: from
    /// then on the table is authoritative.
    pub seed_streams: bool,
}

/// Ordered schema history. Never edit an applied version: add a new one.
pub const MIGRATIONS: &[Migration] = &[
    // The original schema, as created by unversioned releases.
    Migration {
        version: 1,
        statements: &[
            "CREATE TABLE IF NOT EXISTS follows (id TEXT NOT NULL, inbox TEXT NOT NULL, actor TEXT NOT NULL, UNIQUE (inbox, actor))",
            "CREATE INDEX IF NOT EXISTS follows_actor ON follows (actor) INCLUDE (inbox)",
        ],
        seed_streams: false,
    },
    // A follow is one remote actor following one relay actor. Followers on
    // the same instance share a sharedInbox, so (inbox, actor) rejected the
    // second of them. Rows that repeat (id, actor) with another inbox (an
    // actor that moved) collapse to one, chosen arbitrarily: the follower is
    // kept, and its next Follow sets the inbox.
    Migration {
        version: 2,
        statements: &[
            "DELETE FROM follows a USING follows b WHERE a.id = b.id AND a.actor = b.actor AND a.ctid < b.ctid",
            "ALTER TABLE follows DROP CONSTRAINT IF EXISTS follows_inbox_actor_key",
            "ALTER TABLE follows ADD CONSTRAINT follows_id_actor_key UNIQUE (id, actor)",
        ],
        seed_streams: false,
    },
    // Management: policy tables, runtime streams, the pause flag, and the
    // Follow activity id (a Reject sent later refers to it).
    Migration {
        version: 3,
        statements: &[
            "ALTER TABLE follows ADD COLUMN IF NOT EXISTS follow_id TEXT",
            "CREATE TABLE IF NOT EXISTS blocked_domains (domain TEXT PRIMARY KEY, reason TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now())",
            "CREATE TABLE IF NOT EXISTS blocked_sources (pattern TEXT PRIMARY KEY, reason TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now())",
            "CREATE TABLE IF NOT EXISTS streams (url TEXT PRIMARY KEY, enabled BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT now())",
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            "INSERT INTO settings (key, value) VALUES ('paused', 'false') ON CONFLICT (key) DO NOTHING",
        ],
        seed_streams: true,
    },
];

/// Serializes concurrent migrators (two relays starting on one database).
const MIGRATION_LOCK: i64 = 0x6275_7a7a_7265_6c61; // "buzzrela"

async fn migrate(client: &mut Client, seed_streams: &[String]) -> Result<Vec<i32>, Error> {
    let tx = client.transaction().await?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK]).await?;
    // under the lock: two first starts must not race on creating it
    tx.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
        &[],
    ).await?;
    let applied: Vec<i32> = tx.query("SELECT version FROM schema_migrations", &[])
        .await?
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    let mut newly = vec![];
    for migration in MIGRATIONS {
        if applied.contains(&migration.version) {
            continue;
        }
        for statement in migration.statements {
            tx.execute(*statement, &[]).await?;
        }
        if migration.seed_streams {
            for url in seed_streams {
                tx.execute("INSERT INTO streams (url) VALUES ($1) ON CONFLICT (url) DO NOTHING", &[url]).await?;
            }
        }
        tx.execute("INSERT INTO schema_migrations (version) VALUES ($1)", &[&migration.version]).await?;
        newly.push(migration.version);
    }
    tx.commit().await?;
    Ok(newly)
}

#[derive(Clone)]
pub struct Database {
    inner: Arc<DatabaseInner>,
}

struct DatabaseInner {
    client: Client,
    add_follow: Statement,
    del_follow: Statement,
    get_following_inboxes: Statement,
    get_follows_count: Statement,
    get_followers_count: Statement,
}

impl Database {
    pub async fn connect(conn_str: &str, seed_streams: &[String]) -> Self {
        let (mut client, connection) = tokio_postgres::connect(conn_str, NoTls)
            .await
            .unwrap();

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::error!("postgresql: {}", e);
            }
        });

        let applied = migrate(&mut client, seed_streams).await
            .expect("database migration");
        if !applied.is_empty() {
            tracing::info!("applied schema versions {applied:?}");
        }
        let add_follow = client.prepare("INSERT INTO follows (id, inbox, actor, follow_id) VALUES ($1, $2, $3, $4) ON CONFLICT (id, actor) DO UPDATE SET inbox = EXCLUDED.inbox, follow_id = EXCLUDED.follow_id")
            .await
            .unwrap();
        let del_follow = client.prepare("DELETE FROM follows WHERE id=$1 AND actor=$2")
            .await
            .unwrap();
        let get_following_inboxes = client.prepare("SELECT DISTINCT inbox FROM follows WHERE actor=$1")
            .await
            .unwrap();
        let get_follows_count = client.prepare("SELECT COUNT(id) FROM follows")
            .await
            .unwrap();
        let get_followers_count = client.prepare("SELECT COUNT(DISTINCT id) FROM follows")
            .await
            .unwrap();

        Database {
            inner: Arc::new(DatabaseInner {
                client,
                add_follow,
                del_follow,
                get_following_inboxes,
                get_follows_count,
                get_followers_count,
            }),
        }
    }

    pub async fn add_follow(&self, id: &str, inbox: &str, actor: &str, follow_id: Option<&str>) -> Result<(), Error> {
        let t1 = Instant::now();
        self.inner.client.execute(&self.inner.add_follow, &[&id, &inbox, &actor, &follow_id])
            .await?;
        let t2 = Instant::now();
        histogram!("postgres_query_duration", "query" => "add_follow")
            .record(t2 - t1);
        Ok(())
    }

    pub async fn del_follow(&self, id: &str, actor: &str) -> Result<(), Error> {
        let t1 = Instant::now();
        self.inner.client.execute(&self.inner.del_follow, &[&id, &actor])
            .await?;
        let t2 = Instant::now();
        histogram!("postgres_query_duration", "query" => "del_follow")
            .record(t2 - t1);
        Ok(())
    }

    pub async fn get_following_inboxes(&self, actor: &str) -> Result<impl Iterator<Item = String>, Error> {
        let t1 = Instant::now();
        let rows = self.inner.client.query(&self.inner.get_following_inboxes, &[&actor])
            .await?;
        let t2 = Instant::now();
        histogram!("postgres_query_duration", "query" => "get_following_inboxes")
            .record(t2 - t1);
        Ok(rows.into_iter()
           .map(|row| row.get(0))
        )
    }

    pub async fn get_follows_count(&self) -> Result<i64, Error> {
        let row = self.inner.client.query_one(&self.inner.get_follows_count, &[])
            .await?;
        Ok(row.get(0))
    }

    pub async fn get_followers_count(&self) -> Result<i64, Error> {
        let row = self.inner.client.query_one(&self.inner.get_followers_count, &[])
            .await?;
        Ok(row.get(0))
    }

    pub async fn ping(&self) -> Result<(), Error> {
        self.inner.client.query_one("SELECT 1", &[]).await?;
        Ok(())
    }

    /// Every follow, or those of one relay actor.
    pub async fn list_follows(&self, actor: Option<&str>) -> Result<Vec<Follow>, Error> {
        let rows = self.inner.client.query(
            "SELECT id, inbox, actor, follow_id FROM follows WHERE ($1::TEXT IS NULL OR actor = $1) ORDER BY actor, id",
            &[&actor],
        ).await?;
        Ok(rows.iter().map(Follow::from_row).collect())
    }

    /// Deletes a follower's follows (of one relay actor, or all) and returns them.
    pub async fn remove_follows(&self, follower: &str, actor: Option<&str>) -> Result<Vec<Follow>, Error> {
        let rows = self.inner.client.query(
            "DELETE FROM follows WHERE id = $1 AND ($2::TEXT IS NULL OR actor = $2) RETURNING id, inbox, actor, follow_id",
            &[&follower, &actor],
        ).await?;
        Ok(rows.iter().map(Follow::from_row).collect())
    }

    /// Deletes every follow whose follower or inbox is on `domain` or below.
    /// Matching is done here, with the same rule as the policy, rather than
    /// in SQL.
    pub async fn remove_follows_on_domain(&self, domain: &str) -> Result<u64, Error> {
        let only = Policy::new([domain.to_string()], [], false);
        let followers: Vec<String> = self.list_follows(None).await?
            .into_iter()
            .filter(|f| only.follower_matches(&f.id, &f.inbox))
            .map(|f| f.id)
            .collect();
        if followers.is_empty() {
            return Ok(0);
        }
        self.inner.client.execute("DELETE FROM follows WHERE id = ANY($1)", &[&followers]).await
    }

    /// Followers and distinct inboxes per relay actor, most followed first.
    pub async fn actor_counts(&self) -> Result<Vec<ActorCount>, Error> {
        let rows = self.inner.client.query(
            "SELECT actor, COUNT(DISTINCT id), COUNT(DISTINCT inbox) FROM follows GROUP BY actor ORDER BY 2 DESC, actor",
            &[],
        ).await?;
        Ok(rows.iter().map(|row| ActorCount {
            actor: row.get(0),
            followers: row.get(1),
            inboxes: row.get(2),
        }).collect())
    }

    pub async fn list_blocks(&self, kind: BlockKind) -> Result<Vec<BlockRow>, Error> {
        let (table, key) = kind.table();
        let rows = self.inner.client.query(
            &format!("SELECT {key}, reason, {CREATED_AT} FROM {table} ORDER BY {key}"),
            &[],
        ).await?;
        Ok(rows.iter().map(|row| BlockRow {
            key: row.get(0),
            reason: row.get(1),
            created_at: row.get(2),
        }).collect())
    }

    /// Inserts or updates the reason; true when the row is new.
    pub async fn put_block(&self, kind: BlockKind, key: &str, reason: &str) -> Result<bool, Error> {
        let (table, column) = kind.table();
        let row = self.inner.client.query_one(
            &format!("INSERT INTO {table} ({column}, reason) VALUES ($1, $2) ON CONFLICT ({column}) DO UPDATE SET reason = EXCLUDED.reason RETURNING (xmax = 0)"),
            &[&key, &reason],
        ).await?;
        Ok(row.get(0))
    }

    /// True when a row was deleted.
    pub async fn delete_block(&self, kind: BlockKind, key: &str) -> Result<bool, Error> {
        let (table, column) = kind.table();
        let n = self.inner.client.execute(&format!("DELETE FROM {table} WHERE {column} = $1"), &[&key]).await?;
        Ok(n > 0)
    }

    pub async fn list_streams(&self) -> Result<Vec<StreamRow>, Error> {
        let rows = self.inner.client.query(
            &format!("SELECT url, enabled, {CREATED_AT} FROM streams ORDER BY url"),
            &[],
        ).await?;
        Ok(rows.iter().map(|row| StreamRow {
            url: row.get(0),
            enabled: row.get(1),
            created_at: row.get(2),
        }).collect())
    }

    /// Inserts or sets `enabled`; true when the row is new.
    pub async fn put_stream(&self, url: &str, enabled: bool) -> Result<bool, Error> {
        let row = self.inner.client.query_one(
            "INSERT INTO streams (url, enabled) VALUES ($1, $2) ON CONFLICT (url) DO UPDATE SET enabled = EXCLUDED.enabled RETURNING (xmax = 0)",
            &[&url, &enabled],
        ).await?;
        Ok(row.get(0))
    }

    pub async fn delete_stream(&self, url: &str) -> Result<bool, Error> {
        let n = self.inner.client.execute("DELETE FROM streams WHERE url = $1", &[&url]).await?;
        Ok(n > 0)
    }

    pub async fn paused(&self) -> Result<bool, Error> {
        let row = self.inner.client.query_opt("SELECT value FROM settings WHERE key = 'paused'", &[]).await?;
        Ok(row.is_some_and(|row| row.get::<_, String>(0) == "true"))
    }

    pub async fn set_paused(&self, paused: bool) -> Result<(), Error> {
        let value = if paused { "true" } else { "false" };
        self.inner.client.execute(
            "INSERT INTO settings (key, value) VALUES ('paused', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            &[&value],
        ).await?;
        Ok(())
    }

    /// The policy snapshot the relay loop consults. Rows that no longer
    /// parse (written by hand) are skipped with a warning.
    pub async fn load_policy(&self) -> Result<Policy, Error> {
        let domains = self.list_blocks(BlockKind::Domain).await?
            .into_iter()
            .filter_map(|row| {
                let domain = policy::normalize_domain(&row.key);
                if domain.is_none() {
                    tracing::warn!("blocked_domains: unusable row {:?}", row.key);
                }
                domain
            });
        let sources: Vec<SourcePattern> = self.list_blocks(BlockKind::Source).await?
            .into_iter()
            .filter_map(|row| {
                let pattern = SourcePattern::parse(&row.key);
                if pattern.is_none() {
                    tracing::warn!("blocked_sources: unusable row {:?}", row.key);
                }
                pattern
            })
            .collect();
        let domains: Vec<String> = domains.collect();
        Ok(Policy::new(domains, sources, self.paused().await?))
    }

    /// Enabled stream URLs: what the supervisor should run.
    pub async fn enabled_streams(&self) -> Result<Vec<String>, Error> {
        Ok(self.list_streams().await?
            .into_iter()
            .filter(|s| s.enabled)
            .map(|s| s.url)
            .collect())
    }
}

const CREATED_AT: &str = r#"to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')"#;

impl Follow {
    fn from_row(row: &tokio_postgres::Row) -> Self {
        Follow {
            id: row.get(0),
            inbox: row.get(1),
            actor: row.get(2),
            follow_id: row.get(3),
        }
    }
}

impl BlockKind {
    /// (table, key column): fixed identifiers, never user input.
    fn table(self) -> (&'static str, &'static str) {
        match self {
            BlockKind::Domain => ("blocked_domains", "domain"),
            BlockKind::Source => ("blocked_sources", "pattern"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Follow {
    pub id: String,
    pub inbox: String,
    pub actor: String,
    pub follow_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorCount {
    pub actor: String,
    pub followers: i64,
    pub inboxes: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    Domain,
    Source,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRow {
    pub key: String,
    pub reason: String,
    /// RFC 3339, UTC
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRow {
    pub url: String,
    pub enabled: bool,
    pub created_at: String,
}


/// PostgreSQL-backed tests. They need a server: set `BUZZRELAY_TEST_DB` to a
/// libpq connection string for a database the test user may create schemas
/// in, and run `cargo test -- --include-ignored`. Each test works in its own
/// schema.
#[cfg(test)]
mod test {
    use super::MIGRATIONS;

    #[test]
    fn migration_versions_strictly_increase_from_one() {
        let versions: Vec<i32> = MIGRATIONS.iter().map(|m| m.version).collect();
        let expected: Vec<i32> = (1..=MIGRATIONS.len() as i32).collect();
        assert_eq!(versions, expected);
    }
}

#[cfg(test)]
pub mod pg_tests {
    use super::*;

    pub async fn test_db() -> String {
        let base = std::env::var("BUZZRELAY_TEST_DB")
            .expect("BUZZRELAY_TEST_DB must name a test database for --ignored tests");
        let (client, connection) = tokio_postgres::connect(&base, NoTls).await.unwrap();
        tokio::spawn(connection);
        let schema = format!(
            "t_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        client.execute(&format!("CREATE SCHEMA {schema}"), &[]).await.unwrap();
        format!("{base} options=-csearch_path={schema}")
    }

    #[tokio::test]
    #[ignore = "needs BUZZRELAY_TEST_DB"]
    async fn followers_sharing_a_shared_inbox_are_both_stored() {
        let db = Database::connect(&test_db().await, &[]).await;
        db.add_follow("https://a.example/users/alice", "https://a.example/inbox", "https://relay.test/tag/bsd", None).await.unwrap();
        db.add_follow("https://a.example/users/bob", "https://a.example/inbox", "https://relay.test/tag/bsd", None).await.unwrap();
        assert_eq!(db.get_followers_count().await.unwrap(), 2);
        let inboxes: Vec<String> = db.get_following_inboxes("https://relay.test/tag/bsd").await.unwrap().collect();
        assert_eq!(inboxes, vec!["https://a.example/inbox".to_string()]);
    }

    #[tokio::test]
    #[ignore = "needs BUZZRELAY_TEST_DB"]
    async fn refollow_updates_the_inbox() {
        let db = Database::connect(&test_db().await, &[]).await;
        db.add_follow("https://a.example/users/alice", "https://a.example/users/alice/inbox", "https://relay.test/tag/bsd", None).await.unwrap();
        db.add_follow("https://a.example/users/alice", "https://a.example/inbox", "https://relay.test/tag/bsd", None).await.unwrap();
        assert_eq!(db.get_follows_count().await.unwrap(), 1);
        let inboxes: Vec<String> = db.get_following_inboxes("https://relay.test/tag/bsd").await.unwrap().collect();
        assert_eq!(inboxes, vec!["https://a.example/inbox".to_string()]);
    }

    #[tokio::test]
    #[ignore = "needs BUZZRELAY_TEST_DB"]
    async fn legacy_schema_is_migrated_and_migration_is_idempotent() {
        let conn = test_db().await;
        {
            let (client, connection) = tokio_postgres::connect(&conn, NoTls).await.unwrap();
            tokio::spawn(connection);
            // what unversioned releases left behind, with one follower
            client.batch_execute(
                "CREATE TABLE follows (id TEXT NOT NULL, inbox TEXT NOT NULL, actor TEXT NOT NULL, UNIQUE (inbox, actor));
                 CREATE INDEX follows_actor ON follows (actor) INCLUDE (inbox);
                 INSERT INTO follows VALUES ('https://a.example/users/alice', 'https://a.example/inbox', 'https://relay.test/tag/bsd');"
            ).await.unwrap();
        }
        let db = Database::connect(&conn, &[]).await;
        db.add_follow("https://a.example/users/bob", "https://a.example/inbox", "https://relay.test/tag/bsd", None).await.unwrap();
        drop(db);
        // a second start applies nothing and keeps the rows
        let db = Database::connect(&conn, &[]).await;
        assert_eq!(db.get_followers_count().await.unwrap(), 2);
        let (client, connection) = tokio_postgres::connect(&conn, NoTls).await.unwrap();
        tokio::spawn(connection);
        let versions: Vec<i32> = client.query("SELECT version FROM schema_migrations ORDER BY version", &[])
            .await.unwrap().into_iter().map(|r| r.get(0)).collect();
        assert_eq!(versions, (1..=MIGRATIONS.len() as i32).collect::<Vec<_>>());
    }

    const TAG: &str = "https://relay.test/tag/bsd";
    const INST: &str = "https://relay.test/instance/a.example";

    async fn seeded() -> Database {
        let db = Database::connect(&test_db().await, &["https://fedi.buzz/api/v1/streaming/public".to_string()]).await;
        db.add_follow("https://a.example/users/alice", "https://a.example/inbox", TAG, Some("https://a.example/f/1")).await.unwrap();
        db.add_follow("https://a.example/users/alice", "https://a.example/inbox", INST, None).await.unwrap();
        db.add_follow("https://a.example/users/bob", "https://a.example/inbox", TAG, None).await.unwrap();
        db.add_follow("https://m.spam.example/users/x", "https://m.spam.example/inbox", TAG, None).await.unwrap();
        db.add_follow("https://c.example/users/y", "https://spam.example/inbox", TAG, None).await.unwrap();
        db
    }

    #[tokio::test]
    #[ignore = "needs BUZZRELAY_TEST_DB"]
    async fn config_streams_seed_the_table_once() {
        let conn = test_db().await;
        let db = Database::connect(&conn, &["https://a.example/s".to_string()]).await;
        assert!(db.delete_stream("https://a.example/s").await.unwrap());
        drop(db);
        let db = Database::connect(&conn, &["https://a.example/s".to_string()]).await;
        assert!(db.list_streams().await.unwrap().is_empty(), "a deleted stream is not re-seeded");
        assert!(!db.paused().await.unwrap());
        db.ping().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "needs BUZZRELAY_TEST_DB"]
    async fn follows_are_listed_and_removed() {
        let db = seeded().await;
        assert_eq!(db.list_follows(None).await.unwrap().len(), 5);
        let inst = db.list_follows(Some(INST)).await.unwrap();
        assert_eq!(inst, vec![Follow { id: "https://a.example/users/alice".into(), inbox: "https://a.example/inbox".into(), actor: INST.into(), follow_id: None }]);
        let removed = db.remove_follows("https://a.example/users/alice", Some(TAG)).await.unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].follow_id.as_deref(), Some("https://a.example/f/1"));
        assert!(db.remove_follows("https://a.example/users/alice", Some(TAG)).await.unwrap().is_empty(), "idempotent");
        assert_eq!(db.remove_follows("https://a.example/users/alice", None).await.unwrap().len(), 1);
        assert_eq!(db.get_follows_count().await.unwrap(), 3);
    }

    #[tokio::test]
    #[ignore = "needs BUZZRELAY_TEST_DB"]
    async fn a_domain_loses_its_follows_by_actor_or_inbox() {
        let db = seeded().await;
        assert_eq!(db.remove_follows_on_domain("spam.example").await.unwrap(), 2);
        assert_eq!(db.remove_follows_on_domain("spam.example").await.unwrap(), 0);
        let left: Vec<String> = db.list_follows(None).await.unwrap().into_iter().map(|f| f.id).collect();
        assert!(left.iter().all(|id| id.starts_with("https://a.example/")), "{left:?}");
    }

    #[tokio::test]
    #[ignore = "needs BUZZRELAY_TEST_DB"]
    async fn actor_counts_group_followers() {
        let db = seeded().await;
        let counts = db.actor_counts().await.unwrap();
        assert_eq!(counts[0], ActorCount { actor: TAG.into(), followers: 4, inboxes: 3 });
        assert_eq!(counts[1], ActorCount { actor: INST.into(), followers: 1, inboxes: 1 });
    }

    #[tokio::test]
    #[ignore = "needs BUZZRELAY_TEST_DB"]
    async fn blocks_are_idempotent_and_feed_the_policy() {
        let db = seeded().await;
        assert!(db.put_block(BlockKind::Domain, "spam.example", "spam").await.unwrap());
        assert!(!db.put_block(BlockKind::Domain, "spam.example", "still spam").await.unwrap());
        assert!(db.put_block(BlockKind::Source, "bot@a.example", "").await.unwrap());
        let domains = db.list_blocks(BlockKind::Domain).await.unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].reason, "still spam");
        assert!(domains[0].created_at.ends_with('Z'), "{}", domains[0].created_at);
        db.set_paused(true).await.unwrap();
        let policy = db.load_policy().await.unwrap();
        assert!(policy.paused);
        assert!(policy.domain_blocked("x.spam.example"));
        assert!(policy.source_blocked(Some("b.example"), Some("bot@a.example")));
        assert!(db.delete_block(BlockKind::Domain, "spam.example").await.unwrap());
        assert!(!db.delete_block(BlockKind::Domain, "spam.example").await.unwrap());
        db.set_paused(false).await.unwrap();
        let policy = db.load_policy().await.unwrap();
        assert!(!policy.paused && !policy.domain_blocked("spam.example"));
    }

    #[tokio::test]
    #[ignore = "needs BUZZRELAY_TEST_DB"]
    async fn streams_are_put_and_deleted() {
        let db = seeded().await;
        assert!(db.put_stream("https://b.example/s", true).await.unwrap());
        assert!(!db.put_stream("https://b.example/s", false).await.unwrap());
        let streams = db.list_streams().await.unwrap();
        assert_eq!(streams.iter().map(|s| (s.url.as_str(), s.enabled)).collect::<Vec<_>>(),
            vec![("https://b.example/s", false), ("https://fedi.buzz/api/v1/streaming/public", true)]);
        assert!(db.delete_stream("https://b.example/s").await.unwrap());
        assert!(!db.delete_stream("https://b.example/s").await.unwrap());
    }
}
