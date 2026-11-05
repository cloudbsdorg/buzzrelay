use axum::{response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    #[serde(rename = "@context")]
    pub jsonld_context: serde_json::Value,
    #[serde(rename = "type")]
    pub actor_type: String,
    pub id: String,
    pub name: Option<String>,
    pub icon: Option<Media>,
    pub inbox: String,
    pub outbox: Option<String>,
    pub endpoints: Option<ActorEndpoints>,
    #[serde(rename = "publicKey")]
    pub public_key: ActorPublicKey,
    #[serde(rename = "preferredUsername")]
    pub preferred_username: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorEndpoints {
    #[serde(rename = "sharedInbox")]
    pub shared_inbox: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorPublicKey {
    pub id: String,
    pub owner: Option<String>,
    #[serde(rename = "publicKeyPem")]
    pub pem: String,
}

/// `ActivityPub` "activity"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action<O> {
    #[serde(rename = "@context")]
    pub jsonld_context: serde_json::Value,
    #[serde(rename = "type")]
    pub action_type: String,
    pub id: String,
    pub actor: String,
    pub to: Option<serde_json::Value>,
    pub object: Option<O>,
}

impl IntoResponse for Actor {
    fn into_response(self) -> axum::response::Response {
        ([("content-type", "application/activity+json")],
         Json(self)).into_response()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Media {
    #[serde(rename = "type")]
    pub media_type: Option<String>,
    #[serde(rename = "mediaType")]
    pub content_type: Option<String>,
    pub url: String,
}

/// An `Accept` or `Reject` of a Follow, sent by the relay actor `target` to
/// the follower. `follow` is the Follow being answered.
pub fn follow_response(
    kind: FollowResponse,
    hostname: &str,
    target: &str,
    follower: &str,
    follower_inbox: &str,
    follow: serde_json::Value,
) -> Action<serde_json::Value> {
    let id = match kind {
        FollowResponse::Accept => format!(
            "https://{hostname}/activity/accept/{}/{}",
            urlencoding::encode(target),
            urlencoding::encode(follower_inbox),
        ),
        FollowResponse::Reject => {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            format!(
                "https://{hostname}/activity/reject/{}/{}/{nonce}{:x}",
                urlencoding::encode(target),
                urlencoding::encode(follower_inbox),
                REJECT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            )
        }
    };
    Action {
        jsonld_context: serde_json::Value::String("https://www.w3.org/ns/activitystreams".to_string()),
        action_type: match kind {
            FollowResponse::Accept => "Accept",
            FollowResponse::Reject => "Reject",
        }.to_string(),
        actor: target.to_string(),
        to: Some(serde_json::json!(follower)),
        id,
        object: Some(follow),
    }
}

static REJECT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowResponse {
    Accept,
    Reject,
}

/// The Follow a `Reject` refers to when the original activity is not at hand
/// (a subscriber removed later). `follow_id` is the Follow's own id when it
/// was recorded; Mastodon matches relay subscriptions by it.
pub fn embedded_follow(follow_id: Option<&str>, follower: &str, target: &str) -> serde_json::Value {
    let mut follow = serde_json::json!({
        "type": "Follow",
        "actor": follower,
        "object": target,
    });
    if let Some(id) = follow_id {
        follow["id"] = serde_json::Value::String(id.to_string());
    }
    follow
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn accept_keeps_the_upstream_id_and_embeds_the_follow() {
        let follow = serde_json::json!({"type": "Follow", "id": "https://a.example/f/1"});
        let accept = follow_response(FollowResponse::Accept, "relay.test", "https://relay.test/tag/bsd",
            "https://a.example/users/alice", "https://a.example/inbox", follow.clone());
        assert_eq!(accept.action_type, "Accept");
        assert_eq!(accept.actor, "https://relay.test/tag/bsd");
        assert_eq!(accept.to, Some(serde_json::json!("https://a.example/users/alice")));
        assert_eq!(accept.id, "https://relay.test/activity/accept/https%3A%2F%2Frelay.test%2Ftag%2Fbsd/https%3A%2F%2Fa.example%2Finbox");
        assert_eq!(accept.object, Some(follow));
    }

    #[test]
    fn rejects_get_distinct_ids() {
        let reject = |_| follow_response(FollowResponse::Reject, "relay.test", "https://relay.test/tag/bsd",
            "https://a.example/users/alice", "https://a.example/inbox", serde_json::json!({}));
        let (a, b) = (reject(1), reject(2));
        assert_eq!(a.action_type, "Reject");
        assert!(a.id.starts_with("https://relay.test/activity/reject/"), "{}", a.id);
        assert_ne!(a.id, b.id, "a later Reject must not be deduplicated against an earlier one");
    }

    #[test]
    fn embedded_follow_carries_the_recorded_id() {
        let f = embedded_follow(Some("https://a.example/f/1"), "https://a.example/users/alice", "https://relay.test/tag/bsd");
        assert_eq!(f, serde_json::json!({
            "type": "Follow", "id": "https://a.example/f/1",
            "actor": "https://a.example/users/alice", "object": "https://relay.test/tag/bsd",
        }));
        let f = embedded_follow(None, "https://a.example/users/alice", "https://relay.test/tag/bsd");
        assert!(f.get("id").is_none());
        assert_eq!(f["actor"], "https://a.example/users/alice");
    }
}
