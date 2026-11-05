//! Relay policy: blocked domains, blocked post sources and the pause flag.
//! Pure logic; the rows live in PostgreSQL (see `db`) and a snapshot is held
//! in `State` so the relay loop never queries per post.

use std::collections::HashSet;

/// Lower-cases and validates a DNS name. Accepts a leading `*.` or `@` and a
/// trailing dot. Rejects anything that is not letters, digits, `-` and `.`
/// labels, so a URL or an acct is never stored as a domain.
pub fn normalize_domain(input: &str) -> Option<String> {
    let mut domain = input.trim().to_ascii_lowercase();
    if let Some(rest) = domain.strip_prefix("*.").or_else(|| domain.strip_prefix('@')) {
        domain = rest.to_string();
    }
    if let Some(rest) = domain.strip_suffix('.') {
        domain = rest.to_string();
    }
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if domain.split('.').all(label_ok) {
        Some(domain)
    } else {
        None
    }
}

/// The lower-cased host of an http(s) URL.
pub fn host_of(url: &str) -> Option<String> {
    let url = reqwest::Url::parse(url).ok()?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return None;
    }
    url.host_str().map(str::to_ascii_lowercase)
}

/// What a `blocked_sources` row matches: every post from a host (and its
/// subdomains), or every post from one account.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SourcePattern {
    Host(String),
    Acct { user: String, host: String },
}

impl SourcePattern {
    /// `example.com`, `user@example.com` or `@user@example.com`.
    pub fn parse(input: &str) -> Option<Self> {
        let input = input.trim();
        let input = input.strip_prefix('@').unwrap_or(input);
        match input.split_once('@') {
            None => normalize_domain(input)
                .filter(|_| !input.starts_with("*."))
                .map(SourcePattern::Host),
            Some((user, host)) => {
                let user = user.to_ascii_lowercase();
                let user_ok = !user.is_empty()
                    && user.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-');
                if !user_ok || host.contains('@') || host.starts_with('@') {
                    return None;
                }
                let host = normalize_domain(host)?;
                Some(SourcePattern::Acct { user, host })
            }
        }
    }

    /// The normalized text stored as the row key.
    pub fn key(&self) -> String {
        match self {
            SourcePattern::Host(host) => host.clone(),
            SourcePattern::Acct { user, host } => format!("{user}@{host}"),
        }
    }
}

/// The full `user@host` of a post's author: Mastodon gives local authors a
/// bare `user`, so the post's own host completes it.
pub fn full_acct(acct: &str, post_host: Option<&str>) -> Option<String> {
    let acct = acct.trim().trim_start_matches('@').to_ascii_lowercase();
    if acct.is_empty() {
        return None;
    }
    if let Some((user, host)) = acct.split_once('@') {
        normalize_domain(host).map(|host| format!("{user}@{host}"))
    } else {
        post_host.map(|host| format!("{acct}@{}", host.to_ascii_lowercase()))
    }
}

/// Lower case without the trailing dot of a fully qualified name, so
/// `Spam.Example.` meets the stored `spam.example`.
fn canonical_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// The host itself and every parent domain: `a.b.c`, `b.c`, `c`.
fn self_and_parents(host: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(host), |h| h.split_once('.').map(|(_, rest)| rest))
}

#[derive(Debug, Clone, Default)]
pub struct Policy {
    domains: HashSet<String>,
    source_hosts: HashSet<String>,
    source_accts: HashSet<String>,
    pub paused: bool,
}

impl Policy {
    pub fn new(domains: impl IntoIterator<Item = String>, sources: impl IntoIterator<Item = SourcePattern>, paused: bool) -> Self {
        let mut policy = Policy {
            domains: domains.into_iter().collect(),
            paused,
            ..Policy::default()
        };
        for source in sources {
            match source {
                SourcePattern::Host(host) => policy.source_hosts.insert(host),
                acct @ SourcePattern::Acct { .. } => policy.source_accts.insert(acct.key()),
            };
        }
        policy
    }

    /// Is this host, or a domain above it, blocked?
    pub fn domain_blocked(&self, host: &str) -> bool {
        if self.domains.is_empty() {
            return false;
        }
        let host = canonical_host(host);
        let blocked = self_and_parents(&host).any(|d| self.domains.contains(d));
        blocked
    }

    /// Is a would-be follower on a blocked domain? Both its actor id and its
    /// inbox count, so a blocked instance cannot subscribe through a
    /// sharedInbox elsewhere or an actor hosted elsewhere.
    pub fn follower_blocked(&self, actor_id: &str, inbox: &str) -> bool {
        [actor_id, inbox].iter()
            .filter_map(|url| host_of(url))
            .any(|host| self.domain_blocked(&host))
    }

    /// Is a post from this host and author filtered out?
    pub fn source_blocked(&self, host: Option<&str>, acct: Option<&str>) -> bool {
        if let Some(host) = host {
            let host = canonical_host(host);
            let blocked = self_and_parents(&host).any(|d| self.source_hosts.contains(d));
            if blocked {
                return true;
            }
        }
        acct.is_some_and(|acct| self.source_accts.contains(&acct.to_ascii_lowercase()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn domains_are_normalized() {
        assert_eq!(normalize_domain("Example.COM."), Some("example.com".into()));
        assert_eq!(normalize_domain(" *.spam.example "), Some("spam.example".into()));
        assert_eq!(normalize_domain("@spam.example"), Some("spam.example".into()));
        assert_eq!(normalize_domain("xn--bcher-kva.example"), Some("xn--bcher-kva.example".into()));
    }

    #[test]
    fn non_domains_are_refused() {
        for bad in ["", ".", "https://example.com/", "user@example.com", "exa mple.com", "a..b", "-a.example", "a-.example", "%.example", "a_b.example", &"a".repeat(64)] {
            assert_eq!(normalize_domain(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn host_of_urls() {
        assert_eq!(host_of("https://Mastodon.Example/users/a"), Some("mastodon.example".into()));
        assert_eq!(host_of("https://mastodon.example:8443/inbox"), Some("mastodon.example".into()));
        assert_eq!(host_of("not a url"), None);
        assert_eq!(host_of("mailto:a@example.com"), None);
    }

    #[test]
    fn source_patterns_parse() {
        assert_eq!(SourcePattern::parse("Spam.Example"), Some(SourcePattern::Host("spam.example".into())));
        assert_eq!(SourcePattern::parse("@Bot@Spam.Example"), Some(SourcePattern::Acct { user: "bot".into(), host: "spam.example".into() }));
        assert_eq!(SourcePattern::parse("bot@spam.example").unwrap().key(), "bot@spam.example");
        assert_eq!(SourcePattern::parse("spam.example").unwrap().key(), "spam.example");
        for bad in ["", "@", "bot@", "@spam.example@", "a b@spam.example", "bot@not a host", "https://spam.example/@bot"] {
            assert_eq!(SourcePattern::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn full_acct_completes_local_authors() {
        assert_eq!(full_acct("alice", Some("a.example")), Some("alice@a.example".into()));
        assert_eq!(full_acct("Alice@B.Example", Some("a.example")), Some("alice@b.example".into()));
        assert_eq!(full_acct("alice", None), None);
        assert_eq!(full_acct("", Some("a.example")), None);
        // the host part is canonicalized like a stored pattern
        assert_eq!(full_acct("bot@A.Example.", Some("x.example")), Some("bot@a.example".into()));
        assert_eq!(full_acct("bot@not a host", Some("x.example")), None);
    }

    #[test]
    fn a_blocked_domain_covers_its_subdomains_only() {
        let policy = Policy::new(["spam.example".to_string()], [], false);
        assert!(policy.domain_blocked("spam.example"));
        assert!(policy.domain_blocked("relay.spam.example"));
        assert!(policy.domain_blocked("Relay.Spam.Example"));
        assert!(!policy.domain_blocked("notspam.example"));
        assert!(!policy.domain_blocked("example"));
        assert!(!Policy::default().domain_blocked("spam.example"));
        // a fully qualified name with its trailing dot is the same host
        assert!(policy.domain_blocked("spam.example."));
        assert!(policy.follower_blocked("https://spam.example./users/a", "https://ok.example/inbox"));
    }

    #[test]
    fn sources_match_by_host_or_account() {
        let policy = Policy::new(
            [],
            [SourcePattern::parse("spam.example").unwrap(), SourcePattern::parse("bot@a.example").unwrap()],
            false,
        );
        assert!(policy.source_blocked(Some("spam.example"), None));
        assert!(policy.source_blocked(Some("m.spam.example"), Some("x@m.spam.example")));
        assert!(policy.source_blocked(Some("a.example"), Some("bot@a.example")));
        assert!(policy.source_blocked(Some("c.example"), Some("BOT@a.example")));
        assert!(!policy.source_blocked(Some("a.example"), Some("alice@a.example")));
        assert!(!policy.source_blocked(None, None));
        assert!(policy.source_blocked(Some("spam.example."), None));
    }

    #[test]
    fn followers_are_blocked_by_actor_or_inbox_host() {
        let policy = Policy::new(["spam.example".to_string()], [], false);
        assert!(policy.follower_blocked("https://spam.example/users/a", "https://ok.example/inbox"));
        assert!(policy.follower_blocked("https://ok.example/users/a", "https://m.spam.example/inbox"));
        assert!(!policy.follower_blocked("https://ok.example/users/a", "https://ok.example/inbox"));
        assert!(!policy.follower_blocked("not a url", "also not"));
    }
}
