# buzzrelay

A follow-only ActivityPub relay that connects to Mastodon's [Streaming
API](https://docs.joinmastodon.org/methods/streaming/#public).

You don't need to run this yourself, just use the instance at
[relay.fedi.buzz](https://relay.fedi.buzz/).

## Setup

See also: [Notes on an setting up a fediverse relay with FediBuzz on an Ubuntu server.](https://box464.com/posts/fediverse-relays/)

### Build

NixOS/Flakes users are in luck: not only does this build, it also
comes with a NixOS module!

Anyone else installs a Rust toolchain to build with:

```bash
cargo build --release
```

### Generate signing keypair

ActivityPub messages are signed using RSA keys. Generate a keypair
first:

```bash
openssl genrsa -out private-key.pem 4096
openssl rsa -in private-key.pem -pubout -out public-key.pem
```

Let your `config.yaml` point there.

### Database

Create a PostgreSQL database and user, set them in your `config.yaml`.

The program will create its schema on start.

## Ethics

*Should everyone connect to the streaming API of the big popular
Mastodon instances?*

Once these connections become a problem, they may become disallowed,
resulting in problems for everyone. That's why **fedi.buzz** serves
the firehose feed through the streaming API, too.

You can let this service use **fedi.buzz** as listed in the default
`config.yaml`.

## CloudBSD fork

This is [cloudbsdorg/buzzrelay](https://github.com/cloudbsdorg/buzzrelay),
the relay behind [relay.cloudbsd.ai](https://relay.cloudbsd.ai/). It is
[astro/buzzrelay](https://github.com/astro/buzzrelay) plus relay management.
It stays under the AGPL-3.0 (see `LICENSE`): the relay's page links to
this repository, the source of exactly what it runs.

What changed:

- **FreeBSD builds without libsystemd.** The `systemd` crate is a Linux-only
  dependency behind the default `systemd` feature; elsewhere the readiness
  and watchdog notifications are no-ops. On Linux without libsystemd,
  build with `--no-default-features`.
- **Follows are unique per follower and relay actor**, not per inbox:
  followers on one instance share a sharedInbox, and the old
  `(inbox, actor)` key refused the second of them. A re-follow updates the
  inbox.
- **Versioned migrations** (`schema_migrations`). They run on start, inside
  one transaction under an advisory lock, and are idempotent.
- **Blocked domains.** A Follow from a blocked domain (actor or inbox host,
  subdomains included) is answered with a signed `Reject`; blocking a domain
  deletes its follows; deliveries to it are skipped.
- **Blocked sources.** Firehose posts are dropped by host (`example.com`,
  subdomains included) or by account (`user@example.com`).
- **Runtime streams.** The `streams` table decides which streaming APIs are
  read. It is seeded once from `streams` in the config; a supervisor
  reconciles running streams with it every 30 s and on every admin change.
- **Pause.** Stops relaying posts; follows are still accepted.
- **Removing a subscriber** deletes its follows and sends each a signed
  `Reject{Follow}` (carrying the Follow's id, recorded for new follows).
- **Actor cache TTL.** Remote actors are cached for an hour, failed lookups
  for a minute (they used to be cached until evicted).
- **`/metrics` moved** from the public listener to the admin listener.
  Point Prometheus at `http://127.0.0.1:<admin_listen_port>/metrics` with
  the bearer (`authorization: {credentials_file: ...}`); with
  `admin_listen_port` unset, `/metrics` is not served at all.

### Configuration keys

| Key | Meaning |
| --- | --- |
| `streams` | Initial stream list, used once to seed the `streams` table. |
| `admin_listen_port` | Port of the admin API, bound to 127.0.0.1 only. Unset: no admin API and no `/metrics`. |
| `admin_token_file` | File holding the admin bearer token: one word of at least 32 characters. A regular file, not a symlink, mode `0600` or `0640` (no other bits). Required with `admin_listen_port`; buzzrelay refuses to start if it is unusable. |

Making the token and a first request (FreeBSD, service user `buzzrelay`):

```sh
( umask 077; openssl rand -hex 32 > /usr/local/etc/cloudbsd/buzzrelay/admin.token )
chown root:buzzrelay /usr/local/etc/cloudbsd/buzzrelay/admin.token
chmod 640 /usr/local/etc/cloudbsd/buzzrelay/admin.token
# the header goes in a file so the token is never on a command line
printf 'Authorization: Bearer %s\n' "$(cat /usr/local/etc/cloudbsd/buzzrelay/admin.token)" > /root/relay-admin.hdr
curl -H @/root/relay-admin.hdr http://127.0.0.1:3001/admin/health
curl -H @/root/relay-admin.hdr -H 'content-type: application/json' \
  -X DELETE -d '{"domain": "example.com"}' http://127.0.0.1:3001/admin/blocks/domains
```

### Admin API

Every request needs `Authorization: Bearer <token>`; without it the answer
is `401`. Bodies are JSON. Mutations are idempotent: a repeated PUT updates,
a DELETE of something absent answers `{"deleted": false}`. Errors are
`{"error": "..."}` with `400` (bad input) or `500`. DELETE takes its JSON
body too (`-H 'content-type: application/json' -d ...`). Stream URLs must be
https and are shown with credentials (`access_token=...`) replaced by
`REDACTED`.

In `/admin/stats`, `followers.follows` counts follow rows, `followers.followers`
distinct follower actors, `followers.inboxes` distinct inboxes. A post counts
as relayed when it was queued for at least one inbox. Stream `state` is
`connecting`, `connected` or `retrying`; `since` is the Unix time of the last
state change; `posts` and `connects` count since the stream task started.
Blocking a domain deletes its follows without sending Rejects (no traffic goes
to a blocked domain); removing a subscriber sends one per follow.

| Method and path | Body / query | Answer |
| --- | --- | --- |
| `GET /admin/health` | | `{status, version, paused, database, streams_enabled, streams_running, streams_connected}`; `status` is `ok` or `degraded`, `503` when the database is unreachable |
| `GET /admin/stats` | | followers (totals, by actor, by domain), counters (posts relayed or skipped, deliveries enqueued, skipped, dropped, ok, failed, follows accepted and rejected), hosts with a queue or backoff, streams |
| `GET /admin/subscribers` | `?actor=<relay actor URI>&domain=<domain>` (domain matches the follower's actor host or inbox host, subdomains included: the same rule as a domain block) | `[{id, inbox, actor, domain}]`: follower actor id, its inbox, the relay actor followed, the follower's actor host |
| `DELETE /admin/subscribers` | `{"id": "<follower actor id>", "actor": "<relay actor URI, optional>"}` | `{removed, rejects_sent}` |
| `GET /admin/blocks/domains` | | `[{domain, reason, created_at}]` |
| `PUT /admin/blocks/domains` | `{"domain": "example.com", "reason": "..."}` | `{domain, created, removed_follows}` |
| `DELETE /admin/blocks/domains` | `{"domain": "example.com"}` | `{deleted}` |
| `GET /admin/blocks/sources` | | `[{pattern, reason, created_at}]` |
| `PUT /admin/blocks/sources` | `{"pattern": "example.com" or "user@example.com", "reason": "..."}` | `{pattern, created}` |
| `DELETE /admin/blocks/sources` | `{"pattern": "..."}` | `{deleted}` |
| `GET /admin/streams` | | `[{id, url, enabled, created_at, state, since, posts, connects, last_error}]` |
| `PUT /admin/streams` | `{"url": "https://.../api/v1/streaming/public", "enabled": true}` | `{id, url, enabled, created}` |
| `DELETE /admin/streams` | `{"id": "<from GET>"}` or `{"url": "<full URL>"}` | `{deleted}` |
| `POST /admin/pause` | | `{"paused": true}` |
| `POST /admin/resume` | | `{"paused": false}` |
| `GET /admin/actors` | | follower counts per relay actor: `[{actor, followers, inboxes}]` |
| `GET /metrics` | | Prometheus text |

### Tests

`cargo test` runs the unit tests. The PostgreSQL tests are `#[ignore]`d;
run them against a scratch database (each test makes its own schema):

```bash
BUZZRELAY_TEST_DB="host=127.0.0.1 port=55432 user=postgres dbname=buzzrelay_test" \
  cargo test -- --include-ignored
```
