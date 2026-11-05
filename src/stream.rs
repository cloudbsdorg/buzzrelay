use std::{sync::Arc, time::Duration};
use futures::{Stream, StreamExt};
use eventsource_stream::Eventsource;
use tokio::{
    sync::mpsc::{channel, Receiver, Sender},
    time::sleep,
};
use crate::streams::{now, Spawner, StatusCell, StreamState, StreamStatus};

/// No `Debug`: a reqwest error's Debug carries the URL (and its token).
pub enum StreamError {
    Http(reqwest::Error),
    HttpStatus(reqwest::StatusCode),
    InvalidContentType,
}

async fn run(url: &str) -> Result<impl Stream<Item = String>, StreamError> {
    let client = reqwest::Client::new();
    let res = client.get(url)
        .timeout(Duration::MAX)
        .send()
        .await
        .map_err(StreamError::Http)?;
    if res.status() != 200 {
        return Err(StreamError::HttpStatus(res.status()));
    }
    let ct = res.headers().get("content-type")
        .and_then(|c| c.to_str().ok());
    if ct != Some("text/event-stream") {
        return Err(StreamError::InvalidContentType);
    }

    let src = res.bytes_stream()
        .eventsource()
        .filter_map(|result| async {
            let result = result.ok()?;
            if result.event == "update" {
                Some(result)
            } else {
                None
            }
        })
        .map(|event| event.data);
    Ok(src)
}

impl std::fmt::Display for StreamError {
    /// Never includes the URL: it may carry an access token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Http(e) => write!(f, "http error: {}", RedactedError(e)),
            StreamError::HttpStatus(status) => write!(f, "http status {}", status.as_u16()),
            StreamError::InvalidContentType => write!(f, "invalid content-type"),
        }
    }
}

struct RedactedError<'a>(&'a reqwest::Error);

impl std::fmt::Display for RedactedError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = if self.0.is_timeout() {
            "timeout"
        } else if self.0.is_connect() {
            "connect"
        } else if self.0.is_body() || self.0.is_decode() {
            "body"
        } else {
            "request"
        };
        // the source (DNS, TLS, refused) carries no URL
        match std::error::Error::source(self.0) {
            Some(source) => write!(f, "{kind}: {source}"),
            None => f.write_str(kind),
        }
    }
}

fn set_status(status: &StatusCell, f: impl FnOnce(&mut StreamStatus)) {
    let mut status = status.lock().unwrap();
    f(&mut status);
}

/// Follows one SSE stream forever, reconnecting after a second, and sends
/// every post to `tx`. Aborting the task stops it.
pub async fn follow(url: String, tx: Sender<String>, status: StatusCell) {
    let id = crate::streams::stream_id(&url);
    loop {
        set_status(&status, |s| { s.state = StreamState::Connecting; s.since = now(); });
        match run(&url).await {
            Ok(stream) => {
                tracing::info!("stream {id} connected");
                set_status(&status, |s| {
                    s.state = StreamState::Connected;
                    s.since = now();
                    s.connects += 1;
                    s.last_error = None;
                });
                stream.for_each(|post| async {
                    set_status(&status, |s| s.posts += 1);
                    tx.send(post).await.unwrap();
                }).await;
                set_status(&status, |s| s.last_error = Some("stream ended".to_string()));
            }
            Err(e) => {
                tracing::error!("stream {id}: {e}");
                set_status(&status, |s| s.last_error = Some(e.to_string()));
            }
        }
        set_status(&status, |s| { s.state = StreamState::Retrying; s.since = now(); });
        sleep(Duration::from_secs(1)).await;
    }
}

/// The channel all streams feed, and a spawner for the supervisor.
pub fn channel_and_spawner() -> (Spawner, Receiver<String>) {
    let (tx, rx) = channel(1024);
    let spawner: Spawner = Arc::new(move |url, status| {
        tokio::spawn(follow(url, tx.clone(), status))
    });
    (spawner, rx)
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn stream_errors_do_not_carry_the_url() {
        let e = reqwest::Client::new()
            .get("http://127.0.0.1:9/api/v1/streaming/public?access_token=s3cr3t")
            .send().await
            .unwrap_err();
        assert!(format!("{e}").contains("s3cr3t"), "precondition: reqwest's own Display has the URL");
        let shown = StreamError::Http(e).to_string();
        assert!(!shown.contains("s3cr3t") && !shown.contains("127.0.0.1"), "{shown}");
        assert!(shown.starts_with("http error: "), "{shown}");
    }
}
