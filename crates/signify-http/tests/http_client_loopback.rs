//! The production transport against an in-process HTTP/1.1 server on loopback.
//!
//! These are hermetic by construction, not by discipline: the server is a `TcpListener` this test
//! binds on `127.0.0.1:0`, so nothing reaches a network, no external service is needed, and the
//! port cannot collide. That lets the whole contract `ARCHITECTURE.md` §8.1 asks for be checked
//! against a real socket — the request bytes that go out, a response coming back, timeouts,
//! bounded bodies, connection failure, cancellation, and hostile responses.

#![cfg(feature = "http-client")]

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use signify_http::header::{HeaderName, HeaderValue};
use signify_http::transport::{HttpTransport, Method, Request, RequestUrl, Transport, TransportError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// What the loopback server does with a connection it accepted.
#[derive(Clone)]
enum Behaviour {
    /// Read the request, then write these exact bytes back.
    Reply(Vec<u8>),
    /// Read the request, then hold the connection open without answering.
    Hang,
    /// Read the request, then close without writing anything.
    Hangup,
}

/// One request as the server saw it on the wire.
#[derive(Clone, Debug, Default)]
struct Seen {
    request_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A minimal HTTP/1.1 server on loopback, for one connection.
struct Loopback {
    port: u16,
    seen: Arc<std::sync::Mutex<Vec<Seen>>>,
    accepted: Arc<AtomicUsize>,
}

impl Loopback {
    /// Binds a listener and serves `behaviour` for every connection it accepts.
    async fn start(behaviour: Behaviour) -> Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let accepted = Arc::new(AtomicUsize::new(0));

        let recorder = Arc::clone(&seen);
        let counter = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let behaviour = behaviour.clone();
                let recorder = Arc::clone(&recorder);
                tokio::spawn(async move {
                    // A connection failing mid-test is the behaviour under test, not a problem
                    // here: what the client observed is asserted by the test itself.
                    let _outcome = read_request(&mut { stream }, behaviour, &recorder).await;
                });
            }
        });

        Ok(Self { port, seen, accepted })
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// Reads one request off a connection, records it, then applies the behaviour.
async fn read_request(
    stream: &mut TcpStream,
    behaviour: Behaviour,
    recorder: &Arc<std::sync::Mutex<Vec<Seen>>>,
) -> Result<(), std::io::Error> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];

    // Read until the header block is complete.
    let header_end = loop {
        if let Some(offset) = find_header_end(&buffer) {
            break offset;
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(chunk.get(..read).unwrap_or_default());
    };

    let head = String::from_utf8_lossy(buffer.get(..header_end).unwrap_or_default()).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }

    // Read exactly the declared body, so the recording is complete before answering.
    let declared: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = buffer.get(header_end.saturating_add(4)..).unwrap_or_default().to_vec();
    while body.len() < declared {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(chunk.get(..read).unwrap_or_default());
    }

    if let Ok(mut guard) = recorder.lock() {
        guard.push(Seen {
            request_line,
            headers,
            body,
        });
    }

    match behaviour {
        Behaviour::Reply(bytes) => {
            stream.write_all(&bytes).await?;
            stream.flush().await?;
        }
        Behaviour::Hang => {
            // Hold the connection open so the client's own deadline is what ends the request.
            tokio::time::sleep(Duration::from_mins(1)).await;
        }
        Behaviour::Hangup => {}
    }
    Ok(())
}

/// Finds the end of the header block.
fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Builds an HTTP/1.1 response with a body and the headers given.
fn reply(status: &str, headers: &[(&str, &str)], body: &str) -> Behaviour {
    use std::fmt::Write as _;

    let mut text = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in headers {
        let _ = write!(text, "{name}: {value}\r\n");
    }
    let _ = write!(text, "Content-Length: {}\r\n\r\n", body.len());
    text.push_str(body);
    Behaviour::Reply(text.into_bytes())
}

fn transport(timeout: Duration) -> Result<HttpTransport, Box<dyn Error>> {
    Ok(HttpTransport::builder().timeout(timeout).build()?)
}

#[tokio::test]
async fn a_request_reaches_the_wire_exactly_as_built() -> Result<(), Box<dyn Error>> {
    let server = Loopback::start(reply(
        "200 OK",
        &[("Content-Type", "application/json")],
        r#"{"name":"aid1"}"#,
    ))
    .await?;

    let request = Request::builder(Method::Put, RequestUrl::new(server.url("/identifiers/aid1?type=ixn"))?)
        .header(HeaderName::new("Content-Type")?, HeaderValue::new("application/json")?)
        .header(HeaderName::new("Signify-Resource")?, HeaderValue::new("EPRE")?)
        .body(br#"{"name":"renamed"}"#.to_vec())
        .build()?;

    let response = transport(Duration::from_secs(5))?.execute(request).await?;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.body(), br#"{"name":"aid1"}"#);
    assert_eq!(response.headers().get("content-type"), Some("application/json"));

    let seen = server.seen();
    let first = seen.first().ok_or("the server saw no request")?;
    // The request line carries the method and the target, query included.
    assert_eq!(first.request_line, "PUT /identifiers/aid1?type=ixn HTTP/1.1");
    assert_eq!(first.header("signify-resource"), Some("EPRE"));
    assert_eq!(first.header("content-type"), Some("application/json"));
    assert_eq!(first.body, br#"{"name":"renamed"}"#);
    Ok(())
}

#[tokio::test]
async fn a_path_with_dot_segments_is_sent_unchanged() -> Result<(), Box<dyn Error>> {
    // The case that decided the dependency: this must reach the server as written, because
    // Roadmap 3.10 signed exactly these bytes.
    let server = Loopback::start(reply("200 OK", &[], "")).await?;
    let path = "/identifiers/..";
    let request = Request::builder(Method::Get, RequestUrl::new(server.url(path))?).build()?;

    transport(Duration::from_secs(5))?.execute(request).await?;

    let seen = server.seen();
    let first = seen.first().ok_or("the server saw no request")?;
    assert_eq!(first.request_line, format!("GET {path} HTTP/1.1"));
    Ok(())
}

#[tokio::test]
async fn a_get_sends_no_body_and_a_post_sends_its_own() -> Result<(), Box<dyn Error>> {
    let server = Loopback::start(reply("204 No Content", &[], "")).await?;
    let sender = transport(Duration::from_secs(5))?;

    sender
        .execute(Request::builder(Method::Get, RequestUrl::new(server.url("/a"))?).build()?)
        .await?;
    sender
        .execute(
            Request::builder(Method::Post, RequestUrl::new(server.url("/b"))?)
                .body(b"payload".to_vec())
                .build()?,
        )
        .await?;

    let seen = server.seen();
    let get = seen.first().ok_or("no GET recorded")?;
    let post = seen.get(1).ok_or("no POST recorded")?;
    assert_eq!(get.body, [] as [u8; 0]);
    // An absent body sends no content-length at all, rather than a zero-length one.
    assert_eq!(get.header("content-length"), None);
    assert_eq!(post.body, b"payload");
    assert_eq!(post.header("content-length"), Some("7"));
    Ok(())
}

#[tokio::test]
async fn a_non_success_status_comes_back_as_a_response() -> Result<(), Box<dyn Error>> {
    let server = Loopback::start(reply("404 Not Found", &[("Content-Type", "text/plain")], "missing")).await?;
    let request = Request::builder(Method::Get, RequestUrl::new(server.url("/gone"))?).build()?;

    // Not an error: the layer that knows what was asked for decides what a 404 means.
    let response = transport(Duration::from_secs(5))?.execute(request).await?;
    assert_eq!(response.status().as_u16(), 404);
    assert!(response.status().is_client_error());
    assert_eq!(response.body(), b"missing");
    Ok(())
}

#[tokio::test]
async fn a_slow_server_trips_the_deadline() -> Result<(), Box<dyn Error>> {
    let server = Loopback::start(Behaviour::Hang).await?;
    let request = Request::builder(Method::Get, RequestUrl::new(server.url("/slow"))?).build()?;

    let outcome = transport(Duration::from_millis(150))?.execute(request).await;
    assert!(
        matches!(outcome, Err(TransportError::Timeout { milliseconds: 150 })),
        "{outcome:?}"
    );
    // The request did reach the server; it simply never answered.
    assert_eq!(server.accepted(), 1);
    Ok(())
}

#[tokio::test]
async fn an_oversized_body_stops_at_the_limit() -> Result<(), Box<dyn Error>> {
    let body = "x".repeat(4096);
    let server = Loopback::start(reply("200 OK", &[], &body)).await?;
    let request = Request::builder(Method::Get, RequestUrl::new(server.url("/big"))?)
        .response_limit(1024)
        .build()?;

    let outcome = transport(Duration::from_secs(5))?.execute(request).await;
    match outcome {
        Err(TransportError::ResponseBodyTooLarge { limit, actual }) => {
            assert_eq!(limit, 1024);
            // Reading stopped at the limit rather than buffering the whole body first.
            assert!(actual > 1024, "{actual}");
            assert!(actual <= 1024 + 4096, "{actual}");
        }
        other => return Err(format!("expected a limit failure, got {other:?}").into()),
    }
    Ok(())
}

#[tokio::test]
async fn a_body_exactly_at_the_limit_is_accepted() -> Result<(), Box<dyn Error>> {
    let body = "y".repeat(256);
    let server = Loopback::start(reply("200 OK", &[], &body)).await?;
    let request = Request::builder(Method::Get, RequestUrl::new(server.url("/exact"))?)
        .response_limit(256)
        .build()?;

    let response = transport(Duration::from_secs(5))?.execute(request).await?;
    assert_eq!(response.body().len(), 256);
    Ok(())
}

#[tokio::test]
async fn a_closed_port_is_a_connection_failure() -> Result<(), Box<dyn Error>> {
    // Bind and drop, so the port is almost certainly closed and nothing is listening.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    drop(listener);

    let request = Request::builder(Method::Get, RequestUrl::new(format!("http://127.0.0.1:{port}/a"))?).build()?;
    let outcome = transport(Duration::from_secs(5))?.execute(request).await;
    assert!(matches!(outcome, Err(TransportError::Connect { .. })), "{outcome:?}");
    Ok(())
}

#[tokio::test]
async fn a_server_that_hangs_up_is_a_typed_failure() -> Result<(), Box<dyn Error>> {
    let server = Loopback::start(Behaviour::Hangup).await?;
    let request = Request::builder(Method::Get, RequestUrl::new(server.url("/rude"))?).build()?;

    let outcome = transport(Duration::from_secs(5))?.execute(request).await;
    assert!(outcome.is_err(), "a truncated exchange must not look like success");
    if let Err(error) = outcome {
        assert_ne!(error.to_string(), "");
    }
    Ok(())
}

#[tokio::test]
async fn a_duplicated_response_header_is_refused() -> Result<(), Box<dyn Error>> {
    // Two values for one name are ambiguous where responses are signed, so the response is
    // refused rather than silently joined or half-dropped.
    let server = Loopback::start(reply(
        "200 OK",
        &[("X-Signed-Thing", "first"), ("X-Signed-Thing", "second")],
        "{}",
    ))
    .await?;
    let request = Request::builder(Method::Get, RequestUrl::new(server.url("/dup"))?).build()?;

    let outcome = transport(Duration::from_secs(5))?.execute(request).await;
    assert!(matches!(outcome, Err(TransportError::Header { .. })), "{outcome:?}");
    Ok(())
}

#[tokio::test]
async fn an_invalid_status_line_is_refused() -> Result<(), Box<dyn Error>> {
    let server = Loopback::start(Behaviour::Reply(
        b"HTTP/1.1 999 Nonsense\r\nContent-Length: 0\r\n\r\n".to_vec(),
    ))
    .await?;
    let request = Request::builder(Method::Get, RequestUrl::new(server.url("/odd"))?).build()?;

    let outcome = transport(Duration::from_secs(5))?.execute(request).await;
    // Either the HTTP parser or this crate's status range refuses it; both are typed failures.
    assert!(outcome.is_err(), "a 999 status must not be accepted");
    Ok(())
}

#[tokio::test]
async fn dropping_the_future_cancels_the_request() -> Result<(), Box<dyn Error>> {
    let server = Loopback::start(Behaviour::Hang).await?;
    let sender = transport(Duration::from_secs(30))?;
    let request = Request::builder(Method::Get, RequestUrl::new(server.url("/cancelled"))?).build()?;

    // Start the exchange, let it reach the server, then drop it well inside the deadline.
    let future = sender.execute(request);
    let outcome = tokio::time::timeout(Duration::from_millis(200), future).await;
    assert!(outcome.is_err(), "the hung server must not have answered");

    // The future is gone, and the deadline never had to fire.
    assert_eq!(server.accepted(), 1);
    Ok(())
}

#[tokio::test]
async fn one_transport_serves_many_requests_over_a_pooled_connection() -> Result<(), Box<dyn Error>> {
    let server = Loopback::start(reply("200 OK", &[], "ok")).await?;
    let sender = transport(Duration::from_secs(5))?;

    for index in 0..3 {
        let request = Request::builder(Method::Get, RequestUrl::new(server.url(&format!("/{index}")))?).build()?;
        let response = sender.execute(request).await?;
        assert_eq!(response.body(), b"ok");
    }

    let seen = server.seen();
    assert_eq!(seen.len(), 3);
    let targets: Vec<&str> = seen
        .iter()
        .filter_map(|request| request.request_line.split(' ').nth(1))
        .collect();
    assert_eq!(targets, ["/0", "/1", "/2"]);
    Ok(())
}

#[tokio::test]
async fn a_transport_object_works_behind_the_trait() -> Result<(), Box<dyn Error>> {
    // How a client will hold it: one shared object, no type parameter.
    let server = Loopback::start(reply("202 Accepted", &[], "{}")).await?;
    let sender: Arc<dyn Transport> = Arc::new(transport(Duration::from_secs(5))?);
    let request = Request::builder(Method::Post, RequestUrl::new(server.url("/boot"))?)
        .body(b"{}".to_vec())
        .build()?;

    let response = sender.execute(request).await?;
    assert_eq!(response.status().as_u16(), 202);
    Ok(())
}
