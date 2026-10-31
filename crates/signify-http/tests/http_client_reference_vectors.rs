//! The reference's own recorded requests, replayed through the production transport onto a socket.
//!
//! The `http-transport` fixture proved that this crate's `Request` can *express* every call the
//! pinned reference makes. This proves the rest of the claim: that the production transport puts
//! those calls on the wire unchanged. Each recorded request is rebuilt, sent to an in-process
//! loopback server, and compared against what the reference sent — the same method and target on
//! the request line, the same header values, and the same body bytes.

#![cfg(feature = "http-client")]

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use signify_http::header::{HeaderName, HeaderValue};
use signify_http::transport::{HttpTransport, Method, Request, RequestUrl, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/http-transport/v1.json"));

#[derive(Debug, Deserialize)]
struct Fixture {
    reference_sha: String,
    requests: Vec<RequestCase>,
}

#[derive(Debug, Deserialize)]
struct RequestCase {
    name: String,
    request: RecordedRequest,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    url: String,
    method: String,
    headers: Vec<RecordedHeader>,
    body: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedHeader {
    name: String,
    value: Option<String>,
}

/// One request as the loopback server saw it.
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

/// Serves one `204 No Content` per connection and records what arrived.
async fn loopback() -> Result<(u16, Arc<std::sync::Mutex<Vec<Seen>>>), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let recorder = Arc::clone(&recorder);
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0_u8; 1024];
                let header_end = loop {
                    if let Some(offset) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                        break offset;
                    }
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => buffer.extend_from_slice(chunk.get(..read).unwrap_or_default()),
                    }
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
                let declared: usize = headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.parse().ok())
                    .unwrap_or(0);
                let mut body = buffer.get(header_end.saturating_add(4)..).unwrap_or_default().to_vec();
                while body.len() < declared {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => body.extend_from_slice(chunk.get(..read).unwrap_or_default()),
                    }
                }

                if let Ok(mut guard) = recorder.lock() {
                    guard.push(Seen {
                        request_line,
                        headers,
                        body,
                    });
                }
                let _outcome = stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });

    Ok((port, seen))
}

/// Rebuilds a recorded request against the loopback server, keeping its path and query.
fn rebuild(recorded: &RecordedRequest, port: u16) -> Result<Request, Box<dyn Error>> {
    let original = RequestUrl::new(recorded.url.clone())?;
    let target = match original.query() {
        Some(query) => format!("http://127.0.0.1:{port}{}?{query}", original.path()),
        None => format!("http://127.0.0.1:{port}{}", original.path()),
    };
    let method = Method::ALL
        .iter()
        .copied()
        .find(|method| method.as_str() == recorded.method)
        .ok_or_else(|| format!("unmodelled method {:?}", recorded.method))?;

    let mut builder = Request::builder(method, RequestUrl::new(target)?);
    for header in &recorded.headers {
        // A masked value is a clock read or a signature over one; its exact bytes are
        // keri-http-auth's evidence, and what matters here is that the header reaches the wire at
        // all.
        let value = header.value.clone().unwrap_or_else(|| "masked".to_owned());
        builder = builder.header(HeaderName::new(header.name.clone())?, HeaderValue::new(value)?);
    }
    if let Some(body) = &recorded.body {
        builder = builder.body(body.clone().into_bytes());
    }
    Ok(builder.build()?)
}

#[tokio::test]
async fn every_recorded_request_reaches_the_wire_unchanged() -> Result<(), Box<dyn Error>> {
    let fixture: Fixture = serde_json::from_str(FIXTURE)?;
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert_eq!(fixture.requests.len(), 8);

    let (port, seen) = loopback().await?;
    let transport = HttpTransport::builder().timeout(Duration::from_secs(5)).build()?;

    for case in &fixture.requests {
        let request = rebuild(&case.request, port)?;
        let response = transport.execute(request).await?;
        assert_eq!(response.status().as_u16(), 204, "{}", case.name);
    }

    let observed = seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    assert_eq!(observed.len(), fixture.requests.len());

    for (case, sent) in fixture.requests.iter().zip(&observed) {
        let original = RequestUrl::new(case.request.url.clone())?;
        let expected_target = match original.query() {
            Some(query) => format!("{}?{query}", original.path()),
            None => original.path().to_owned(),
        };

        // The request line carries the reference's own method and target, byte for byte.
        assert_eq!(
            sent.request_line,
            format!("{} {expected_target} HTTP/1.1", case.request.method),
            "{}",
            case.name
        );

        // Every header the reference set arrives, and every unmasked value is unchanged.
        for header in &case.request.headers {
            let arrived = sent.header(&header.name);
            assert!(
                arrived.is_some(),
                "{}: {} did not reach the wire",
                case.name,
                header.name
            );
            if let Some(value) = &header.value {
                assert_eq!(arrived, Some(value.as_str()), "{}: {}", case.name, header.name);
            }
        }

        // The body arrives exactly, and an absent one stays absent.
        if let Some(body) = &case.request.body {
            assert_eq!(sent.body, body.as_bytes(), "{}", case.name);
            assert_eq!(
                sent.header("content-length")
                    .and_then(|value| value.parse::<usize>().ok()),
                Some(body.len()),
                "{}",
                case.name
            );
        } else {
            assert!(sent.body.is_empty(), "{}", case.name);
            assert_eq!(sent.header("content-length"), None, "{}", case.name);
        }
    }
    Ok(())
}

#[tokio::test]
async fn the_percent_encoded_path_survives_the_round_trip() -> Result<(), Box<dyn Error>> {
    // The reference's own `a name with ñ!` identifier, whose path is percent-encoded UTF-8 that
    // must reach the server without being decoded or re-encoded.
    let fixture: Fixture = serde_json::from_str(FIXTURE)?;
    let case = fixture
        .requests
        .iter()
        .find(|case| case.name == "identifier_update")
        .ok_or("the fixture records no identifier update")?;

    let (port, seen) = loopback().await?;
    let transport = HttpTransport::builder().timeout(Duration::from_secs(5)).build()?;
    transport.execute(rebuild(&case.request, port)?).await?;

    let observed = seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    let sent = observed.first().ok_or("nothing reached the server")?;
    assert_eq!(sent.request_line, "PUT /identifiers/a%20name%20with%20%C3%B1! HTTP/1.1");
    Ok(())
}
