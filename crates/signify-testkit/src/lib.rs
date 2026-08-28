//! Test-only doubles for a KERIA agent.
//!
//! Nineteen test files in `signify-client` each carried their own copy of the same scripted agent —
//! roughly two thousand lines, byte-identical in the parts that mattered and quietly divergent in
//! the parts that did not. This crate is that harness, once. `ARCHITECTURE.md` §11 provides for a
//! small test-support package "only after duplication is real"; at nineteen copies it is.
//!
//! # Why this exists rather than [`signify_http::transport::ScriptedTransport`]
//!
//! [`signify_http::transport::ScriptedTransport`] pre-scripts complete responses, which is enough
//! whenever the answer does not depend on the question. A connected client authenticates the
//! agent's response signature, and that signature covers the request's method and path — so the
//! answer has to be *computed per request*. [`AgentTransport`] closes exactly that gap and nothing
//! else. Where response authentication is not what a test is about,
//! `ConnectedClient::with_freshness(Freshness::Ignore)` and a plain `ScriptedTransport` remain the
//! lighter choice.
//!
//! # What this crate must never become
//!
//! It holds no protocol logic. Everything here is a fixture, a constant, or plumbing; anything that
//! decides what a correct KERI artifact looks like belongs in the crate under test, where it is
//! subject to the real gates. `ARCHITECTURE.md` §11 says the same in one line: a test-support
//! package "may not contain production protocol logic".

use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use signify_crypto::signer::Signer;
use signify_crypto::verifier::KeyTransferability;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::retry::{Clock, TestClock};
use signify_http::signature::authentication::RequestSigner;
use signify_http::signature::input::{RequestTarget, default_components};
use signify_http::signature::timestamp::SignifyTimestamp;
use signify_http::transport::{Method, Request, Response, StatusCode, Transport, TransportError, TransportFuture};

/// Administrative URL every scripted client is configured against.
pub const ADMIN: &str = "http://127.0.0.1:3901";

/// Boot URL every scripted client is configured against.
pub const BOOT: &str = "http://127.0.0.1:3903";

/// The twenty-one character passcode the pinned reference's own tests use.
///
/// `PUBLIC TEST MATERIAL`: this is the reference's published test passcode, not a secret.
pub const PASSCODE: &str = "0123456789abcdefghijk";

/// Prefix of the agent every scripted answer claims to come from.
pub const AGENT: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";

/// The instant every scripted answer is stamped with, in milliseconds since the Unix epoch.
pub const FIXED_MILLIS: u64 = 1_700_000_000_123;

/// How many requests connecting a client makes before any endpoint call.
///
/// `ConnectedClient::connect` reads the agent's state and then approves its delegation, so the
/// first two recorded requests are never the ones a test is asking about.
/// [`AgentTransport::endpoint_requests`] skips exactly these — and checks that it skipped the right
/// ones, so this constant cannot silently drift out of step with the client.
pub const LIFECYCLE_REQUESTS: usize = 2;

/// The agent's signing seed, so a scripted answer verifies as that agent's.
///
/// This is the seed Roadmap 6.4's fixture pinned and the one every `tools/reference-vectors`
/// generator signs its recorded answers with, so a Rust test and the generator that produced its
/// fixture agree about who the agent is. `PUBLIC TEST MATERIAL`.
const AGENT_SEED: [u8; 32] = [
    187, 140, 234, 145, 219, 254, 20, 194, 16, 18, 97, 194, 140, 192, 61, 145, 222, 110, 59, 160, 152, 2, 72, 122, 87,
    143, 109, 39, 98, 153, 192, 148,
];

/// Status a scripted answer carries unless a test asks for another.
const DEFAULT_STATUS: u16 = 202;

/// One request as it left the client, in the shape a test wants to read it.
///
/// The nineteen copies this crate replaces returned seven different tuples between them — a path
/// and a method here, a path and a body there, a fourth element bolted on somewhere else. A view
/// with named accessors lets each caller read the two or three things it cares about, and lets a
/// later caller want a fourth without disturbing anyone.
#[derive(Clone, Debug)]
pub struct Recorded {
    request: Request,
}

impl Recorded {
    /// Returns the resource the request addressed: its path, and its query when it had one.
    ///
    /// The query is part of the address, and a test that asserts on `/challenges` when the client
    /// sent `/challenges?strength=128` is asserting about a request that was never made. The
    /// nineteen copies this crate replaces got this right by stripping the base URL from the whole
    /// address; dropping the query here reintroduced the bug, and their assertions caught it.
    #[must_use]
    pub fn resource(&self) -> String {
        let url = self.request.url();
        match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        }
    }

    /// Returns the path the request was sent to, without the host or the query.
    #[must_use]
    pub fn path(&self) -> &str {
        self.request.url().path()
    }

    /// Returns the request's method.
    #[must_use]
    pub fn method(&self) -> &'static str {
        self.request.method().as_str()
    }

    /// Returns the request's body as text, when it carried one that is UTF-8.
    #[must_use]
    pub fn body_text(&self) -> Option<String> {
        self.request
            .body()
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .map(ToOwned::to_owned)
    }

    /// Returns the request's body bytes, when it carried one.
    #[must_use]
    pub fn body(&self) -> Option<&[u8]> {
        self.request.body()
    }

    /// Returns one request header's value, when it was sent.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.request.headers().get(name)
    }

    /// Returns the underlying request, for the rare test that needs more than the accessors give.
    #[must_use]
    pub const fn request(&self) -> &Request {
        &self.request
    }
}

/// A scripted KERIA agent that signs its answers.
///
/// Answers are consumed in the order they were supplied; once they run out every further request
/// is answered `{}`, or — under [`Self::repeating_last`] — with the last answer again, which is
/// what a test that polls an operation until it completes needs.
#[derive(Debug)]
pub struct AgentTransport {
    answers: Mutex<Vec<Vec<u8>>>,
    recorded: Mutex<Vec<Request>>,
    status: Mutex<u16>,
    content_range: Mutex<Option<String>>,
    repeat_last: Mutex<bool>,
}

impl AgentTransport {
    /// Builds a transport that answers with `answers`, in order.
    #[must_use]
    pub fn new(answers: &[&[u8]]) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.iter().rev().map(|body| body.to_vec()).collect()),
            recorded: Mutex::new(Vec::new()),
            status: Mutex::new(DEFAULT_STATUS),
            content_range: Mutex::new(None),
            repeat_last: Mutex::new(false),
        })
    }

    /// Adds a `Content-Range` header to every answer.
    ///
    /// A listing endpoint reports its window in that header, and a test about paging needs to say
    /// what the agent claimed.
    pub fn with_content_range(&self, range: &str) {
        if let Ok(mut guard) = self.content_range.lock() {
            *guard = Some(range.to_owned());
        }
    }

    /// Answers everything from here on with `status`.
    ///
    /// Use it to observe what a client does when the agent refuses — that a rotation is not
    /// adopted, that nothing is left half-applied.
    pub fn with_status(&self, status: u16) {
        if let Ok(mut guard) = self.status.lock() {
            *guard = status;
        }
    }

    /// Answers everything from here on with `400`.
    ///
    /// The common case of [`Self::with_status`], named for what a test is actually saying.
    pub fn refuse(&self) {
        self.with_status(400);
    }

    /// Keeps answering with the final scripted answer instead of consuming it.
    ///
    /// A caller that polls an operation until it finishes makes an unknown number of requests, so
    /// its last answer has to survive being read. Without this an exhausted script answers `{}`,
    /// which the caller reads as a malformed operation rather than as one still running.
    pub fn repeating_last(&self) {
        if let Ok(mut guard) = self.repeat_last.lock() {
            *guard = true;
        }
    }

    /// Returns every request the client made, in order.
    #[must_use]
    pub fn requests(&self) -> Vec<Recorded> {
        self.recorded.lock().map_or_else(
            |_| Vec::new(),
            |guard| guard.iter().cloned().map(|request| Recorded { request }).collect(),
        )
    }

    /// Returns the requests made after connecting, in order.
    ///
    /// # Errors
    ///
    /// Returns an error when the leading requests are not the two `ConnectedClient::connect` makes
    /// against `/agent/`. Every copy this crate replaces skipped a hardcoded two without checking;
    /// had `connect` ever grown a third request, all nineteen would have gone on asserting about
    /// the wrong one.
    pub fn endpoint_requests(&self) -> Result<Vec<Recorded>, Box<dyn Error>> {
        let all = self.requests();
        let lifecycle = all.get(..LIFECYCLE_REQUESTS).ok_or_else(|| {
            format!(
                "expected at least {LIFECYCLE_REQUESTS} requests for the connection, and {} were made",
                all.len()
            )
        })?;
        for request in lifecycle {
            if !request.path().starts_with("/agent/") {
                return Err(format!(
                    "the connection's first {LIFECYCLE_REQUESTS} requests should address /agent/, and one addressed {}",
                    request.path()
                )
                .into());
            }
        }
        Ok(all.into_iter().skip(LIFECYCLE_REQUESTS).collect())
    }

    /// Returns the method and path of each request made after connecting, in order.
    ///
    /// The shape a test asserting on a *sequence* of calls wants — that a poller asked about the
    /// operation and then deleted it, in that order — without unpacking a whole request each time.
    #[must_use]
    pub fn endpoint_calls(&self) -> Vec<(String, String)> {
        self.requests()
            .into_iter()
            .skip(LIFECYCLE_REQUESTS)
            .map(|request| (request.method().to_owned(), request.resource()))
            .collect()
    }

    /// Answers one request, signing the answer as the agent.
    fn answer(&self, request: &Request) -> Result<Response, TransportError> {
        let repeat = self.repeat_last.lock().is_ok_and(|guard| *guard);
        let body = {
            let mut queue = self
                .answers
                .lock()
                .map_err(|_| TransportError::signing("the scripted answers are poisoned"))?;
            if repeat && queue.len() == 1 {
                queue.last().cloned()
            } else {
                queue.pop()
            }
        }
        .unwrap_or_else(|| b"{}".to_vec());

        let status = self.status.lock().map_or(DEFAULT_STATUS, |guard| *guard);
        let range = self.content_range.lock().ok().and_then(|guard| guard.clone());
        signed_response(request.method(), request.url().path(), body, status, range.as_deref())
            .map_err(|error| TransportError::signing(error.to_string()))
    }
}

impl Transport for AgentTransport {
    fn execute(&self, request: Request) -> TransportFuture<'_> {
        let answer = {
            if let Ok(mut guard) = self.recorded.lock() {
                guard.push(request.clone());
            }
            self.answer(&request)
        };
        let future: Pin<Box<dyn Future<Output = Result<Response, TransportError>> + Send + '_>> =
            Box::pin(async move { answer });
        future
    }
}

/// Returns the agent's signer.
///
/// # Errors
///
/// Returns an error when the pinned seed does not derive a signer, which would mean the crypto
/// layer had changed underneath this crate.
pub fn agent_signer() -> Result<Signer, Box<dyn Error>> {
    Ok(Signer::from_seed(&AGENT_SEED, KeyTransferability::NonTransferable)?)
}

/// Returns the agent's verification key, or the empty string if it cannot be derived.
#[must_use]
pub fn agent_verification_key() -> String {
    agent_signer()
        .and_then(|signer| Ok(signer.verifier().qb64()?))
        .unwrap_or_default()
}

/// Returns the state document an agent reports for `controller`, whose inception is `inception`.
#[must_use]
pub fn agent_state(controller: &str, inception: &str) -> String {
    let agent = format!(
        r#"{{"vn":[1,0],"i":"{AGENT}","s":"0","p":"","d":"{AGENT}","f":"0","dt":"2023-12-01T10:05:25.062609+00:00","et":"dip","kt":"1","k":["{key}"],"nt":"1","n":["EL6zVoZ0F8OXcbXP4LOm5oJTxCXP6ZLp5o3vNfvVZ9YB"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{AGENT}","br":[],"ba":[]}},"di":"{controller}"}}"#,
        key = agent_verification_key()
    );
    format!(r#"{{"agent":{agent},"controller":{{"state":{agent},"ee":{inception}}},"ridx":0,"pidx":0}}"#)
}

/// Builds one answer, signed as the agent over `method` and `path`.
///
/// # Errors
///
/// Returns an error when the headers, the signature, or the status cannot be built.
pub fn signed_response(
    method: Method,
    path: &str,
    body: Vec<u8>,
    status: u16,
    content_range: Option<&str>,
) -> Result<Response, Box<dyn Error>> {
    let stamp = SignifyTimestamp::from_unix(Duration::from_millis(FIXED_MILLIS))?;
    let mut headers = Headers::new();
    headers.insert(HeaderName::new("signify-resource")?, HeaderValue::new(AGENT)?)?;
    headers.insert(HeaderName::new("signify-timestamp")?, stamp.to_header_value()?)?;
    if let Some(range) = content_range {
        headers.insert(HeaderName::new("content-range")?, HeaderValue::new(range)?)?;
    }
    let signer = RequestSigner::new(agent_signer()?);
    let input = signer.signature_input(default_components()?, stamp.created())?;
    let target = RequestTarget::new(method.as_str(), path)?;
    signer.sign(&input, &target, &headers)?.apply(&mut headers)?;
    Ok(Response::new(StatusCode::new(status)?, headers, body)?)
}

/// Returns a clock pinned to [`FIXED_MILLIS`], so every stamp a test produces is reproducible.
#[must_use]
pub fn clock() -> Arc<dyn Clock> {
    Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(FIXED_MILLIS),
    ))
}

/// Drives `future` to completion on the current thread.
///
/// The client's futures never yield to a reactor — every await in a test resolves against this
/// crate's own transport — so a full runtime would be machinery with nothing to do.
pub fn block_on<F: Future>(future: F) -> F::Output {
    use core::task::{Context, Poll, Waker};
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
    }
}
