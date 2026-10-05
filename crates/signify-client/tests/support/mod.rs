//! Test-only doubles for a KERIA agent.
//!
//! A scripted KERIA agent signing its answers per request, a pinned clock, and a minimal executor.

#![allow(
    dead_code,
    reason = "compiled once per test binary; not every binary uses every helper"
)]

use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::retry::{Clock, TestClock};
use signify_http::signature::authentication::RequestSigner;
use signify_http::signature::input::{RequestTarget, default_components};
use signify_http::signature::timestamp::SignifyTimestamp;
use signify_http::transport::{Method, Request, Response, StatusCode, Transport, TransportError, TransportFuture};

pub(crate) const ADMIN: &str = "http://127.0.0.1:3901";

pub(crate) const BOOT: &str = "http://127.0.0.1:3903";

/// The pinned reference's own test passcode. PUBLIC TEST MATERIAL, not a secret.
pub(crate) const PASSCODE: &str = "0123456789abcdefghijk";

pub(crate) const AGENT: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";

pub(crate) const FIXED_MILLIS: u64 = 1_700_000_000_123;

/// Requests `connect` makes before any endpoint call; `endpoint_requests` skips exactly these.
pub(crate) const LIFECYCLE_REQUESTS: usize = 2;

/// The agent's signing seed, so a scripted answer verifies as that agent's. PUBLIC TEST MATERIAL.
const AGENT_SEED: [u8; 32] = [
    187, 140, 234, 145, 219, 254, 20, 194, 16, 18, 97, 194, 140, 192, 61, 145, 222, 110, 59, 160, 152, 2, 72, 122, 87,
    143, 109, 39, 98, 153, 192, 148,
];

const DEFAULT_STATUS: u16 = 202;

#[derive(Clone, Debug)]
pub(crate) struct Recorded {
    request: Request,
}

impl Recorded {
    #[must_use]
    pub(crate) fn resource(&self) -> String {
        let url = self.request.url();
        match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        }
    }

    #[must_use]
    pub(crate) fn path(&self) -> &str {
        self.request.url().path()
    }

    #[must_use]
    pub(crate) fn method(&self) -> &'static str {
        self.request.method().as_str()
    }

    #[must_use]
    pub(crate) fn body_text(&self) -> Option<String> {
        self.request
            .body()
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .map(ToOwned::to_owned)
    }

    #[must_use]
    pub(crate) fn body(&self) -> Option<&[u8]> {
        self.request.body()
    }

    #[must_use]
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.request.headers().get(name)
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &Request {
        &self.request
    }
}

#[derive(Debug)]
pub(crate) struct AgentTransport {
    answers: Mutex<Vec<Vec<u8>>>,
    recorded: Mutex<Vec<Request>>,
    status: Mutex<u16>,
    content_range: Mutex<Option<String>>,
    repeat_last: Mutex<bool>,
}

impl AgentTransport {
    #[must_use]
    pub(crate) fn new(answers: &[&[u8]]) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.iter().rev().map(|body| body.to_vec()).collect()),
            recorded: Mutex::new(Vec::new()),
            status: Mutex::new(DEFAULT_STATUS),
            content_range: Mutex::new(None),
            repeat_last: Mutex::new(false),
        })
    }

    pub(crate) fn with_content_range(&self, range: &str) {
        if let Ok(mut guard) = self.content_range.lock() {
            *guard = Some(range.to_owned());
        }
    }

    pub(crate) fn with_status(&self, status: u16) {
        if let Ok(mut guard) = self.status.lock() {
            *guard = status;
        }
    }

    pub(crate) fn refuse(&self) {
        self.with_status(400);
    }

    pub(crate) fn repeating_last(&self) {
        if let Ok(mut guard) = self.repeat_last.lock() {
            *guard = true;
        }
    }

    #[must_use]
    pub(crate) fn requests(&self) -> Vec<Recorded> {
        self.recorded.lock().map_or_else(
            |_| Vec::new(),
            |guard| guard.iter().cloned().map(|request| Recorded { request }).collect(),
        )
    }

    pub(crate) fn endpoint_requests(&self) -> Result<Vec<Recorded>, Box<dyn Error>> {
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

    #[must_use]
    pub(crate) fn endpoint_calls(&self) -> Vec<(String, String)> {
        self.requests()
            .into_iter()
            .skip(LIFECYCLE_REQUESTS)
            .map(|request| (request.method().to_owned(), request.resource()))
            .collect()
    }

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

pub(crate) fn agent_signer() -> Result<Signer, Box<dyn Error>> {
    Ok(Signer::from_seed(&AGENT_SEED, KeyTransferability::NonTransferable)?)
}

#[must_use]
pub(crate) fn agent_verification_key() -> String {
    agent_signer()
        .and_then(|signer| Ok(signer.verifier().qb64()?))
        .unwrap_or_default()
}

#[must_use]
pub(crate) fn agent_state(controller: &str, inception: &str) -> String {
    let agent = format!(
        r#"{{"vn":[1,0],"i":"{AGENT}","s":"0","p":"","d":"{AGENT}","f":"0","dt":"2023-12-01T10:05:25.062609+00:00","et":"dip","kt":"1","k":["{key}"],"nt":"1","n":["EL6zVoZ0F8OXcbXP4LOm5oJTxCXP6ZLp5o3vNfvVZ9YB"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{AGENT}","br":[],"ba":[]}},"di":"{controller}"}}"#,
        key = agent_verification_key()
    );
    format!(r#"{{"agent":{agent},"controller":{{"state":{agent},"ee":{inception}}},"ridx":0,"pidx":0}}"#)
}

pub(crate) fn signed_response(
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

#[must_use]
pub(crate) fn clock() -> Arc<dyn Clock> {
    Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(FIXED_MILLIS),
    ))
}

pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    use core::task::{Context, Poll, Waker};
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
    }
}
