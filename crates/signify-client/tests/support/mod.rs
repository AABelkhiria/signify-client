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

use keri_cesr::crypto::cipher::{Ciphertext, Decrypter, Encrypter};
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_protocol::prefix::IdentifierPrefix;
use keria_types::api::MultisigExchangeResource;
use proptest::strategy::Strategy;
use proptest::test_runner::TestCaseError;
use serde::de::DeserializeOwned;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::exchanges::ClassifiedExchange;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::retry::{Clock, TestClock};
use signify_http::signature::authentication::RequestSigner;
use signify_http::signature::input::{RequestTarget, default_components};
use signify_http::signature::timestamp::SignifyTimestamp;
use signify_http::transport::{Method, Request, Response, StatusCode, Transport, TransportError, TransportFuture};
use signify_keys::manager::DerivationCost;

pub(crate) const ADMIN: &str = "http://127.0.0.1:3901";

/// Brings a credential record or status the reference's schema shaped to KERIA's wire form.
///
/// The schema spells the anchoring sequence number of a credential status as text; KERIA writes
/// it as a number, and the record types follow KERIA. Mocks the reference builds from its schema
/// are converted before an agent answers with them or a test reads them as a record.
pub(crate) fn as_keria_writes(mut value: serde_json::Value) -> Result<serde_json::Value, Box<dyn Error>> {
    let path = if value.get("status").is_some() {
        "/status/a/s"
    } else {
        "/a/s"
    };
    if let Some(serde_json::Value::String(text)) = value.pointer(path).cloned() {
        let number: u64 = text.parse()?;
        if let Some(slot) = value.pointer_mut(path) {
            *slot = serde_json::Value::from(number);
        }
    }
    Ok(value)
}

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

/// Reads and decodes `fixtures/<dir>/v1.json`.
pub(crate) fn fixture<T: DeserializeOwned>(dir: &str) -> Result<T, Box<dyn Error>> {
    let path = format!("{}/fixtures/{dir}/v1.json", env!("CARGO_MANIFEST_DIR"));
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

/// A connected client, the scripted agent answering it, and the client's clock.
pub(crate) struct Harness {
    pub(crate) client: ConnectedClient,
    pub(crate) transport: Arc<AgentTransport>,
    pub(crate) clock: Arc<TestClock>,
}

/// How [`connected_with`] connects beyond its scripted answers.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Connection<'a> {
    pub(crate) passcode: &'a str,
    pub(crate) content_range: Option<&'a str>,
    pub(crate) repeat_last: bool,
}

impl Default for Connection<'_> {
    fn default() -> Self {
        Self {
            passcode: PASSCODE,
            content_range: None,
            repeat_last: false,
        }
    }
}

/// Connects a client whose agent answers `bodies` in order after the connection's own two.
pub(crate) fn connected(bodies: &[&[u8]]) -> Result<Harness, Box<dyn Error>> {
    connected_with(bodies, Connection::default())
}

/// Connects as [`connected`] does, under `connection`'s passcode, content range and repetition.
pub(crate) fn connected_with(bodies: &[&[u8]], connection: Connection<'_>) -> Result<Harness, Box<dyn Error>> {
    let configuration = || {
        ClientConfig::new(ADMIN, connection.passcode)
            .and_then(|config| config.with_boot_url(BOOT))
            .map(|config| config.with_derivation_cost(DerivationCost::Ephemeral))
    };
    let probe = SignifyClient::new(
        configuration()?,
        AgentTransport::new(&[]) as Arc<dyn Transport>,
        clock(),
    )?;
    let prefix = probe.controller().prefix().qb64()?;
    let inception = core::str::from_utf8(probe.controller().current_event().raw())?.to_owned();

    let state = agent_state(&prefix, &inception);
    let mut answers: Vec<&[u8]> = vec![state.as_bytes(), b"{}"];
    answers.extend_from_slice(bodies);
    let transport = AgentTransport::new(&answers);
    if let Some(range) = connection.content_range {
        transport.with_content_range(range);
    }
    if connection.repeat_last {
        transport.repeating_last();
    }

    let clock = Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(FIXED_MILLIS),
    ));
    let client = SignifyClient::new(
        configuration()?,
        Arc::clone(&transport) as Arc<dyn Transport>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    )?;
    Ok(Harness {
        client: block_on(client.connect())?,
        transport,
        clock,
    })
}

/// An endpoint request as the agent received it.
#[derive(Clone, Debug)]
pub(crate) struct SentRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) body: Option<String>,
    recorded: Recorded,
}

impl SentRequest {
    /// The request's `name` header, if it carried one.
    #[must_use]
    pub(crate) fn header(&self, name: &str) -> Option<String> {
        self.recorded.header(name).map(ToOwned::to_owned)
    }
}

impl From<Recorded> for SentRequest {
    fn from(recorded: Recorded) -> Self {
        Self {
            method: recorded.method().to_owned(),
            path: recorded.resource(),
            body: recorded.body_text(),
            recorded,
        }
    }
}

/// The endpoint request at `index`, counting after the connection's own.
pub(crate) fn sent(transport: &AgentTransport, index: usize) -> Result<SentRequest, Box<dyn Error>> {
    sent_all(transport)?
        .into_iter()
        .nth(index)
        .ok_or_else(|| "no endpoint request was sent".into())
}

/// Every endpoint request, after the connection's own.
pub(crate) fn sent_all(transport: &AgentTransport) -> Result<Vec<SentRequest>, Box<dyn Error>> {
    Ok(transport
        .endpoint_requests()?
        .into_iter()
        .map(SentRequest::from)
        .collect())
}

/// The sealing and opening keys for salts under `passcode`.
pub(crate) fn sealing_keys(passcode: &str) -> Result<(Encrypter, Decrypter), Box<dyn Error>> {
    let salt = Salt::from_qb64(&format!("0AA{passcode}"), SecurityTier::Low)?;
    let signer = salt.derive_signer("", KeyTransferability::NonTransferable)?;
    Ok((
        Encrypter::from_verification_key(signer.verifier())?,
        Decrypter::from_signer(&signer),
    ))
}

/// A recorded document as KERIA stores it: each `sxlt_opens_to` salt sealed under `passcode`'s key.
pub(crate) fn reseal(record: &Value, passcode: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut document = record.clone();
    let (encrypter, _) = sealing_keys(passcode)?;
    reseal_in_place(&mut document, &encrypter)?;
    Ok(serde_json::to_vec(&document)?)
}

/// Replaces every `sxlt_opens_to` in `document` with that salt sealed under `encrypter`.
pub(crate) fn reseal_in_place(document: &mut Value, encrypter: &Encrypter) -> Result<(), Box<dyn Error>> {
    match document {
        Value::Object(fields) => {
            if let Some(Value::String(opens_to)) = fields.get("sxlt_opens_to").cloned() {
                let sealed = encrypter
                    .encrypt_salt(&Salt::from_qb64(&opens_to, SecurityTier::Low)?)?
                    .qb64()?;
                fields.remove("sxlt_opens_to");
                fields.insert("sxlt".to_owned(), Value::String(sealed));
            }
            for value in fields.values_mut() {
                reseal_in_place(value, encrypter)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                reseal_in_place(item, encrypter)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// A sent body with each sealed salt masked, and the salts it opened to under `passcode`'s key.
pub(crate) fn mask_sealed(body: &str, passcode: &str) -> Result<(String, Vec<String>), Box<dyn Error>> {
    let (_, decrypter) = sealing_keys(passcode)?;
    let mut masked = String::with_capacity(body.len());
    let mut opened = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find(r#""sxlt":""#) {
        let (head, tail) = rest.split_at(start.saturating_add(r#""sxlt":""#.len()));
        masked.push_str(head);
        let end = tail.find('"').ok_or("an unterminated sealed salt")?;
        let (sealed, remainder) = tail.split_at(end);
        opened.push(
            decrypter
                .decrypt_salt(&Ciphertext::from_qb64(sealed)?, SecurityTier::Low)?
                .expose_qb64()?
                .to_string(),
        );
        masked.push_str("<SXLT>");
        rest = remainder;
    }
    masked.push_str(rest);
    Ok((masked, opened))
}

/// Parses a qb64 identifier prefix.
pub(crate) fn prefix(text: &str) -> Result<IdentifierPrefix, Box<dyn Error>> {
    Ok(IdentifierPrefix::from_qb64(text)?)
}

/// Arbitrary well-formed `E`-coded identifier prefixes.
pub(crate) fn prefixes() -> impl Strategy<Value = IdentifierPrefix> {
    "[A-Za-z0-9_-]{43}".prop_filter_map("not a prefix", |body| {
        IdentifierPrefix::from_qb64(&format!("E{body}")).ok()
    })
}

/// Classifies the first entry of an agent's multisig exchange listing.
pub(crate) fn classify(document: &str) -> Result<ClassifiedExchange, Box<dyn Error>> {
    let decoded: Vec<MultisigExchangeResource> = serde_json::from_str(document)?;
    let entry = decoded.first().ok_or("empty listing")?;
    Ok(ClassifiedExchange::try_from(entry)?)
}

/// Turns an error into a failed proptest case.
pub(crate) fn fail(error: impl core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}
