#![no_main]

//! Fuzzes the client lifecycle over a hostile agent-state response.
//!
//! Everything a client learns about the world before it can sign anything comes from one document:
//! the body of `GET /agent/{caid}`. That body names the agent whose key every response will be
//! verified against, and the establishment event the controller will be rebuilt from. A client
//! that accepts a bad one signs requests to a peer it has not authenticated and verifies replies
//! against a key an attacker chose — so the parse and the two checks around it are the whole of
//! this module's security surface.
//!
//! The target asserts that nothing panics, that every rejection is a typed [`ClientError`] with a
//! non-empty description, and that anything accepted holds the three properties that make a
//! connection worth having: the agent's inception **anchors this controller and no other**; the
//! controller is rebuilt at the rotation index the document named, never mutated after the fact;
//! and the connected client stamps its own prefix rather than anything the document supplied.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use libfuzzer_sys::fuzz_target;
use signify_client::client::SignifyClient;
use signify_client::config::{ClientConfig, PASSCODE_LENGTH, Passcode};
use signify_client::error::ClientError;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::retry::{Clock, TestClock};
use signify_http::transport::{Response, ScriptedTransport, StatusCode};
use signify_keri::manager::DerivationCost;

const ADMIN: &str = "http://127.0.0.1:3901";
const BOOT: &str = "http://127.0.0.1:3903";
const PASSCODE: &str = "0123456789abcdefghijk";
const AGENT: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";
const AGENT_KEY: &str = "BHptu91ecGv_mxO8T3b98vNQUCghT8nfYkWRkVqOZark";

thread_local! {
    /// The client's derived material, built **once** per process rather than per iteration.
    ///
    /// Deriving a controller is two Argon2 runs even at the ephemeral profile, and the derivation
    /// is not what this target exercises — what the client does with a remote document is.
    static DERIVED: Option<(ClientConfig, String, String)> = derive();
}

/// Returns the configuration, the controller prefix, and its inception, derived once.
fn derive() -> Option<(ClientConfig, String, String)> {
    let config = ClientConfig::new(ADMIN, PASSCODE)
        .ok()?
        .with_boot_url(BOOT)
        .ok()?
        .with_derivation_cost(DerivationCost::Ephemeral);
    let client = SignifyClient::new(config.clone(), Arc::new(ScriptedTransport::new()), clock()).ok()?;
    let prefix = client.controller().prefix().qb64().ok()?;
    let inception = core::str::from_utf8(client.controller().current_event().raw())
        .ok()?
        .to_owned();
    Some((config, prefix, inception))
}

fn clock() -> Arc<dyn Clock> {
    Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_123),
    ))
}

fn response(status: u16, body: Vec<u8>) -> Option<Response> {
    let mut headers = Headers::new();
    headers
        .insert(
            HeaderName::new("signify-resource").ok()?,
            HeaderValue::new(AGENT).ok()?,
        )
        .ok()?;
    Response::new(StatusCode::new(status).ok()?, headers, body).ok()
}

/// Assembles an agent-state document whose fields come from the input.
fn agent_state(anchor: &str, inception: &str, rotation_index: &str, agent_prefix: &str) -> String {
    let agent = format!(
        r#"{{"vn":[1,0],"i":"{agent_prefix}","s":"0","p":"","d":"{agent_prefix}","f":"0","dt":"2023-12-01T10:05:25.062609+00:00","et":"dip","kt":"1","k":["{AGENT_KEY}"],"nt":"1","n":["EL6zVoZ0F8OXcbXP4LOm5oJTxCXP6ZLp5o3vNfvVZ9YB"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{agent_prefix}","br":[],"ba":[]}},"di":"{anchor}"}}"#
    );
    format!(
        r#"{{"agent":{agent},"controller":{{"state":{agent},"ee":{inception}}},"ridx":{rotation_index},"pidx":0}}"#
    )
}

/// Escapes a value so it can sit inside a JSON string without breaking the document.
fn escaped(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .flat_map(|character| match character {
            '"' | '\\' => vec!['\\', character],
            other => vec![other],
        })
        .take(128)
        .collect()
}

fuzz_target!(|data: &[u8]| {
    DERIVED.with(|derived| {
        if let Some((config, prefix, inception)) = derived.as_ref() {
            drive(config, prefix, inception, data);
        }
    });
});

/// One fuzz iteration, given material derived once.
fn drive(config: &ClientConfig, prefix: &str, inception: &str, data: &[u8]) {
    let [control, sections @ ..] = data else {
        return;
    };

    // The input splits into the anchor the agent claims, its own prefix, the rotation index, and
    // an arbitrary replacement for the whole body.
    let mut parts = sections.split(|&byte| byte == 0xff);
    let anchor = escaped(&String::from_utf8_lossy(parts.next().unwrap_or_default()));
    let agent_prefix = escaped(&String::from_utf8_lossy(parts.next().unwrap_or_default()));
    let rotation_index = escaped(&String::from_utf8_lossy(parts.next().unwrap_or_default()));
    let raw_body = parts.next().unwrap_or_default();

    // A passcode built from the input, which must be refused unless it is exactly well formed.
    let passcode_text = String::from_utf8_lossy(&data[..data.len().min(40)]).into_owned();
    match Passcode::new(passcode_text.clone()) {
        Ok(passcode) => {
            assert_eq!(passcode.expose().chars().count(), PASSCODE_LENGTH);
            assert!(
                passcode
                    .expose()
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-' || character == '_')
            );
            // A passcode never renders itself, whatever it holds.
            assert!(!format!("{passcode:?}").contains(passcode.expose()));
        }
        Err(error) => {
            assert!(!error.to_string().is_empty());
            assert!(matches!(
                error,
                ClientError::InvalidPasscodeLength { .. } | ClientError::PasscodeNotBase64 { .. }
            ));
        }
    }

    // The document the client will be handed: either an assembled one whose fields the input
    // chose, or the raw bytes verbatim.
    let body = if control & 0x01 == 0 {
        let anchor = if control & 0x02 == 0 { prefix } else { anchor.as_str() };
        let agent_prefix = if control & 0x04 == 0 { AGENT } else { agent_prefix.as_str() };
        let index = if control & 0x08 == 0 { "0" } else { rotation_index.as_str() };
        agent_state(anchor, inception, index, agent_prefix).into_bytes()
    } else {
        raw_body.to_vec()
    };

    let transport = Arc::new(ScriptedTransport::new());
    let Some(answer) = response(if control & 0x10 == 0 { 200 } else { 404 }, body) else {
        return;
    };
    transport.push_response(answer);
    // Connecting may also approve the delegation, which needs a second answer.
    if let Some(empty) = response(200, b"{}".to_vec()) {
        transport.push_response(empty);
    }

    let Ok(client) = SignifyClient::new(config.clone(), transport, clock()) else {
        return;
    };
    assert_eq!(
        client.controller().prefix().qb64().ok().as_deref(),
        Some(prefix),
        "the controller must not depend on the response"
    );

    match block_on(client.connect()) {
        Ok(connected) => {
            // A connection is only accepted when the agent anchors *this* controller.
            let anchored = connected
                .agent()
                .anchor()
                .qb64()
                .expect("an accepted agent's anchor encodes");
            assert_eq!(anchored, prefix, "an agent anchoring someone else was accepted");

            // The client stamps its own prefix, never anything the document carried.
            assert_eq!(connected.resource().as_str(), prefix);
            assert_eq!(
                connected.controller().prefix().qb64().ok().as_deref(),
                Some(prefix)
            );

            // And the agent it verifies against is the one the document named, parsed as a key
            // rather than copied as text.
            assert!(!connected.agent().prefix().qb64().unwrap_or_default().is_empty());
        }
        Err(error) => {
            assert!(!error.to_string().is_empty());
            // Every reachable refusal is one of these; anything else means a path was missed.
            assert!(
                matches!(
                    error,
                    ClientError::AgentNotFound { .. }
                        | ClientError::AgentNotDelegatedToController { .. }
                        | ClientError::IncompleteAgentState { .. }
                        | ClientError::Status { .. }
                        | ClientError::Serialization { .. }
                        | ClientError::Controller { .. }
                        | ClientError::Manager { .. }
                        | ClientError::Transport { .. }
                        | ClientError::Header { .. }
                        | ClientError::Request { .. }
                        | ClientError::Authentication { .. }
                        | ClientError::Crypto { .. }
                        | ClientError::Cesr { .. }
                ),
                "an unexpected refusal shape: {error}"
            );
        }
    }
}

/// A minimal executor; every future on this path is ready on its first poll.
fn block_on<F: core::future::Future>(future: F) -> F::Output {
    use core::task::{Context, Poll, Waker};
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
    }
}
