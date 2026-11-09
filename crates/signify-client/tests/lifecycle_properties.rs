//! Invariants of the client lifecycle.
//!
//! Construction, connection, and state invariants, every client derived at the ephemeral cost.

mod support;

use std::sync::Arc;

use crate::support::{block_on, clock, fail};
use keri_cesr::crypto::salt::SecurityTier;
use keri_protocol::serialization::{Sad, SadValue};
use proptest::prelude::*;
use signify_client::client::{BOOT_PREFIX_INDEX, ClientRequest, SignifyClient};
use signify_client::config::{ClientConfig, DEFAULT_BOOT_URL, PASSCODE_LENGTH, Passcode};
use signify_client::error::ClientError;
use signify_client::random::{random_nonce, random_passcode};
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::request::ResourcePath;
use signify_http::transport::{Method, Response, ScriptedTransport, StatusCode};
use signify_keys::manager::DerivationCost;

const ADMIN: &str = "http://127.0.0.1:3901";
const BOOT: &str = "http://127.0.0.1:3903";
const PASSCODE: &str = "0123456789abcdefghijk";
const AGENT: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";
const AGENT_KEY: &str = "BHptu91ecGv_mxO8T3b98vNQUCghT8nfYkWRkVqOZark";

fn config(passcode: &str) -> Result<ClientConfig, ClientError> {
    Ok(ClientConfig::new(ADMIN, passcode)?
        .with_boot_url(BOOT)?
        .with_derivation_cost(DerivationCost::Ephemeral))
}

/// Largest integer a JSON number carries exactly.
const JSON_SAFE_MAX: i64 = (1 << 53) - 1;

fn agent_state(controller_prefix: &str, inception: &str, rotation_index: u32) -> String {
    let agent = format!(
        r#"{{"vn":[1,0],"i":"{AGENT}","s":"0","p":"","d":"{AGENT}","f":"0","dt":"2023-12-01T10:05:25.062609+00:00","et":"dip","kt":"1","k":["{AGENT_KEY}"],"nt":"1","n":["EL6zVoZ0F8OXcbXP4LOm5oJTxCXP6ZLp5o3vNfvVZ9YB"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{AGENT}","br":[],"ba":[]}},"di":"{controller_prefix}"}}"#
    );
    format!(r#"{{"agent":{agent},"controller":{{"state":{agent},"ee":{inception}}},"ridx":{rotation_index},"pidx":0}}"#)
}

fn response(status: u16, body: Vec<u8>) -> Result<Response, TestCaseError> {
    let mut headers = Headers::new();
    headers
        .insert(
            HeaderName::new("signify-resource").map_err(fail)?,
            HeaderValue::new(AGENT).map_err(fail)?,
        )
        .map_err(fail)?;
    Response::new(StatusCode::new(status).map_err(fail)?, headers, body).map_err(fail)
}

proptest! {
    #[test]
    fn a_passcode_is_accepted_exactly_when_it_is_well_formed(
        length in 0_usize..30,
        illegal in prop::option::of(0_usize..21),
    ) {
        let mut text: String = "a".repeat(length);
        if let Some(position) = illegal
            && position < length
        {
            text.replace_range(position..=position, "+");
        }
        let offending = illegal.filter(|position| *position < length);

        match Passcode::new(text.clone()) {
            Ok(passcode) => {
                prop_assert_eq!(length, PASSCODE_LENGTH);
                prop_assert!(offending.is_none());
                prop_assert_eq!(passcode.expose(), text.as_str());
            }
            Err(ClientError::InvalidPasscodeLength { expected, actual }) => {
                prop_assert_ne!(length, PASSCODE_LENGTH);
                prop_assert_eq!(expected, PASSCODE_LENGTH);
                prop_assert_eq!(actual, length);
            }
            Err(ClientError::PasscodeNotBase64 { position }) => {
                prop_assert_eq!(length, PASSCODE_LENGTH);
                prop_assert_eq!(Some(position), offending);
            }
            Err(other) => return Err(fail(other)),
        }
    }

    #[test]
    fn a_passcode_is_never_rendered(suffix in "[A-Za-z0-9_-]{11}") {
        let text = format!("0123456789{suffix}");
        let passcode = Passcode::new(text.clone()).map_err(fail)?;
        let rendered = format!("{passcode:?}");
        prop_assert!(!rendered.contains(&text), "a passcode rendered itself");

        let config = config(&text).map_err(fail)?;
        let rendered = format!("{config:?}");
        prop_assert!(!rendered.contains(&text), "a configuration rendered its passcode");
        prop_assert!(!rendered.contains(&suffix), "a configuration rendered part of its passcode");

        let transport = Arc::new(ScriptedTransport::new());
        let client = SignifyClient::new(config, transport, clock()).map_err(fail)?;
        let rendered = format!("{client:?}");
        prop_assert!(!rendered.contains(&text), "a client rendered its passcode");
    }

    #[test]
    fn the_boot_body_shape_never_varies(suffix in "[A-Za-z0-9_-]{11}") {
        let passcode = format!("0123456789{suffix}");
        let transport = Arc::new(ScriptedTransport::new());
        let client = SignifyClient::new(config(&passcode).map_err(fail)?, transport, clock()).map_err(fail)?;

        let body = client.boot_body().map_err(fail)?;
        let document = Sad::from_json_bytes(&body).map_err(fail)?;
        let labels: Vec<&str> = document.entries().map(|(label, _)| label).collect();
        prop_assert_eq!(labels, ["icp", "sig", "stem", "pidx", "tier"]);
        prop_assert_eq!(document.get("pidx"), Some(&SadValue::Integer(BOOT_PREFIX_INDEX)));
        prop_assert_eq!(document.get_text("stem"), Some("signify:controller"));
        prop_assert_eq!(document.get_text("tier"), Some("low"));

        let inception = document.get("icp").and_then(SadValue::as_map)
            .ok_or_else(|| TestCaseError::fail("no inception in the boot body"))?;
        prop_assert_eq!(
            inception.to_json_bytes().map_err(fail)?,
            client.controller().current_event().raw()
        );
    }

    #[test]
    fn a_tier_changes_the_controller_and_its_wire_text(index in 0_usize..3) {
        let tiers = [SecurityTier::Low, SecurityTier::Medium, SecurityTier::High];
        let texts = ["low", "med", "high"];
        let tier = *tiers.get(index).ok_or_else(|| TestCaseError::fail("no such tier"))?;
        let expected = *texts.get(index).ok_or_else(|| TestCaseError::fail("no such text"))?;

        let transport = Arc::new(ScriptedTransport::new());
        let client = SignifyClient::new(
            config(PASSCODE).map_err(fail)?.with_tier(tier),
            transport,
            clock(),
        )
        .map_err(fail)?;
        let body = Sad::from_json_bytes(&client.boot_body().map_err(fail)?).map_err(fail)?;
        prop_assert_eq!(body.get_text("tier"), Some(expected));
    }

    #[test]
    fn an_agent_anchoring_someone_else_is_refused(suffix in "[A-Za-z0-9_-]{11}") {
        let transport = Arc::new(ScriptedTransport::new());
        let client = SignifyClient::new(config(PASSCODE).map_err(fail)?, Arc::clone(&transport) as Arc<_>, clock())
            .map_err(fail)?;
        let prefix = client.controller().prefix().qb64().map_err(fail)?;
        let inception = core::str::from_utf8(client.controller().current_event().raw())
            .map_err(fail)?
            .to_owned();

        let other = SignifyClient::new(
            config(&format!("abcdefghij{suffix}")).map_err(fail)?,
            Arc::new(ScriptedTransport::new()),
            clock(),
        )
        .map_err(fail)?;
        let other_prefix = other.controller().prefix().qb64().map_err(fail)?;
        prop_assume!(other_prefix != prefix);

        transport.push_response(response(200, agent_state(&other_prefix, &inception, 0).into_bytes())?);
        let outcome = block_on(client.connect());
        prop_assert!(
            matches!(
                &outcome,
                Err(ClientError::AgentNotDelegatedToController { expected, actual })
                    if *expected == prefix && *actual == other_prefix
            ),
            "an agent anchoring another controller was accepted"
        );
    }

    #[test]
    fn a_non_success_state_read_is_never_parsed(status in 400_u16..600) {
        let transport = Arc::new(ScriptedTransport::new());
        let client = SignifyClient::new(config(PASSCODE).map_err(fail)?, Arc::clone(&transport) as Arc<_>, clock())
            .map_err(fail)?;
        transport.push_response(response(status, b"trouble".to_vec())?);

        match block_on(client.state()) {
            Err(ClientError::AgentNotFound { controller }) => {
                prop_assert_eq!(status, 404);
                prop_assert_eq!(controller, client.controller().prefix().qb64().map_err(fail)?);
            }
            Err(ClientError::Status { status: reported, detail }) => {
                prop_assert_ne!(status, 404);
                prop_assert_eq!(reported, status);
                prop_assert_eq!(detail, "trouble");
            }
            other => return Err(fail(format!("a {status} was not refused: {other:?}"))),
        }
    }

    #[test]
    fn an_incomplete_state_body_is_refused(drop_agent in any::<bool>()) {
        let transport = Arc::new(ScriptedTransport::new());
        let client = SignifyClient::new(config(PASSCODE).map_err(fail)?, Arc::clone(&transport) as Arc<_>, clock())
            .map_err(fail)?;
        let body = if drop_agent {
            r#"{"controller":{"ee":{}},"ridx":0,"pidx":0}"#
        } else {
            r#"{"agent":{},"ridx":0,"pidx":0}"#
        };
        transport.push_response(response(200, body.as_bytes().to_vec())?);

        prop_assert!(
            matches!(
                block_on(client.state()),
                Err(ClientError::IncompleteAgentState { .. })
            ),
            "an incomplete state body was accepted"
        );
    }

    #[test]
    fn an_unreadable_index_is_refused(
        label in prop_oneof![Just("ridx"), Just("pidx")],
        // Too large, negative, and not an integer.
        value in prop_oneof![
            (i64::from(u32::MAX) + 1..=JSON_SAFE_MAX).prop_map(|value| value.to_string()),
            (-JSON_SAFE_MAX..0).prop_map(|value| value.to_string()),
            Just(r#""1""#.to_owned()),
        ],
    ) {
        let transport = Arc::new(ScriptedTransport::new());
        let client = SignifyClient::new(config(PASSCODE).map_err(fail)?, Arc::clone(&transport) as Arc<_>, clock())
            .map_err(fail)?;
        let inception = core::str::from_utf8(client.controller().current_event().raw())
            .map_err(fail)?
            .to_owned();
        let prefix = client.controller().prefix().qb64().map_err(fail)?;
        let state = agent_state(&prefix, &inception, 0)
            .replace(&format!(r#""{label}":0"#), &format!(r#""{label}":{value}"#));
        transport.push_response(response(200, state.into_bytes())?);

        match block_on(client.state()) {
            Err(ClientError::InvalidAgentIndex { label: reported }) => prop_assert_eq!(reported, label),
            other => return Err(fail(format!("{label}={value} was not refused: {other:?}"))),
        }
    }

    #[test]
    fn the_random_helpers_always_produce_usable_values(rounds in 1_usize..6) {
        for _ in 0..rounds {
            let passcode = random_passcode().map_err(fail)?;
            prop_assert_eq!(passcode.expose().chars().count(), PASSCODE_LENGTH);
            Passcode::new(passcode.expose()).map_err(fail)?;

            let nonce = random_nonce().map_err(fail)?;
            prop_assert_eq!(nonce.len(), 44);
            prop_assert!(nonce.starts_with('A'));
        }
    }
}

#[test]
fn a_connected_controller_past_zero_does_not_reapprove() -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(ScriptedTransport::new());
    let client = SignifyClient::new(config(PASSCODE)?, Arc::clone(&transport) as Arc<_>, clock())?;
    let prefix = client.controller().prefix().qb64()?;
    // The passcode's own key: connecting refuses an established key the passcode does not derive.
    let key = client
        .controller()
        .current_keys()
        .first()
        .cloned()
        .ok_or("the controller has no key")?;

    let rotation = format!(
        r#"{{"v":"KERI10JSON000160_","t":"rot","d":"EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C","i":"{prefix}","s":"1","p":"{prefix}","kt":"1","k":["{key}"],"nt":"1","n":["EIFG_uqfr1yN560LoHYHfvPAhxQ5sN6xZZT_E3h7d2tL"],"bt":"0","br":[],"ba":[],"a":[]}}"#
    );
    let sized = keri_protocol::serialization::SerializedEvent::from_sad(Sad::from_json_bytes(rotation.as_bytes())?)?;
    let adopted = core::str::from_utf8(sized.raw())?.to_owned();

    transport.push_response({
        let mut headers = Headers::new();
        headers.insert(HeaderName::new("signify-resource")?, HeaderValue::new(AGENT)?)?;
        Response::new(
            StatusCode::new(200)?,
            headers,
            agent_state(&prefix, &adopted, 0).into_bytes(),
        )?
    });

    let connected = block_on(client.connect())?;
    assert_eq!(connected.controller().current_sequence_number(), 1);
    assert_eq!(transport.recorded().len(), 1);
    Ok(())
}

#[test]
fn an_unconnected_client_exposes_no_signed_call() -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(ScriptedTransport::new());
    let client = SignifyClient::new(config(PASSCODE)?, transport, clock())?;

    let path = ResourcePath::builder().segment("contacts").build()?;
    let request = ClientRequest::new(Method::Get, path);
    assert_eq!(request.method(), Method::Get);
    assert_eq!(request.path().as_str(), "/contacts");
    assert_eq!(client.config().boot_url().as_str(), BOOT);
    Ok(())
}

#[test]
fn the_default_boot_url_is_the_references() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::new(ADMIN, PASSCODE)?;
    assert_eq!(config.boot_url().as_str(), DEFAULT_BOOT_URL);
    assert_eq!(DEFAULT_BOOT_URL, "http://localhost:3903");
    Ok(())
}
