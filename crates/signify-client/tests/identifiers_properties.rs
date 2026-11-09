//! Invariants of the identifier endpoint family that hold for every input, not just the recorded ones.
//!
//! An alias never leaves its path segment, and an answer is believed only in a state it actually claimed.

mod support;

use std::error::Error;

use crate::support::{AgentTransport, Harness, LIFECYCLE_REQUESTS, PASSCODE, block_on, connected};
use keri_cesr::crypto::salt::SecurityTier;
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_protocol::event::Timestamp;
use keria_types::api::Role;
use proptest::prelude::*;
use serde_json::Value;
use signify_client::endpoint::identifiers::{IdentifierUpdate, LocationSchemeRequest, PreparedRotation};
use signify_client::error::ClientError;
use signify_http::request::ItemRange;
use signify_keys::identifier::{CreateAlgorithm, CreateIdentifierRequest, RotateIdentifierRequest};
use signify_keys::manager::DerivationCost;

const STAMP: &str = "2021-06-27T21:26:21.233257+00:00";

fn sealed_salt() -> Result<&'static str, Box<dyn Error>> {
    use keri_cesr::crypto::cipher::Encrypter;
    use keri_cesr::crypto::salt::Salt;
    static SEALED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    if let Some(sealed) = SEALED.get() {
        return Ok(sealed);
    }
    let salt = Salt::from_qb64(&format!("0AA{PASSCODE}"), SecurityTier::Low)?;
    let signer = salt.derive_signer("", KeyTransferability::NonTransferable)?;
    let sealed = Encrypter::from_verification_key(signer.verifier())?
        .encrypt_salt(&Salt::from_qb64(&format!("0AA{PASSCODE}"), SecurityTier::Low)?)?
        .qb64()?;
    Ok(SEALED.get_or_init(|| sealed))
}

fn record(prefix: &str, key: &str, next: &str, sealed: &str) -> String {
    format!(
        r#"{{"name":"aid1","prefix":"{prefix}","icp_dt":"{STAMP}","state":{{"vn":[1,0],"i":"{prefix}","s":"0","p":"","d":"{prefix}","f":"0","dt":"{STAMP}","et":"icp","kt":"1","k":["{key}"],"nt":"1","n":["{next}"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{prefix}","br":[],"ba":[]}},"di":""}},"transferable":true,"windexes":[],"salty":{{"tier":"low","sxlt":"{sealed}","pidx":0,"kidx":0,"stem":"signify:aid","dcode":"E","icodes":["A"],"ncodes":["A"],"transferable":true}}}}"#
    )
}

fn endpoint_paths(transport: &AgentTransport) -> Vec<String> {
    transport
        .requests()
        .iter()
        .skip(LIFECYCLE_REQUESTS)
        .map(crate::support::Recorded::resource)
        .collect()
}

fn endpoint_body(transport: &AgentTransport, index: usize) -> Option<String> {
    transport
        .requests()
        .get(2 + index)
        .and_then(|request| request.body().map(<[u8]>::to_vec))
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

fn storable_creation() -> CreateIdentifierRequest {
    CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: Some(PASSCODE.into()),
        tier: SecurityTier::Low,
        current_count: 1,
        next_count: 1,
        cost: DerivationCost::Production,
    })
}

fn aliases() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z0-9_-]{1,24}",
        "[a-zA-Z0-9/?#&=%. ]{1,24}",
        Just("..".to_owned()),
        Just("../identifiers".to_owned()),
        Just("a/b?c=d".to_owned()),
        Just("a name with ñ!".to_owned()),
        Just("%2F".to_owned()),
        Just("#fragment".to_owned()),
    ]
}

fn assert_contained(path: &str, alias: &str, trailing: Option<&str>) -> Result<(), TestCaseError> {
    let parts: Vec<&str> = path.split('/').collect();
    let expected = trailing.map_or(3, |_| 4);
    prop_assert_eq!(parts.len(), expected, "path {} escaped its segment", path);
    prop_assert_eq!(parts.first().copied(), Some(""));
    prop_assert_eq!(parts.get(1).copied(), Some("identifiers"));
    let component = parts.get(2).copied().unwrap_or_default();
    prop_assert!(!component.contains('?'));
    prop_assert!(!component.contains('#'));
    prop_assert!(!component.is_empty() || alias.is_empty());
    if let Some(trailing) = trailing {
        prop_assert_eq!(parts.get(3).copied(), Some(trailing));
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    #[test]
    fn an_alias_never_leaves_its_own_segment(alias in aliases()) {
        let record = record(
            "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
            "DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9",
            "EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc",
            sealed_salt().map_err(|error| TestCaseError::fail(error.to_string()))?,
        );
        let Harness { client, transport, .. } = connected(&[record.as_bytes(), record.as_bytes()])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let _ = block_on(client.identifiers().get_any(&alias));
        let _ = block_on(client.identifiers().members(&alias));
        let paths = endpoint_paths(&transport);
        prop_assert_eq!(paths.len(), 2);
        assert_contained(paths.first().map_or("", String::as_str), &alias, None)?;
        assert_contained(paths.get(1).map_or("", String::as_str), &alias, Some("members"))?;
    }

    #[test]
    fn an_update_body_is_always_exactly_one_field(name in "[\\PC&&[^/]]{0,40}") {
        let record = record(
            "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
            "DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9",
            "EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc",
            sealed_salt().map_err(|error| TestCaseError::fail(error.to_string()))?,
        );
        let Harness { client, transport, .. } = connected(&[record.as_bytes()])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let _ = block_on(client.identifiers().update_any("aid1", &IdentifierUpdate::rename(name.clone())));

        let body = endpoint_body(&transport, 0).unwrap_or_default();
        let document: Value = serde_json::from_str(&body)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let fields = document.as_object().ok_or_else(|| TestCaseError::fail("not an object"))?;
        prop_assert_eq!(fields.len(), 1);
        prop_assert_eq!(fields.get("name").and_then(Value::as_str), Some(name.as_str()));
    }

    #[test]
    fn a_requested_window_is_sent_exactly(start in 0_u64..1_000, span in 0_u64..1_000) {
        let end = start.saturating_add(span);
        let Harness { client, transport, .. } = connected(&[b"[]"])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let window = ItemRange::new(start, end)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let listing = block_on(client.identifiers().list(window))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert!(listing.window.is_none());
        prop_assert!(listing.identifiers.is_empty());

        let requests = transport.requests();
        let sent = requests.get(2).ok_or_else(|| TestCaseError::fail("no listing was sent"))?;
        let expected = format!("aids={start}-{end}");
        prop_assert_eq!(sent.header("range"), Some(expected.as_str()));
        prop_assert_eq!(sent.path(), "/identifiers");
        prop_assert!(!sent.request().url().as_str().contains('?'));
    }

    #[test]
    fn an_unsatisfiable_window_cannot_be_built(start in 1_u64..1_000, drop in 1_u64..1_000) {
        let end = start.saturating_sub(drop);
        prop_assume!(end < start);
        prop_assert!(ItemRange::new(start, end).is_err());
    }
}

#[test]
fn a_body_names_its_optional_fields_exactly_when_they_apply() -> Result<(), Box<dyn Error>> {
    for proxy in [None, Some("EPROXY".to_owned())] {
        let mut request = storable_creation();
        request.proxy = proxy.clone();
        let Harness { client, transport, .. } = connected(&[b"{}"])?;
        let _ = block_on(client.identifiers().create("aid1", &request))?;

        let body = endpoint_body(&transport, 0).unwrap_or_default();
        let document: Value = serde_json::from_str(&body)?;
        let fields = document.as_object().ok_or("the body is not an object")?;
        assert!(fields.contains_key("name"));
        assert!(fields.contains_key("icp"));
        assert!(fields.contains_key("sigs"));
        assert!(fields.contains_key("salty"));
        assert_eq!(fields.contains_key("proxy"), proxy.is_some());
        assert!(!fields.contains_key("smids"));
        assert!(!fields.contains_key("rmids"));
        assert_eq!(fields.len(), 4 + usize::from(proxy.is_some()));
    }
    Ok(())
}

#[test]
fn a_salty_block_always_carries_the_same_nine_fields_in_order() -> Result<(), Box<dyn Error>> {
    for keys in 1_usize..3 {
        let mut request = storable_creation();
        if let CreateAlgorithm::Salty {
            current_count,
            next_count,
            ..
        } = &mut request.algorithm
        {
            *current_count = keys;
            *next_count = keys;
        }
        request.signing_threshold = Some(keri_protocol::threshold::SigningThreshold::numeric(1));
        request.next_threshold = Some(keri_protocol::threshold::SigningThreshold::numeric(1));
        let Harness { client, transport, .. } = connected(&[b"{}"])?;
        let _ = block_on(client.identifiers().create("aid1", &request))?;

        let body = endpoint_body(&transport, 0).unwrap_or_default();
        let start = body.find(r#""salty":{"#).ok_or("the body carries no salty block")?;
        let block = body.get(start..).unwrap_or_default();
        let mut cursor = 0_usize;
        for label in [
            r#""sxlt":"#,
            r#""pidx":"#,
            r#""kidx":"#,
            r#""stem":"#,
            r#""tier":"#,
            r#""icodes":"#,
            r#""ncodes":"#,
            r#""dcode":"#,
            r#""transferable":"#,
        ] {
            let found = block
                .get(cursor..)
                .and_then(|rest| rest.find(label))
                .ok_or_else(|| format!("the salty block lost {label}"))?;
            cursor = cursor.saturating_add(found).saturating_add(label.len());
        }
        let mut codes = String::from(r#""icodes":["#);
        codes.push_str(&vec!["\"A\""; keys].join(","));
        codes.push(']');
        assert!(block.contains(&codes), "the key count did not reach the block");
    }
    Ok(())
}

#[test]
fn a_rotation_always_names_both_member_lists() -> Result<(), Box<dyn Error>> {
    let record = record(
        "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
        "DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9",
        "EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc",
        sealed_salt()?,
    );
    let Harness { client, transport, .. } = connected(&[record.as_bytes(), b"{}"])?;
    let _ = block_on(client.identifiers().rotate("aid1", &RotateIdentifierRequest::default()))?;

    let body = endpoint_body(&transport, 1).unwrap_or_default();
    let document: Value = serde_json::from_str(&body)?;
    let fields = document.as_object().ok_or("the body is not an object")?;
    assert!(fields.contains_key("rot"));
    assert_eq!(fields.get("smids"), Some(&Value::Array(Vec::new())));
    assert_eq!(fields.get("rmids"), Some(&Value::Array(Vec::new())));
    Ok(())
}

fn rotatable_record() -> Result<String, Box<dyn Error>> {
    Ok(record(
        "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
        "DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9",
        "EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc",
        sealed_salt()?,
    ))
}

#[test]
fn a_prepared_rotation_is_resent_byte_for_byte_after_a_restore() -> Result<(), Box<dyn Error>> {
    let record = rotatable_record()?;
    let Harness { client, transport, .. } = connected(&[record.as_bytes(), b"{}", b"{}"])?;
    let identifiers = client.identifiers();
    let prepared = block_on(identifiers.prepare_rotation("aid1", &RotateIdentifierRequest::default(), None))?;
    assert_eq!(
        transport.requests().len(),
        LIFECYCLE_REQUESTS + 1,
        "preparing sends nothing"
    );

    let restored = PreparedRotation::from_body(prepared.as_body().to_vec())?;
    assert_eq!(restored, prepared);
    let submission = block_on(identifiers.submit_rotation("aid1", &restored))?;
    assert_eq!(submission.artifact().said(), prepared.said());
    let _ = block_on(identifiers.submit_rotation("aid1", &restored))?;

    let stored = String::from_utf8(prepared.as_body().to_vec())?;
    assert_eq!(endpoint_body(&transport, 1).as_deref(), Some(stored.as_str()));
    assert_eq!(endpoint_body(&transport, 2).as_deref(), Some(stored.as_str()));
    Ok(())
}

#[test]
fn a_prepared_rotation_matches_a_direct_rotation() -> Result<(), Box<dyn Error>> {
    let record = rotatable_record()?;
    let Harness { client, transport, .. } = connected(&[record.as_bytes(), record.as_bytes(), b"{}"])?;
    let identifiers = client.identifiers();
    let prepared = block_on(identifiers.prepare_rotation("aid1", &RotateIdentifierRequest::default(), None))?;
    let _ = block_on(identifiers.rotate("aid1", &RotateIdentifierRequest::default()))?;

    let sent = endpoint_body(&transport, 2).ok_or("the rotation was not sent")?;
    assert_eq!(sent.as_bytes(), prepared.as_body());
    Ok(())
}

#[test]
fn a_prior_state_replaces_the_agents_current_one() -> Result<(), Box<dyn Error>> {
    let record = rotatable_record()?;
    let document: Value = serde_json::from_str(&record)?;
    let mut state = document.get("state").cloned().ok_or("the record holds no state")?;
    let fields = state.as_object_mut().ok_or("the state is not an object")?;
    fields.insert("s".to_owned(), Value::from("4"));
    fields.insert(
        "d".to_owned(),
        Value::from("EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc"),
    );
    let prior = serde_json::from_value(state)?;

    let Harness { client, .. } = connected(&[record.as_bytes()])?;
    let identifiers = client.identifiers();
    let prepared = block_on(identifiers.prepare_rotation("aid1", &RotateIdentifierRequest::default(), Some(&prior)))?;

    let body: Value = serde_json::from_slice(prepared.as_body())?;
    let event = body.get("rot").ok_or("the body holds no rotation")?;
    assert_eq!(event.get("s").and_then(Value::as_str), Some("5"));
    assert_eq!(
        event.get("p").and_then(Value::as_str),
        Some("EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc")
    );
    Ok(())
}

#[test]
fn stored_bytes_without_a_rotation_are_refused() {
    for body in [
        &b"not json"[..],
        b"{}",
        br#"{"rot":"text","sigs":["S"],"salty":{}}"#,
        br#"{"rot":{"t":"rot"},"sigs":["S"],"salty":{}}"#,
        br#"{"rot":{"d":"E"},"sigs":[],"salty":{}}"#,
        br#"{"rot":{"d":"E"},"salty":{}}"#,
        br#"{"rot":{"d":"E"},"sigs":["S"]}"#,
    ] {
        assert!(matches!(
            PreparedRotation::from_body(body.to_vec()),
            Err(ClientError::InvalidPreparedRotation)
        ));
    }
}

#[test]
fn a_prepared_rotation_keeps_its_body_out_of_debug_output() -> Result<(), Box<dyn Error>> {
    let rotation =
        PreparedRotation::from_body(br#"{"rot":{"d":"ESAID"},"sigs":["S"],"salty":{"sxlt":"SEALED"}}"#.to_vec())?;
    let rendered = format!("{rotation:?}");
    assert!(rendered.contains("ESAID"));
    assert!(!rendered.contains("SEALED"));
    Ok(())
}

#[test]
fn a_pending_record_is_refused_under_any_alias() -> Result<(), Box<dyn Error>> {
    for alias in ["group1", "..", "a/b", ""] {
        let pending = r#"{"name":"group1","prefix":"EGRP","icp_dt":"2023-12-01T10:05:25.062609+00:00","transferable":true,"windexes":[],"randy":{"prxs":[],"nxts":[]}}"#;
        let Harness { client, .. } = connected(&[pending.as_bytes()])?;
        let outcome = block_on(client.identifiers().get(alias));
        assert!(
            matches!(outcome, Err(ClientError::IdentifierNotAccepted { ref name }) if name == alias),
            "an alias of {alias:?} was not refused"
        );
    }
    Ok(())
}

#[test]
fn an_alias_of_two_dots_addresses_the_identifier_it_names() -> Result<(), Box<dyn Error>> {
    let Harness { client, transport, .. } = connected(&[b"{}", b"{}"])?;
    let _ = block_on(client.identifiers().get_any(".."));
    let _ = block_on(client.identifiers().get_any("../identifiers"));
    let paths = endpoint_paths(&transport);
    assert_eq!(paths.first().map(String::as_str), Some("/identifiers/.."));
    assert_eq!(paths.get(1).map(String::as_str), Some("/identifiers/..%2Fidentifiers"));
    Ok(())
}

#[test]
fn a_defaulted_location_authorization_writes_every_attribute() -> Result<(), Box<dyn Error>> {
    let record = record(
        "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
        "DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9",
        "EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc",
        sealed_salt()?,
    );
    let Harness { client, transport, .. } = connected(&[record.as_bytes(), b"{}"])?;
    let request = LocationSchemeRequest {
        url: "http://test.com".to_owned(),
        scheme: None,
        endpoint: None,
        stamp: Timestamp::parse(STAMP)?,
    };
    let submission = block_on(client.identifiers().add_location_scheme("aid1", &request))?;

    let attributes = submission
        .artifact()
        .reply
        .sad()
        .get("a")
        .and_then(keri_protocol::serialization::SadValue::as_map)
        .ok_or("the reply carries no attributes")?;
    assert_eq!(
        attributes.entries().map(|(label, _)| label).collect::<Vec<_>>(),
        ["eid", "url", "scheme"]
    );
    assert_eq!(attributes.get_text("scheme"), Some("http"));
    assert_eq!(
        attributes.get_text("eid"),
        Some("ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK")
    );
    assert_eq!(
        endpoint_paths(&transport),
        ["/identifiers/aid1", "/identifiers/aid1/locschemes"]
    );
    Ok(())
}

#[test]
fn an_unnamed_role_is_carried_verbatim() -> Result<(), Box<dyn Error>> {
    let role = Role::Other("custodian".to_owned());
    assert_eq!(role.as_str(), "custodian");
    let Harness { client, transport, .. } = connected(&[b"{}"])?;
    let outcome = block_on(
        client
            .identifiers()
            .add_end_role("aid1", &role, None, Timestamp::parse(STAMP)?),
    );
    assert!(matches!(outcome, Err(ClientError::Api { .. })));
    assert_eq!(endpoint_paths(&transport), ["/identifiers/aid1"]);
    Ok(())
}
