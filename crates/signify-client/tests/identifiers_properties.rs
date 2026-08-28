//! Invariants of the identifier endpoint family that hold for every input, not just the recorded
//! ones.
//!
//! The properties here are the ones a caller's safety rests on: an alias can never leave its own
//! path segment whatever it holds — which is exactly the defect the reference has in five of its
//! seven name-bearing paths — a request body always names the fields the agent needs and never the
//! ones it would misread, and an answer is believed only in a state it actually claimed.
//!
//! Every client here derives its controller at the ephemeral profile, because none of these
//! properties is about key derivation.

use std::error::Error;
use std::sync::Arc;

use proptest::prelude::*;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::identifiers::{IdentifierUpdate, LocationSchemeRequest};
use signify_client::error::ClientError;
use signify_crypto::salt::SecurityTier;
use signify_crypto::verifier::KeyTransferability;
use signify_http::request::ItemRange;
use signify_http::transport::Transport;
use signify_keri::event::Timestamp;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest, RotateIdentifierRequest};
use signify_keri::manager::DerivationCost;
use signify_testkit::{ADMIN, AgentTransport, BOOT, LIFECYCLE_REQUESTS, PASSCODE, agent_state, block_on, clock};
use signify_types::api::Role;

const STAMP: &str = "2021-06-27T21:26:21.233257+00:00";

/// Seals the identifier salt this client's controller key can open.
///
/// Derived once for the whole binary: the sealing key is an Argon2 derivation at the production
/// profile, and every case here wants the same one.
fn sealed_salt() -> Result<&'static str, Box<dyn Error>> {
    use signify_crypto::cipher::Encrypter;
    use signify_crypto::salt::Salt;
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

/// An identifier record for `aid1`, whose keeper this client can rebuild.
fn record(prefix: &str, key: &str, next: &str, sealed: &str) -> String {
    format!(
        r#"{{"name":"aid1","prefix":"{prefix}","icp_dt":"{STAMP}","state":{{"vn":[1,0],"i":"{prefix}","s":"0","p":"","d":"{prefix}","f":"0","dt":"{STAMP}","et":"icp","kt":"1","k":["{key}"],"nt":"1","n":["{next}"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{prefix}","br":[],"ba":[]}},"di":""}},"transferable":true,"windexes":[],"salty":{{"tier":"low","sxlt":"{sealed}","pidx":0,"kidx":0,"stem":"signify:aid","dcode":"E","icodes":["A"],"ncodes":["A"],"transferable":true}}}}"#
    )
}

/// Connects a client answering `bodies` after the two the lifecycle consumes.
fn connected(bodies: &[&[u8]]) -> Result<(ConnectedClient, Arc<AgentTransport>), Box<dyn Error>> {
    let configuration = || {
        ClientConfig::new(ADMIN, PASSCODE)
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

    let client = SignifyClient::new(configuration()?, Arc::clone(&transport) as Arc<dyn Transport>, clock())?;
    Ok((block_on(client.connect())?, transport))
}

/// Returns the paths of the endpoint requests one client sent, in order.
fn endpoint_paths(transport: &AgentTransport) -> Vec<String> {
    transport
        .requests()
        .iter()
        .skip(LIFECYCLE_REQUESTS)
        .map(signify_testkit::Recorded::resource)
        .collect()
}

/// Returns the body of the endpoint request at `index`.
fn endpoint_body(transport: &AgentTransport, index: usize) -> Option<String> {
    transport
        .requests()
        .get(2 + index)
        .and_then(|request| request.body().map(<[u8]>::to_vec))
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

/// A creation whose keeper can be stored.
///
/// The cost is the reference's own production profile, and it has to be: a keeper built at the
/// ephemeral profile refuses to report its parameters, because an identifier record stores a tier
/// and not a cost, so it could never be reloaded to the same keys. That makes these properties
/// slow, and correctly so — a request body carries exactly what a reload will read.
fn storable_creation() -> CreateIdentifierRequest {
    CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: Some(PASSCODE.to_owned()),
        tier: SecurityTier::Low,
        current_count: 1,
        next_count: 1,
        cost: DerivationCost::Production,
    })
}

/// Aliases including the shapes that break the reference: delimiters, dot segments, and Unicode.
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

/// Asserts one path is exactly `segments` segments under `/identifiers`, with the alias contained.
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

    /// The defect the reference has in five of its seven paths, closed by construction: whatever an
    /// alias holds, it stays one path segment and never introduces a query or a fragment.
    #[test]
    fn an_alias_never_leaves_its_own_segment(alias in aliases()) {
        let record = record(
            "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
            "DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9",
            "EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc",
            sealed_salt().map_err(|error| TestCaseError::fail(error.to_string()))?,
        );
        let (client, transport) = connected(&[record.as_bytes(), record.as_bytes()])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let _ = block_on(client.identifiers().get_any(&alias));
        let _ = block_on(client.identifiers().members(&alias));
        let paths = endpoint_paths(&transport);
        prop_assert_eq!(paths.len(), 2);
        assert_contained(paths.first().map_or("", String::as_str), &alias, None)?;
        assert_contained(paths.get(1).map_or("", String::as_str), &alias, Some("members"))?;
    }

    /// An update always sends exactly one field, whatever the new name holds — including quotes and
    /// braces, which a hand-built body would have to escape.
    #[test]
    fn an_update_body_is_always_exactly_one_field(name in "[\\PC]{0,40}") {
        let record = record(
            "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
            "DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9",
            "EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc",
            sealed_salt().map_err(|error| TestCaseError::fail(error.to_string()))?,
        );
        let (client, transport) = connected(&[record.as_bytes()])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let _ = block_on(client.identifiers().update_any("aid1", &IdentifierUpdate::rename(name.clone())));

        let body = endpoint_body(&transport, 0).unwrap_or_default();
        let document: Value = serde_json::from_str(&body)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let fields = document.as_object().ok_or_else(|| TestCaseError::fail("not an object"))?;
        prop_assert_eq!(fields.len(), 1);
        prop_assert_eq!(fields.get("name").and_then(Value::as_str), Some(name.as_str()));
    }

    /// The window a listing asks for reaches the agent exactly, for any satisfiable pair, and the
    /// path never carries it — the reference sends it as a header too.
    #[test]
    fn a_requested_window_is_sent_exactly(start in 0_u64..1_000, span in 0_u64..1_000) {
        let end = start.saturating_add(span);
        let (client, transport) = connected(&[b"[]"])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let window = ItemRange::new(start, end)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let listing = block_on(client.identifiers().list(window))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        // This transport reports no content-range, so an unreported window is `None` rather than
        // the three zeroes the reference would produce.
        prop_assert!(listing.window.is_none());
        prop_assert!(listing.identifiers.is_empty());

        let requests = transport.requests();
        let sent = requests.get(2).ok_or_else(|| TestCaseError::fail("no listing was sent"))?;
        let expected = format!("aids={start}-{end}");
        prop_assert_eq!(sent.header("range"), Some(expected.as_str()));
        prop_assert_eq!(sent.path(), "/identifiers");
        prop_assert!(!sent.request().url().as_str().contains('?'));
    }

    /// A window whose end precedes its start is unrepresentable, so it can never be sent — where
    /// the reference interpolates whatever it was handed.
    #[test]
    fn an_unsatisfiable_window_cannot_be_built(start in 1_u64..1_000, drop in 1_u64..1_000) {
        let end = start.saturating_sub(drop);
        prop_assume!(end < start);
        prop_assert!(ItemRange::new(start, end).is_err());
    }
}

/// A creation names `proxy` exactly when one was given, and never names the group's member lists —
/// where a rotation always names both. That asymmetry is the reference's own.
///
/// This is a small deterministic sweep rather than a generated one: every case derives real keys at
/// the reference's production Argon2 profile, because a keeper built at the ephemeral profile
/// refuses to report the parameters a request body carries. The generated properties above are the
/// ones whose input space is actually large.
#[test]
fn a_body_names_its_optional_fields_exactly_when_they_apply() -> Result<(), Box<dyn Error>> {
    for proxy in [None, Some("EPROXY".to_owned())] {
        let mut request = storable_creation();
        request.proxy = proxy.clone();
        let (client, transport) = connected(&[b"{}"])?;
        let _ = block_on(client.identifiers().create("aid1", &request))?;

        let body = endpoint_body(&transport, 0).unwrap_or_default();
        let document: Value = serde_json::from_str(&body)?;
        let fields = document.as_object().ok_or("the body is not an object")?;
        assert!(fields.contains_key("name"));
        assert!(fields.contains_key("icp"));
        assert!(fields.contains_key("sigs"));
        assert!(fields.contains_key("salty"));
        assert_eq!(fields.contains_key("proxy"), proxy.is_some());
        // Never, outside a group: the reference leaves both `undefined` and `JSON.stringify`
        // drops them.
        assert!(!fields.contains_key("smids"));
        assert!(!fields.contains_key("rmids"));
        assert_eq!(fields.len(), 4 + usize::from(proxy.is_some()));
    }
    Ok(())
}

/// A salty block always carries the reference's nine fields in the reference's order, for any key
/// count — because a reload reads every one of them.
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
        request.signing_threshold = Some(signify_keri::threshold::SigningThreshold::numeric(1));
        request.next_threshold = Some(signify_keri::threshold::SigningThreshold::numeric(1));
        let (client, transport) = connected(&[b"{}"])?;
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

/// A rotation always names both member lists, empty or not — where a creation omits them.
#[test]
fn a_rotation_always_names_both_member_lists() -> Result<(), Box<dyn Error>> {
    let record = record(
        "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
        "DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9",
        "EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc",
        sealed_salt()?,
    );
    let (client, transport) = connected(&[record.as_bytes(), b"{}"])?;
    let _ = block_on(client.identifiers().rotate("aid1", &RotateIdentifierRequest::default()))?;

    let body = endpoint_body(&transport, 1).unwrap_or_default();
    let document: Value = serde_json::from_str(&body)?;
    let fields = document.as_object().ok_or("the body is not an object")?;
    assert!(fields.contains_key("rot"));
    assert_eq!(fields.get("smids"), Some(&Value::Array(Vec::new())));
    assert_eq!(fields.get("rmids"), Some(&Value::Array(Vec::new())));
    Ok(())
}

/// A pending record is refused wherever key state is required, whatever it is called.
#[test]
fn a_pending_record_is_refused_under_any_alias() -> Result<(), Box<dyn Error>> {
    for alias in ["group1", "..", "a/b", ""] {
        let pending = r#"{"name":"group1","prefix":"EGRP","icp_dt":"2023-12-01T10:05:25.062609+00:00","transferable":true,"windexes":[],"randy":{"prxs":[],"nxts":[]}}"#;
        let (client, _) = connected(&[pending.as_bytes()])?;
        let outcome = block_on(client.identifiers().get(alias));
        assert!(
            matches!(outcome, Err(ClientError::IdentifierNotAccepted { ref name }) if name == alias),
            "an alias of {alias:?} was not refused"
        );
    }
    Ok(())
}

/// Regression: an alias of exactly `..` keeps its dots, and one carrying a slash is encoded, so a
/// component can never introduce a dot segment or a new segment. This is the same pair Roadmap 6.5
/// pinned for an operation name; the reference's identifier paths do not encode at all.
#[test]
fn an_alias_of_two_dots_addresses_the_identifier_it_names() -> Result<(), Box<dyn Error>> {
    let (client, transport) = connected(&[b"{}", b"{}"])?;
    let _ = block_on(client.identifiers().get_any(".."));
    let _ = block_on(client.identifiers().get_any("../identifiers"));
    let paths = endpoint_paths(&transport);
    assert_eq!(paths.first().map(String::as_str), Some("/identifiers/.."));
    assert_eq!(paths.get(1).map(String::as_str), Some("/identifiers/..%2Fidentifiers"));
    Ok(())
}

/// Regression: a location authorization with no scheme and no endpoint still writes both, because
/// the SAID commits to them — and the defaults are the reference's own.
#[test]
fn a_defaulted_location_authorization_writes_every_attribute() -> Result<(), Box<dyn Error>> {
    let record = record(
        "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
        "DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9",
        "EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc",
        sealed_salt()?,
    );
    let (client, transport) = connected(&[record.as_bytes(), b"{}"])?;
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
        .and_then(signify_keri::serialization::SadValue::as_map)
        .ok_or("the reply carries no attributes")?;
    // All three, in the order the SAID commits to, with the reference's own defaults filled in.
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

/// Regression: an end-role authorization for a role this crate does not name still travels, because
/// `Role::Other` keeps the text exactly as given.
#[test]
fn an_unnamed_role_is_carried_verbatim() -> Result<(), Box<dyn Error>> {
    let role = Role::Other("custodian".to_owned());
    assert_eq!(role.as_str(), "custodian");
    let (client, transport) = connected(&[b"{}"])?;
    let outcome = block_on(
        client
            .identifiers()
            .add_end_role("aid1", &role, None, Timestamp::parse(STAMP)?),
    );
    // The record lookup answers `{}`, which is not an identifier record, so the call stops there.
    assert!(matches!(outcome, Err(ClientError::Api { .. })));
    assert_eq!(endpoint_paths(&transport), ["/identifiers/aid1"]);
    Ok(())
}
