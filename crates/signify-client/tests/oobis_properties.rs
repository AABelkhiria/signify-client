//! Invariants of the OOBI endpoint family.
//!
//! Four raw-interpolated values that can never reshape an address, and an OOBI preserved byte for byte.

use std::error::Error;

use keri_protocol::prefix::IdentifierPrefix;
use keria_types::api::{EndRole, Oobi, Role};
use proptest::prelude::*;
use serde_json::{Value, json};
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_client::endpoint::oobis::{
    DEFAULT_ROLE, END_ROLES_SEGMENT, OOBIS_SEGMENT, OobiResolution, RESOLUTIONS_SEGMENT, ROLE_PARAMETER,
};
use signify_http::request::ResourcePath;
use signify_http::transport::RequestUrl;

const GROUP_AID: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";

fn prefixes() -> impl Strategy<Value = IdentifierPrefix> {
    "[A-Za-z0-9_-]{43}".prop_filter_map("not a prefix", |body| {
        IdentifierPrefix::from_qb64(&format!("E{body}")).ok()
    })
}

fn hostile_text() -> impl Strategy<Value = String> {
    prop_oneof![
        "[\\PC]{0,48}",
        Just("a/b?c=d".to_owned()),
        Just("../identifiers".to_owned()),
        Just("..".to_owned()),
        Just("agent&extra=1".to_owned()),
        Just("?role=witness".to_owned()),
        Just("#fragment".to_owned()),
        Just(String::new()),
    ]
}

fn roles() -> impl Strategy<Value = Role> {
    prop_oneof![
        proptest::sample::select(Role::DECLARED.to_vec()),
        hostile_text().prop_map(Role::Other),
    ]
}

fn oobi_urls() -> impl Strategy<Value = RequestUrl> {
    (
        prop_oneof![Just("http"), Just("https")],
        "[a-z][a-z0-9.-]{0,24}",
        proptest::option::of(1_u16..=65_535),
        "(/[A-Za-z0-9._~%!$&'()*+,;=:@-]{0,16}){0,4}",
        proptest::option::of("[A-Za-z0-9=&_-]{0,24}"),
    )
        .prop_filter_map("not a URL", |(scheme, host, port, path, query)| {
            let authority = port.map_or_else(|| host.clone(), |port| format!("{host}:{port}"));
            let query = query.map(|query| format!("?{query}")).unwrap_or_default();
            RequestUrl::new(format!("{scheme}://{authority}{path}{query}")).ok()
        })
}

fn publication_path(alias: &str, role: &Role) -> Result<ResourcePath, Box<dyn Error>> {
    Ok(ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(alias)
        .segment(OOBIS_SEGMENT)
        .parameter(ROLE_PARAMETER, role.as_str())
        .build()?)
}

fn end_role_path(identifier: &IdentifierPrefix, role: Option<&Role>) -> Result<ResourcePath, Box<dyn Error>> {
    let mut builder = ResourcePath::builder()
        .segment(END_ROLES_SEGMENT)
        .segment(&identifier.qb64()?);
    if let Some(role) = role {
        builder = builder.segment(role.as_str());
    }
    Ok(builder.build()?)
}

const PATH_DELIMITERS: [char; 3] = ['/', '?', '#'];

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn an_alias_is_always_exactly_one_path_segment(alias in hostile_text(), role in roles()) {
        let path = publication_path(&alias, &role).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let route = path.path();
        let opening = format!("/{IDENTIFIERS_SEGMENT}/");
        let closing = format!("/{OOBIS_SEGMENT}");
        prop_assert!(route.starts_with(&opening));
        prop_assert!(route.ends_with(&closing));
        prop_assert_eq!(route.split('/').count(), 4);
        let middle = route.split('/').nth(2).unwrap_or_default();
        for delimiter in PATH_DELIMITERS {
            prop_assert!(!middle.contains(delimiter), "an alias introduced {}", delimiter);
        }
    }

    #[test]
    fn a_role_writes_exactly_one_query_parameter(alias in "[a-z0-9]{1,12}", role in roles()) {
        let path = publication_path(&alias, &role).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let query = path.query().unwrap_or_default();
        let opening = format!("{ROLE_PARAMETER}=");
        prop_assert!(query.starts_with(&opening));
        prop_assert_eq!(query.matches('&').count(), 0);
        prop_assert_eq!(query.matches('=').count(), 1);
        prop_assert_eq!(path.path(), format!("/{IDENTIFIERS_SEGMENT}/{alias}/{OOBIS_SEGMENT}"));
    }

    #[test]
    fn a_prefix_reaches_the_path_unchanged(identifier in prefixes()) {
        let text = identifier.qb64().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let path = end_role_path(&identifier, None).map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(path.as_str(), format!("/{END_ROLES_SEGMENT}/{text}"));
        prop_assert_eq!(path.query(), None);
        prop_assert_eq!(path.path().split('/').count(), 3);
    }

    #[test]
    fn a_role_filter_never_leaves_its_segment(identifier in prefixes(), role in roles()) {
        let filtered = end_role_path(&identifier, Some(&role))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let unfiltered = end_role_path(&identifier, None)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert!(filtered.as_str().starts_with(unfiltered.as_str()));
        prop_assert_eq!(filtered.path().split('/').count(), 4);
        prop_assert_eq!(filtered.query(), None);
        let last = filtered.path().split('/').next_back().unwrap_or_default();
        for delimiter in PATH_DELIMITERS {
            prop_assert!(!last.contains(delimiter), "a role filter introduced {}", delimiter);
        }
    }

    #[test]
    fn a_resolution_body_preserves_its_url_and_tells_an_absent_alias_from_an_empty_one(
        url in oobi_urls(),
        alias in proptest::option::of(hostile_text()),
    ) {
        let mut resolution = OobiResolution::new(url.clone());
        if let Some(alias) = &alias {
            resolution = resolution.with_alias(alias.clone());
        }
        let bytes = resolution.body().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let decoded: Value =
            serde_json::from_slice(&bytes).map_err(|error| TestCaseError::fail(error.to_string()))?;

        prop_assert_eq!(decoded.get("url").and_then(Value::as_str), Some(url.as_str()));
        match &alias {
            None => prop_assert!(decoded.get("oobialias").is_none()),
            Some(alias) => prop_assert_eq!(decoded.get("oobialias").and_then(Value::as_str), Some(alias.as_str())),
        }
        prop_assert_eq!(
            decoded.as_object().map(serde_json::Map::len),
            Some(if alias.is_some() { 2 } else { 1 })
        );
        let path = ResourcePath::builder()
            .segment(RESOLUTIONS_SEGMENT)
            .build()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(path.as_str(), "/oobis");
    }

    #[test]
    fn an_oobi_listing_round_trips_its_role(role in roles(), urls in proptest::collection::vec("[a-z:/.]{0,32}", 0..4)) {
        let document = json!({ "role": role.as_str(), "oobis": urls }).to_string();
        let decoded: Oobi =
            serde_json::from_str(&document).map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(&decoded.role, &role);
        prop_assert_eq!(decoded.oobis.len(), urls.len());
        let re_encoded =
            serde_json::to_string(&decoded).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let again: Oobi =
            serde_json::from_str(&re_encoded).map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(again, decoded);
    }

    #[test]
    fn an_end_role_needs_every_declared_field(
        cid in prefixes(),
        eid in prefixes(),
        role in roles(),
        drop_field in 0_usize..4,
    ) {
        let cid = cid.qb64().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let eid = eid.qb64().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let mut document = json!({ "cid": cid, "role": role.as_str(), "eid": eid });
        let dropped = ["cid", "role", "eid"].get(drop_field).copied();
        if let (Some(field), Some(object)) = (dropped, document.as_object_mut()) {
            object.remove(field);
        }
        let decoded = serde_json::from_str::<EndRole>(&document.to_string());
        if dropped.is_some() {
            prop_assert!(decoded.is_err(), "a record missing a declared field was accepted");
        } else {
            let record = decoded.map_err(|error| TestCaseError::fail(error.to_string()))?;
            prop_assert_eq!(record.cid, cid);
            prop_assert_eq!(record.eid, eid);
            prop_assert_eq!(record.role, role);
        }
    }
}

#[test]
fn the_default_role_produces_the_same_request_as_naming_it() -> Result<(), Box<dyn Error>> {
    let defaulted = publication_path("delegate", &DEFAULT_ROLE)?;
    let named = publication_path("delegate", &Role::Agent)?;
    assert_eq!(defaulted.as_str(), named.as_str());
    assert_eq!(defaulted.as_str(), "/identifiers/delegate/oobis?role=agent");
    Ok(())
}

#[test]
fn a_role_holding_an_ampersand_stays_one_parameter() -> Result<(), Box<dyn Error>> {
    let role = Role::Other("agent&extra=1".to_owned());
    let path = publication_path("aid", &role)?;
    assert_eq!(path.as_str(), "/identifiers/aid/oobis?role=agent%26extra%3D1");
    assert_eq!(path.query().map(|query| query.matches('&').count()), Some(0));
    Ok(())
}

#[test]
fn a_role_filter_of_two_dots_stays_one_segment() -> Result<(), Box<dyn Error>> {
    let identifier = IdentifierPrefix::from_qb64(GROUP_AID)?;
    let role = Role::Other("..".to_owned());
    let path = end_role_path(&identifier, Some(&role))?;
    assert_eq!(path.as_str(), format!("/endroles/{GROUP_AID}/.."));
    assert_eq!(path.path().split('/').count(), 4);
    Ok(())
}

#[test]
fn an_oobi_holding_a_control_byte_is_refused() {
    for hostile in [
        "http://oobiurl.com/\n\r x",
        "http://oobiurl.com/\u{0}",
        "http://oobiurl.com/ ",
        "http://oobiurl.com/oobi#fragment",
        "",
        "not a url at all",
    ] {
        assert!(
            RequestUrl::new(hostile).is_err(),
            "{hostile:?} was accepted as an OOBI URL"
        );
    }
}

#[test]
fn an_oobi_reaches_the_body_exactly_as_supplied() -> Result<(), Box<dyn Error>> {
    for text in [
        "http://127.0.0.1:3901/oobi/ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
        "http://Example.COM/oobi/E",
        "http://example.com/a/../b",
        "http://example.com/%2e%2e/b",
        "http://example.com",
    ] {
        let url = RequestUrl::new(text)?;
        assert_eq!(url.as_str(), text);
        let body = String::from_utf8(OobiResolution::new(url).body()?)?;
        assert_eq!(body, format!(r#"{{"url":"{text}"}}"#));
    }
    Ok(())
}
