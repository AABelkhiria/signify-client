//! Invariants of the IPEX submission endpoint.
//!
//! The address and the message's own `r` can never disagree, which is what lets one `submit` replace five.

use std::error::Error;

use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::{Sad, SadValue};
use proptest::prelude::*;
use serde_json::Value;
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_client::endpoint::ipex::IPEX_SEGMENT;
use signify_http::request::ResourcePath;
use signify_keys::acdc::ipex::IpexRoute;

const SENDER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const HOLDER: &str = "ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k";

fn routes() -> impl Strategy<Value = IpexRoute> {
    prop::sample::select(IpexRoute::ALL.to_vec())
}

fn prefixes() -> impl Strategy<Value = IdentifierPrefix> {
    "[A-Za-z0-9_-]{43}".prop_filter_map("not a prefix", |body| {
        IdentifierPrefix::from_qb64(&format!("E{body}")).ok()
    })
}

fn aliases() -> impl Strategy<Value = String> {
    prop_oneof![
        "[\\PC]{1,48}",
        Just("a/b".to_owned()),
        Just("../identifiers".to_owned()),
        Just("a?b=c".to_owned()),
        Just("a#b".to_owned()),
        Just("multisig".to_owned()),
    ]
}

fn body(route: IpexRoute, attachment: &str, recipients: &[String]) -> Result<String, Box<dyn Error>> {
    let mut document = Sad::new();
    document.insert("exn", SadValue::Map(Sad::new()))?;
    document.insert("sigs", SadValue::Array(vec![SadValue::text("AAB")]))?;
    if matches!(route, IpexRoute::Offer | IpexRoute::Grant | IpexRoute::Admit) {
        document.insert("atc", attachment.to_owned())?;
    }
    document.insert(
        "rec",
        SadValue::Array(recipients.iter().cloned().map(SadValue::Text).collect()),
    )?;
    Ok(String::from_utf8(document.to_json_bytes()?)?)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn a_route_always_addresses_its_own_resource(route in routes(), alias in aliases()) {
        let segment = route.as_str().trim_start_matches("/ipex/");
        let path = ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(&alias)
            .segment(IPEX_SEGMENT)
            .segment(segment)
            .build()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let parts: Vec<&str> = path.path().split('/').skip(1).collect();
        prop_assert_eq!(parts.len(), 4);
        prop_assert_eq!(parts.first().copied(), Some(IDENTIFIERS_SEGMENT));
        prop_assert_eq!(parts.get(2).copied(), Some(IPEX_SEGMENT));
        prop_assert_eq!(parts.get(3).copied(), Some(segment));
        prop_assert_eq!(path.query(), None);
        prop_assert!(!path.as_str().contains('#'));
        prop_assert!(path.as_str().ends_with(route.as_str()));
    }

    #[test]
    fn an_alias_is_always_one_encoded_segment(alias in aliases()) {
        let path = ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(&alias)
            .segment(IPEX_SEGMENT)
            .segment("grant")
            .build()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let parts: Vec<&str> = path.path().split('/').skip(1).collect();
        prop_assert_eq!(parts.len(), 4);
        let encoded = parts.get(1).copied().unwrap_or_default();
        for separator in ['/', '?', '#'] {
            prop_assert!(!encoded.contains(separator), "an encoded alias still carries {}", separator);
        }
    }

    #[test]
    fn the_route_alone_decides_whether_a_body_carries_an_attachment(
        route in routes(),
        attachment in "[-A-Za-z0-9_]{0,64}",
        recipient in prefixes(),
    ) {
        let address = recipient.qb64().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let rendered = body(route, &attachment, &[address])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let document: Value =
            serde_json::from_str(&rendered).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let fields = document.as_object().ok_or_else(|| TestCaseError::fail("not an object"))?;

        let carries = matches!(route, IpexRoute::Offer | IpexRoute::Grant | IpexRoute::Admit);
        prop_assert_eq!(fields.len(), if carries { 4 } else { 3 });
        prop_assert_eq!(fields.contains_key("atc"), carries);
        for label in ["exn", "sigs", "rec"] {
            prop_assert!(fields.contains_key(label), "the body lacks {}", label);
        }
        let opens_with_the_message = rendered.starts_with("{\"exn\":{},\"sigs\":[\"AAB\"],");
        let ends_with_the_recipients = rendered.ends_with("]}");
        prop_assert!(opens_with_the_message);
        prop_assert!(ends_with_the_recipients);
    }

    #[test]
    fn a_recipient_list_is_carried_verbatim(
        recipients in prop::collection::vec(prefixes(), 1..8),
    ) {
        let addresses: Vec<String> = recipients
            .iter()
            .map(|recipient| recipient.qb64().unwrap_or_default())
            .collect();
        let rendered = body(IpexRoute::Grant, "", &addresses)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let document: Value =
            serde_json::from_str(&rendered).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let sent = document
            .get("rec")
            .and_then(Value::as_array)
            .ok_or_else(|| TestCaseError::fail("no recipient list"))?;
        prop_assert_eq!(sent.len(), addresses.len());
        for (position, address) in addresses.iter().enumerate() {
            prop_assert_eq!(sent.get(position).and_then(Value::as_str), Some(address.as_str()));
        }
    }

    #[test]
    fn nothing_that_is_not_a_prefix_is_a_recipient(text in "[\\PC]{0,48}") {
        if IdentifierPrefix::from_qb64(&text).is_ok() {
            let prefix = IdentifierPrefix::from_qb64(&text)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let encoded = prefix.qb64().map_err(|error| TestCaseError::fail(error.to_string()))?;
            prop_assert_eq!(encoded, text);
        } else {
            prop_assert!(text.contains('/') || text.contains('"') || text.len() != 44 || !text.is_ascii());
        }
    }
}

// --- Named regressions ---
#[test]
fn every_route_segment_is_the_last_component_of_the_route_itself() {
    for route in IpexRoute::ALL {
        let segment = route.as_str().trim_start_matches("/ipex/");
        assert!(!segment.contains('/'), "{route} has a multi-part segment");
        assert_eq!(route.as_str(), format!("/{IPEX_SEGMENT}/{segment}"));
    }
    assert_eq!(IpexRoute::ALL.len(), 5);
}

#[test]
fn the_two_attachmentless_routes_are_apply_and_agree() {
    let carrying: Vec<IpexRoute> = IpexRoute::ALL
        .into_iter()
        .filter(|route| body(*route, "-AAB", &[HOLDER.to_owned()]).is_ok_and(|text| text.contains("atc")))
        .collect();
    assert_eq!(carrying, vec![IpexRoute::Offer, IpexRoute::Grant, IpexRoute::Admit]);
}

#[test]
fn an_empty_attachment_is_still_written_where_the_route_carries_one() -> Result<(), Box<dyn Error>> {
    let rendered = body(IpexRoute::Offer, "", &[HOLDER.to_owned()])?;
    assert!(rendered.contains(r#""atc":"""#));
    assert_eq!(
        rendered,
        format!(r#"{{"exn":{{}},"sigs":["AAB"],"atc":"","rec":["{HOLDER}"]}}"#)
    );
    Ok(())
}

#[test]
fn an_apply_body_omits_the_field_entirely_rather_than_emptying_it() -> Result<(), Box<dyn Error>> {
    let rendered = body(IpexRoute::Apply, "ignored", &[HOLDER.to_owned()])?;
    assert!(!rendered.contains("atc"));
    assert_eq!(rendered, format!(r#"{{"exn":{{}},"sigs":["AAB"],"rec":["{HOLDER}"]}}"#));
    Ok(())
}

#[test]
fn a_sender_alias_holding_a_slash_stays_one_segment() -> Result<(), Box<dyn Error>> {
    let path = ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment("a/b")
        .segment(IPEX_SEGMENT)
        .segment("apply")
        .build()?;
    assert_eq!(path.as_str(), "/identifiers/a%2Fb/ipex/apply");
    let plain = ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment("multisig")
        .segment(IPEX_SEGMENT)
        .segment("apply")
        .build()?;
    assert_eq!(plain.as_str(), "/identifiers/multisig/ipex/apply");
    assert!(IdentifierPrefix::from_qb64(SENDER).is_ok());
    Ok(())
}
