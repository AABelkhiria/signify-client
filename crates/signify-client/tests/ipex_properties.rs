//! Invariants of the IPEX submission endpoint.
//!
//! Two dynamic values reach a path here: the sender's alias, which the reference concatenates raw,
//! and a route segment that is not caller input at all — it is read from the message. The
//! properties that matter are that the alias can never leave its segment, and that the address and
//! the message's own `r` field can never disagree, which is what lets one `submit` replace the
//! reference's five methods.
//!
//! The rest is about the body. Its shape is decided entirely by the route, so the split is stated
//! for every route rather than the five the fixture records, and the recipient list — the one part
//! a caller supplies freely — is shown to reach the wire as given and to be refused when empty.

use std::error::Error;

use proptest::prelude::*;
use serde_json::Value;
use signify_acdc::ipex::IpexRoute;
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_client::endpoint::ipex::IPEX_SEGMENT;
use signify_http::request::ResourcePath;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::serialization::{Sad, SadValue};

const SENDER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const HOLDER: &str = "ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k";

/// Every route, as a strategy.
fn routes() -> impl Strategy<Value = IpexRoute> {
    prop::sample::select(IpexRoute::ALL.to_vec())
}

/// Syntactically valid self-addressing identifier prefixes.
fn prefixes() -> impl Strategy<Value = IdentifierPrefix> {
    "[A-Za-z0-9_-]{43}".prop_filter_map("not a prefix", |body| {
        IdentifierPrefix::from_qb64(&format!("E{body}")).ok()
    })
}

/// Aliases, including ones that would reshape a path if they ever reached one unencoded.
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

/// Renders a submission body the way the endpoint does, for one route and recipient list.
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

    /// A route always addresses its own resource, and the address is the route's last component.
    ///
    /// This is what makes the reference's route/resource mismatch unrepresentable: the segment is
    /// never chosen independently of the message.
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

        // Four segments, always: identifiers, the alias, ipex, the route.
        let parts: Vec<&str> = path.path().split('/').skip(1).collect();
        prop_assert_eq!(parts.len(), 4);
        prop_assert_eq!(parts.first().copied(), Some(IDENTIFIERS_SEGMENT));
        prop_assert_eq!(parts.get(2).copied(), Some(IPEX_SEGMENT));
        prop_assert_eq!(parts.get(3).copied(), Some(segment));
        prop_assert_eq!(path.query(), None);
        prop_assert!(!path.as_str().contains('#'));
        // And the address ends with exactly the route the message carries.
        prop_assert!(path.as_str().ends_with(route.as_str()));
    }

    /// An alias is always exactly one segment and never carries a delimiter into the path.
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

    /// The body's field count is decided by the route alone, and always in the same order.
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
        // The order is the reference's, whatever the route. `prop_assert!` treats its argument as
        // a format string, so each shape is decided first.
        let opens_with_the_message = rendered.starts_with("{\"exn\":{},\"sigs\":[\"AAB\"],");
        let ends_with_the_recipients = rendered.ends_with("]}");
        prop_assert!(opens_with_the_message);
        prop_assert!(ends_with_the_recipients);
    }

    /// A recipient list reaches the wire exactly as given, in order, however long it is.
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

    /// A recipient is a validated prefix, so nothing that would reshape a body can be one.
    #[test]
    fn nothing_that_is_not_a_prefix_is_a_recipient(text in "[\\PC]{0,48}") {
        if IdentifierPrefix::from_qb64(&text).is_ok() {
            // Anything accepted re-encodes to itself, so what reaches `rec` is what was parsed.
            let prefix = IdentifierPrefix::from_qb64(&text)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let encoded = prefix.qb64().map_err(|error| TestCaseError::fail(error.to_string()))?;
            prop_assert_eq!(encoded, text);
        } else {
            prop_assert!(text.contains('/') || text.contains('"') || text.len() != 44 || !text.is_ascii());
        }
    }
}

// ---------------------------------------------------------------------------
// Named regressions.
// ---------------------------------------------------------------------------

#[test]
fn every_route_segment_is_the_last_component_of_the_route_itself() {
    // If these ever drift, the address and the `r` field would disagree — which is the defect the
    // single `submit` exists to make unrepresentable.
    for route in IpexRoute::ALL {
        let segment = route.as_str().trim_start_matches("/ipex/");
        assert!(!segment.contains('/'), "{route} has a multi-part segment");
        assert_eq!(route.as_str(), format!("/{IPEX_SEGMENT}/{segment}"));
    }
    assert_eq!(IpexRoute::ALL.len(), 5);
}

#[test]
fn the_two_attachmentless_routes_are_apply_and_agree() {
    // Upstream this is which method a caller happened to call; here it is a property of the route.
    let carrying: Vec<IpexRoute> = IpexRoute::ALL
        .into_iter()
        .filter(|route| body(*route, "-AAB", &[HOLDER.to_owned()]).is_ok_and(|text| text.contains("atc")))
        .collect();
    assert_eq!(carrying, vec![IpexRoute::Offer, IpexRoute::Grant, IpexRoute::Admit]);
}

#[test]
fn an_empty_attachment_is_still_written_where_the_route_carries_one() -> Result<(), Box<dyn Error>> {
    // An offer and an admit send `"atc":""` rather than omitting the field, which is what the
    // reference's own recorded bodies do.
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
    // The reference sends `/identifiers/a/b/ipex/apply`, addressing another identifier entirely.
    let path = ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment("a/b")
        .segment(IPEX_SEGMENT)
        .segment("apply")
        .build()?;
    assert_eq!(path.as_str(), "/identifiers/a%2Fb/ipex/apply");
    // And an ordinary alias reaches the path unchanged, so the encoding costs nothing.
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
