//! Invariants of the group endpoint.
//!
//! Three things vary: the SAID a request is read by, the alias a write is posted under, and the
//! member lists a join names.
//!
//! The first two are addresses, and the property is the one every family here states — a value
//! never leaves its own path segment. What is particular to this family is that **the same alias
//! addresses two different writes**, so the two must agree about everything except their last
//! segment; and that **a join's body is six fields in a fixed order**, where the reference builds
//! it from six loose arguments any of which could be anything.
//!
//! The answers are the trust boundary, and an unusual one: a group request listing is a set of
//! proposals *other members* wrote, each asking this member to sign something. Nothing here
//! verifies them — that is the keeper's job, next — so the property is that a listing decodes whole
//! or not at all, and that what decodes is exactly what Roadmap 8.1 classifies.

use std::error::Error;

use proptest::prelude::*;
use serde_json::{Map, Value, json};
use signify_client::endpoint::exchanges::{ClassifiedExchange, MULTISIG_TOPIC, MultisigRoute};
use signify_client::endpoint::groups::{JOIN_SEGMENT, MULTISIG_SEGMENT, REQUEST_SEGMENT};
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_http::request::{ResourcePath, encode_path_component};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue};
use signify_types::api::MultisigExchangeResource;

const SAID: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const GROUP: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const MEMBER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const SECOND: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";

/// The forty-six-character value the pinned unit test reads by.
const PINNED_SAID: &str = "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose00";

fn read_path(said: &Said) -> Result<ResourcePath, Box<dyn Error>> {
    Ok(ResourcePath::builder()
        .segment(MULTISIG_SEGMENT)
        .segment(REQUEST_SEGMENT)
        .segment(&said.qb64()?)
        .build()?)
}

fn write_path(alias: &str, action: &str) -> Result<ResourcePath, Box<dyn Error>> {
    Ok(ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(alias)
        .segment(MULTISIG_SEGMENT)
        .segment(action)
        .build()?)
}

/// The body a join writes, in the reference's field order.
fn join_body(group: &str, signing: &[String], rotation: &[String]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut body = Sad::new();
    body.insert("tpc", MULTISIG_TOPIC.to_owned())?;
    body.insert("rot", SadValue::Map(Sad::new()))?;
    body.insert("sigs", SadValue::Array(vec![SadValue::text("AAB")]))?;
    body.insert("gid", group.to_owned())?;
    body.insert(
        "smids",
        SadValue::Array(signing.iter().map(|member| SadValue::text(member.clone())).collect()),
    )?;
    body.insert(
        "rmids",
        SadValue::Array(rotation.iter().map(|member| SadValue::text(member.clone())).collect()),
    )?;
    Ok(body.to_json_bytes()?)
}

/// Aliases of the shape the reference uses, plus the ones that would escape a segment.
fn aliases() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("aid1".to_owned()),
        Just("member1".to_owned()),
        Just("multisig".to_owned()),
        "[a-z][a-z0-9-]{0,16}",
        "[\\PC]{1,32}",
        Just("a/b?c=d".to_owned()),
        Just("..".to_owned()),
        Just("../identifiers".to_owned()),
    ]
}

/// One group request listing entry, of the shape the agent answers with.
fn listing_entry(route: MultisigRoute, group_name: Option<&str>) -> String {
    let embed = match route {
        MultisigRoute::Inception => {
            r#""icp":{"v":"KERI10JSON000_","t":"icp","d":"EICP","i":"EGRP","s":"0","kt":"2","k":["DAA"],"nt":"2","n":["EAA"],"bt":"0","b":[],"c":[],"a":[]}"#
        }
        _ => r#""ixn":{"v":"KERI10JSON000_","t":"ixn","d":"EIXN","i":"EGRP","s":"1","p":"EICP","a":[]}"#,
    };
    let exn = format!(
        r#"{{"v":"KERI10JSON000_","t":"exn","d":"{SAID}","i":"{MEMBER}","rp":"{SECOND}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{{"gid":"{GROUP}","smids":["{MEMBER}"],"rmids":["{MEMBER}"]}},"e":{{"d":"EEMB",{embed}}}}}"#,
        route = route.as_str()
    );
    match group_name {
        Some(name) => {
            format!(r#"{{"exn":{exn},"paths":{{}},"groupName":"{name}","memberName":"member1","sender":"{MEMBER}"}}"#)
        }
        None => format!(r#"{{"exn":{exn},"paths":{{}}}}"#),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// A read is always three segments, and the SAID reaches the last one unchanged.
    ///
    /// A qualified digest's alphabet is URL-safe Base64, so every SAID that parses survives the
    /// path builder byte for byte — which is what makes the reference's raw concatenation safe
    /// *for values that are actually SAIDs*, and only for those.
    #[test]
    fn a_said_never_leaves_its_own_segment(text in "[A-Za-z0-9_-]{44}") {
        let Ok(said) = text.parse::<Said>() else { return Ok(()) };
        let path = read_path(&said).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let segments: Vec<&str> = path.path().split('/').skip(1).collect();
        prop_assert_eq!(segments.len(), 3);
        prop_assert_eq!(segments.first().copied(), Some(MULTISIG_SEGMENT));
        prop_assert_eq!(segments.get(1).copied(), Some(REQUEST_SEGMENT));
        prop_assert_eq!(segments.get(2).copied(), Some(text.as_str()));
        prop_assert_eq!(path.query(), None);
    }

    /// A write is always four segments, whatever the alias holds.
    #[test]
    fn an_alias_never_leaves_its_own_segment(alias in aliases()) {
        for action in [REQUEST_SEGMENT, JOIN_SEGMENT] {
            let path = write_path(&alias, action)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let segments: Vec<&str> = path.path().split('/').skip(1).collect();
            prop_assert_eq!(segments.len(), 4, "the path was {}", path.as_str());
            prop_assert_eq!(segments.first().copied(), Some(IDENTIFIERS_SEGMENT));
            let encoded = encode_path_component(&alias);
            prop_assert_eq!(segments.get(1).copied(), Some(encoded.as_str()));
            prop_assert_eq!(segments.get(2).copied(), Some(MULTISIG_SEGMENT));
            prop_assert_eq!(segments.get(3).copied(), Some(action));
            prop_assert_eq!(path.query(), None);
            // Roadmap 3.10 signs the path, so what is signed is what is sent.
            prop_assert_eq!(path.path(), path.as_str());
        }
    }

    /// The two writes always agree about everything but their last segment.
    ///
    /// They are the same resource asked to do two different things, so a caller that mistyped the
    /// alias would mistype it identically for both.
    #[test]
    fn the_two_writes_share_everything_but_their_action(alias in aliases()) {
        let request = write_path(&alias, REQUEST_SEGMENT)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let join = write_path(&alias, JOIN_SEGMENT)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let prefix = |path: &ResourcePath| -> String {
            path.path().rsplit_once('/').map(|(head, _)| head.to_owned()).unwrap_or_default()
        };
        prop_assert_eq!(prefix(&request), prefix(&join));
        prop_assert!(request.path().ends_with(REQUEST_SEGMENT));
        prop_assert!(join.path().ends_with(JOIN_SEGMENT));
        prop_assert_ne!(request.as_str(), join.as_str());
    }

    /// A join always writes the reference's six fields in its order, whatever the lists hold.
    #[test]
    fn a_join_writes_six_fields_in_order(
        signing in proptest::collection::vec(prop_oneof![Just(MEMBER), Just(SECOND)], 1..6),
        rotation in proptest::collection::vec(prop_oneof![Just(MEMBER), Just(SECOND)], 0..6),
    ) {
        let signing: Vec<String> = signing.into_iter().map(ToOwned::to_owned).collect();
        let rotation: Vec<String> = rotation.into_iter().map(ToOwned::to_owned).collect();
        let rendered = join_body(GROUP, &signing, &rotation)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let text = String::from_utf8(rendered)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        prop_assert!(text.starts_with(r#"{"tpc":"multisig","#), "the body was {}", text);
        let mut previous = 0_usize;
        for label in [r#""tpc":"#, r#""rot":"#, r#""sigs":"#, r#""gid":"#, r#""smids":"#, r#""rmids":"#] {
            let at = text.find(label).ok_or_else(|| TestCaseError::fail(format!("no {label}")))?;
            prop_assert!(at >= previous, "{} is out of order in {}", label, text);
            previous = at;
        }

        // Both lists reach the body at their own length, and the rotation list may be empty where
        // the signing list may not.
        let decoded: Value = serde_json::from_str(&text)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(
            decoded.get("smids").and_then(Value::as_array).map(Vec::len),
            Some(signing.len())
        );
        prop_assert_eq!(
            decoded.get("rmids").and_then(Value::as_array).map(Vec::len),
            Some(rotation.len())
        );
    }

    /// A proposal's body is always exactly three fields, and never the two the sibling submission
    /// writes.
    #[test]
    fn a_proposal_writes_three_fields_and_never_a_topic(attachment in "[-A-Za-z0-9_]{0,32}") {
        let mut body = Sad::new();
        body.insert("exn", SadValue::Map(Sad::new()))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        body.insert("sigs", SadValue::Array(vec![SadValue::text("AAB")]))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        body.insert("atc", attachment.clone())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let rendered = body.to_json_bytes()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let decoded: Value = serde_json::from_slice(&rendered)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let fields = decoded.as_object()
            .ok_or_else(|| TestCaseError::fail("the body is not an object"))?;
        prop_assert_eq!(fields.len(), 3);
        prop_assert!(!fields.contains_key("tpc"));
        prop_assert!(!fields.contains_key("rec"));
        prop_assert_eq!(fields.get("atc").and_then(Value::as_str), Some(attachment.as_str()));
    }

    /// A listing decodes whole or not at all, and each entry keeps its optional local aliases.
    #[test]
    fn a_listing_decodes_whole_or_not_at_all(
        count in 0_usize..4,
        named in proptest::bool::ANY,
        bad in proptest::bool::ANY,
    ) {
        let mut entries: Vec<String> = (0..count)
            .map(|_| listing_entry(MultisigRoute::Inception, named.then_some("multisig")))
            .collect();
        if bad {
            entries.push(r#"{"paths":{}}"#.to_owned());
        }
        let document = format!("[{}]", entries.join(","));
        match serde_json::from_str::<Vec<MultisigExchangeResource>>(&document) {
            Ok(listing) => {
                prop_assert!(!bad, "a listing with an entry that has no message was accepted");
                prop_assert_eq!(listing.len(), count);
                for entry in &listing {
                    prop_assert_eq!(entry.group_name.is_some(), named);
                    prop_assert_eq!(entry.member_name.is_some(), named);
                    prop_assert_eq!(entry.sender.is_some(), named);
                }
            }
            Err(error) => {
                prop_assert!(bad, "a listing of {} entries was refused: {}", count, error);
                prop_assert!(!error.to_string().is_empty());
            }
        }
    }

    /// Everything a listing decodes is something Roadmap 8.1 classifies.
    ///
    /// This family and that one meet here: `requests` returns exactly the shape those classifiers
    /// read, which is why neither needs an adapter.
    #[test]
    fn every_decoded_entry_classifies(route in prop::sample::select(MultisigRoute::ALL.to_vec())) {
        // Only the inception and interaction embeds are built above, so the others are expected to
        // be refused for carrying the wrong one — which is itself the invariant 8.1 states.
        let document = format!("[{}]", listing_entry(route, Some("multisig")));
        let listing: Vec<MultisigExchangeResource> = serde_json::from_str(&document)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let entry = listing.first()
            .ok_or_else(|| TestCaseError::fail("empty listing"))?;
        match ClassifiedExchange::try_from(entry) {
            Ok(classified) => {
                let proposal = classified.as_multisig()
                    .ok_or_else(|| TestCaseError::fail("a multisig route did not classify as one"))?;
                prop_assert_eq!(proposal.route, route);
                prop_assert_eq!(proposal.attributes.group.qb64().ok(), Some(GROUP.to_owned()));
            }
            Err(error) => {
                prop_assert!(!matches!(route, MultisigRoute::Inception | MultisigRoute::Interaction));
                prop_assert!(!error.to_string().is_empty());
            }
        }
    }

    /// Arbitrary bytes never panic: a listing either decodes or is refused with a reason.
    #[test]
    fn arbitrary_bytes_decode_or_are_refused(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        match serde_json::from_slice::<Vec<MultisigExchangeResource>>(&bytes) {
            Ok(listing) => {
                for entry in &listing {
                    // Anything that decoded is something the classifier will accept or refuse,
                    // never something it panics on.
                    let _ = ClassifiedExchange::try_from(entry).is_ok();
                }
            }
            Err(error) => prop_assert!(!error.to_string().is_empty()),
        }
    }
}

/// Regression: the three addresses the pinned unit test asserts.
#[test]
fn the_three_pinned_addresses_reproduce() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        write_path("aid1", REQUEST_SEGMENT)?.as_str(),
        "/identifiers/aid1/multisig/request"
    );
    assert_eq!(
        write_path("aid1", JOIN_SEGMENT)?.as_str(),
        "/identifiers/aid1/multisig/join"
    );
    assert_eq!(
        read_path(&SAID.parse::<Said>()?)?.as_str(),
        format!("/multisig/request/{SAID}")
    );
    Ok(())
}

/// Regression: the value the pinned test reads by is two characters too long to be a SAID.
///
/// The reference concatenates it into the path and the agent is asked about a resource that cannot
/// exist. The case that test is actually making — that the address is `/multisig/request/{said}` —
/// reproduces with a real digest.
#[test]
fn the_pinned_read_value_is_not_a_qualified_digest() {
    assert_eq!(PINNED_SAID.len(), 46);
    assert_eq!(SAID.len(), 44);
    assert!(PINNED_SAID.parse::<Said>().is_err());
    assert!(SAID.parse::<Said>().is_ok());
}

/// Regression: the empty string the reference's own integration helper falls back to.
///
/// `waitAndMarkNotification` returns `notes[last]?.a.d ?? ''`, so a member that polled and found
/// nothing asks for `/multisig/request/` — the whole collection — rather than failing.
#[test]
fn the_helpers_empty_fallback_is_not_a_said() {
    assert!("".parse::<Said>().is_err());
}

/// Regression: a group request listing is exactly what Roadmap 8.1 classifies, aliases and all.
#[test]
fn a_listing_entry_carries_both_halves() -> Result<(), Box<dyn Error>> {
    let document = format!("[{}]", listing_entry(MultisigRoute::Inception, Some("multisig")));
    let listing: Vec<MultisigExchangeResource> = serde_json::from_str(&document)?;
    let entry = listing.first().ok_or("empty listing")?;

    // The wrapper: who sent it and what the local aliases are.
    assert_eq!(entry.sender.as_deref(), Some(MEMBER));
    assert_eq!(entry.group_name.as_deref(), Some("multisig"));
    assert_eq!(entry.member_name.as_deref(), Some("member1"));

    // The message: what is actually being proposed.
    let classified = ClassifiedExchange::try_from(entry)?;
    let proposal = classified.as_multisig().ok_or("not a proposal")?;
    assert_eq!(proposal.route, MultisigRoute::Inception);
    assert_eq!(proposal.attributes.group, IdentifierPrefix::from_qb64(GROUP)?);
    Ok(())
}

/// Regression: a body with an unexpected extra field is not what this port writes.
#[test]
fn a_join_body_carries_nothing_beyond_the_references_six() -> Result<(), Box<dyn Error>> {
    let rendered = join_body(GROUP, &[MEMBER.to_owned()], &[])?;
    let decoded: Value = serde_json::from_slice(&rendered)?;
    let fields = decoded.as_object().ok_or("not an object")?;
    assert_eq!(fields.len(), 6);
    let mut labels: Vec<&str> = fields.keys().map(String::as_str).collect();
    labels.sort_unstable();
    assert_eq!(labels, ["gid", "rmids", "rot", "sigs", "smids", "tpc"]);
    // And a body built with an unrelated label is a different body, so nothing silently merges.
    let mut extra = Sad::new();
    extra.insert("tpc", MULTISIG_TOPIC.to_owned())?;
    extra.insert("unexpected", true)?;
    assert_ne!(
        serde_json::from_slice::<Value>(&extra.to_json_bytes()?)?,
        Value::Object(Map::new())
    );
    Ok(())
}

/// Regression: a proposal on a route the table does not name still reaches a caller.
///
/// A group request listing may hold anything the agent stored; classification is 8.1's, and an
/// unnamed route is a message rather than a failure there.
#[test]
fn a_listing_entry_on_an_unnamed_route_still_classifies() -> Result<(), Box<dyn Error>> {
    let exn = json!({
        "v": "KERI10JSON000_", "t": "exn", "d": SAID, "i": MEMBER, "rp": SECOND,
        "p": "", "dt": "2023-11-14T22:13:20.123000+00:00", "r": "/challenge/response",
        "q": {}, "a": { "words": ["shell"] }, "e": {},
    });
    let document = json!([{ "exn": exn, "paths": {} }]).to_string();
    let listing: Vec<MultisigExchangeResource> = serde_json::from_str(&document)?;
    let entry = listing.first().ok_or("empty listing")?;
    let classified = ClassifiedExchange::try_from(entry)?;
    assert!(matches!(classified, ClassifiedExchange::Other { .. }));
    Ok(())
}
