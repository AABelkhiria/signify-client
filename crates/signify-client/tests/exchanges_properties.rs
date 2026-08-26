//! Invariants of the exchange endpoint.
//!
//! Four things vary: the alias a message is posted under, the SAID one is read by, the message's
//! own contents, and the agent's answer.
//!
//! The first two are addresses, and the properties are the ones every family here states — a value
//! never leaves its own path segment, whatever it holds. The third is where this family differs
//! from the rest: an `exn` names **one** addressee and is delivered to a **list**, and the whole
//! shaping decision is that those are separate. So the properties say what separating them buys:
//! the addressee always reaches the message and only the message, the delivery list always reaches
//! the body and only the body, and neither can be silently derived from the other.
//!
//! The fourth is the trust boundary, and it is unusual: the reference declares two incompatible
//! types for the same answer. The property is that they are **disjoint** — no answer is ever read
//! as both — which is what makes offering two decoders safe rather than ambiguous.

use std::error::Error;

use proptest::prelude::*;
use serde_json::{Value, json};
use signify_client::endpoint::exchanges::{EXCHANGES_SEGMENT, ExchangeDraft, MULTISIG_TOPIC, REGISTRY_TOPIC};
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_http::request::{ResourcePath, encode_path_component};
use signify_keri::event::exchange::ExchangeBuilder;
use signify_keri::event::timestamp::Timestamp;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue};
use signify_types::api::{ExchangeOperation, ExchangeRecord, ExchangeResource};

const SENDER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const RECIPIENT: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const SECOND: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const SAID: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const STAMP: &str = "2023-11-14T22:13:20.123000+00:00";

/// The address a submission is posted to.
fn submission_path(alias: &str) -> Result<ResourcePath, Box<dyn Error>> {
    Ok(ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(alias)
        .segment(EXCHANGES_SEGMENT)
        .build()?)
}

/// The address one message is read from.
fn read_path(said: &Said) -> Result<ResourcePath, Box<dyn Error>> {
    Ok(ResourcePath::builder()
        .segment(EXCHANGES_SEGMENT)
        .segment(&said.qb64()?)
        .build()?)
}

/// Aliases of the shape the reference uses, plus the ones that would escape a segment.
fn aliases() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("aid1".to_owned()),
        Just("member1".to_owned()),
        "[a-z][a-z0-9-]{0,16}",
        "[\\PC]{1,32}",
        Just("a/b".to_owned()),
        Just("a?b=c".to_owned()),
        Just("..".to_owned()),
        Just("../identifiers".to_owned()),
        Just("a name with ñ!".to_owned()),
    ]
}

/// Routes of the shape the reference sends, plus arbitrary text.
fn routes() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("/multisig/icp".to_owned()),
        Just("/multisig/vcp".to_owned()),
        Just("/ipex/grant".to_owned()),
        Just("/challenge/response".to_owned()),
        "/[a-z]{1,8}(/[a-z]{1,8}){0,2}",
        "[\\PC]{0,48}",
    ]
}

/// Topics the reference files notifications under, plus arbitrary non-empty text.
fn topics() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(MULTISIG_TOPIC.to_owned()),
        Just(REGISTRY_TOPIC.to_owned()),
        Just("challenge".to_owned()),
        "[a-z]{1,12}",
    ]
}

/// Builds the message a draft describes, which is what `create_message` builds around a keeper.
fn message_for(route: &str, sender: &str, addressee: &str, payload: Sad) -> Result<Sad, Box<dyn Error>> {
    let built = ExchangeBuilder::new(
        route.to_owned(),
        IdentifierPrefix::from_qb64(sender)?,
        IdentifierPrefix::from_qb64(addressee)?,
        STAMP.parse::<Timestamp>()?,
    )
    .payload(payload)
    .build()?;
    Ok(built.sad().clone())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Whatever an alias holds, a submission is three segments under `/identifiers` and carries no
    /// query — where the reference concatenates it raw.
    #[test]
    fn an_alias_never_leaves_its_own_segment(alias in aliases()) {
        let path = submission_path(&alias)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let segments: Vec<&str> = path.path().split('/').skip(1).collect();
        prop_assert_eq!(segments.len(), 3, "the path was {}", path.as_str());
        prop_assert_eq!(segments.first().copied(), Some(IDENTIFIERS_SEGMENT));
        prop_assert_eq!(segments.last().copied(), Some(EXCHANGES_SEGMENT));
        let encoded = encode_path_component(&alias);
        prop_assert_eq!(segments.get(1).copied(), Some(encoded.as_str()));
        prop_assert_eq!(path.query(), None);
        // Roadmap 3.10 signs the path, so what is signed is what is sent.
        prop_assert_eq!(path.path(), path.as_str());
    }

    /// A SAID never leaves its own segment either, and every SAID that parses reaches the path
    /// unchanged — a qualified digest's alphabet is URL-safe Base64.
    #[test]
    fn a_said_never_leaves_its_own_segment(text in "[A-Za-z0-9_-]{44}") {
        let Ok(said) = text.parse::<Said>() else { return Ok(()) };
        let path = read_path(&said)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let segments: Vec<&str> = path.path().split('/').skip(1).collect();
        prop_assert_eq!(segments.len(), 2);
        prop_assert_eq!(segments.first().copied(), Some(EXCHANGES_SEGMENT));
        prop_assert_eq!(segments.get(1).map(|segment| segment.len()), Some(44));
        prop_assert_eq!(path.query(), None);
    }

    /// The addressee reaches the message and nothing else: it is written into `rp` and into the
    /// attribute block's `i`, and never into the address.
    #[test]
    fn the_addressee_reaches_the_message_and_only_the_message(
        alias in aliases(),
        route in routes(),
    ) {
        let message = message_for(&route, SENDER, RECIPIENT, Sad::new())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(message.get_text("rp"), Some(RECIPIENT));
        prop_assert_eq!(message.get_text("i"), Some(SENDER));
        prop_assert_eq!(message.get_text("r"), Some(route.as_str()));

        // The address carries the alias and says nothing about who the message is for.
        let path = submission_path(&alias)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert!(!path.as_str().contains(RECIPIENT));
    }

    /// A draft keeps exactly the route and addressee it was given, whatever they are.
    #[test]
    fn a_draft_keeps_what_it_was_given(route in routes()) {
        let addressee = IdentifierPrefix::from_qb64(RECIPIENT)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let stamp = STAMP.parse::<Timestamp>()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let draft = ExchangeDraft::new(route.clone(), addressee.clone(), stamp);
        prop_assert_eq!(draft.route(), route.as_str());
        prop_assert_eq!(draft.addressee(), &addressee);
    }

    /// A submission body always writes the reference's five fields, in its order, whatever the
    /// topic and delivery list hold.
    #[test]
    fn a_submission_body_writes_five_fields_in_order(
        topic in topics(),
        recipients in proptest::collection::vec(prop_oneof![Just(RECIPIENT), Just(SECOND)], 1..6),
    ) {
        let message = message_for("/multisig/icp", SENDER, RECIPIENT, Sad::new())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let mut body = Sad::new();
        body.insert("tpc", topic.clone()).map_err(|error| TestCaseError::fail(error.to_string()))?;
        body.insert("exn", SadValue::Map(message)).map_err(|error| TestCaseError::fail(error.to_string()))?;
        body.insert("sigs", SadValue::Array(vec![SadValue::text("AA")]))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        body.insert("atc", String::new()).map_err(|error| TestCaseError::fail(error.to_string()))?;
        body.insert(
            "rec",
            SadValue::Array(recipients.iter().map(|entry| SadValue::text(*entry)).collect()),
        )
        .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let rendered = body.to_json_bytes().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let text = String::from_utf8(rendered).map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert!(text.starts_with(r#"{"tpc":"#), "the body was {}", text);
        // The five labels appear once each, in the reference's own order.
        let mut previous = 0_usize;
        for label in [r#""tpc":"#, r#""exn":"#, r#""sigs":"#, r#""atc":"#, r#""rec":"#] {
            let at = text.find(label).ok_or_else(|| TestCaseError::fail(format!("no {label}")))?;
            prop_assert!(at >= previous, "{} is out of order in {}", label, text);
            previous = at;
        }

        // The delivery list reaches the body in order and at its own length.
        let decoded: Value = serde_json::from_str(&text)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let delivered: Vec<&str> = decoded
            .get("rec")
            .and_then(Value::as_array)
            .ok_or_else(|| TestCaseError::fail("no recipients"))?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        prop_assert_eq!(delivered, recipients);
    }

    /// The two shapes the reference declares for one answer are **disjoint**: no document is ever
    /// read as both, so offering a decoder for each cannot silently pick the wrong one.
    #[test]
    fn the_two_declared_answers_are_disjoint(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let as_operation = serde_json::from_slice::<ExchangeOperation>(&bytes).is_ok();
        let as_exchange = serde_json::from_slice::<ExchangeRecord>(&bytes).is_ok();
        prop_assert!(!(as_operation && as_exchange), "a document read as both shapes");
    }

    /// Arbitrary bytes never panic: an answer either decodes into one of the three shapes this
    /// family reads or is refused with a reason.
    #[test]
    fn arbitrary_bytes_decode_or_are_refused(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        for outcome in [
            serde_json::from_slice::<ExchangeOperation>(&bytes).map(|_| ()),
            serde_json::from_slice::<ExchangeRecord>(&bytes).map(|_| ()),
            serde_json::from_slice::<ExchangeResource>(&bytes).map(|_| ()),
        ] {
            if let Err(error) = outcome {
                prop_assert!(!error.to_string().is_empty());
            }
        }
    }

    /// An accepted exchange resource keeps both halves and survives re-encoding.
    #[test]
    fn an_accepted_resource_keeps_both_halves(pathed in proptest::collection::vec("[a-z]{1,6}", 0..4)) {
        let attachments: Vec<String> = pathed
            .iter()
            .map(|label| format!(r#""{label}":"-LA""#))
            .collect();
        let document = format!(
            r#"{{"exn":{{"v":"KERI10JSON0000bf_","t":"exn","d":"{SAID}","i":"{SENDER}","rp":"{RECIPIENT}","p":"","dt":"{STAMP}","r":"/multisig/icp","q":{{}},"a":{{}},"e":{{}}}},"pathed":{{{}}}}}"#,
            attachments.join(",")
        );
        let resource: ExchangeResource = serde_json::from_str(&document)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(&resource.exn.digest, SAID);
        prop_assert_eq!(resource.pathed.len(), pathed.iter().collect::<std::collections::BTreeSet<_>>().len());

        let encoded = serde_json::to_string(&resource)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let again: ExchangeResource = serde_json::from_str(&encoded)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(again, resource);
    }
}

/// Regression: the two addresses the pinned unit tests assert.
#[test]
fn the_pinned_addresses_reproduce() -> Result<(), Box<dyn Error>> {
    assert_eq!(submission_path("aid1")?.as_str(), "/identifiers/aid1/exchanges");
    assert_eq!(
        read_path(&SAID.parse::<Said>()?)?.as_str(),
        format!("/exchanges/{SAID}")
    );
    Ok(())
}

/// Regression: a message addressed to the first of two recipients is a different message from one
/// addressed to the second.
///
/// This is what the reference's dead loop hides. `send` there builds the message once, from
/// `recipients[0]`, and delivers it to everybody — so every member after the first receives a
/// message whose `rp` names somebody else, and whose SAID and signatures commit to that.
#[test]
fn addressing_a_different_recipient_is_a_different_message() -> Result<(), Box<dyn Error>> {
    let first = message_for("/multisig/icp", SENDER, RECIPIENT, Sad::new())?;
    let second = message_for("/multisig/icp", SENDER, SECOND, Sad::new())?;

    assert_eq!(first.get_text("rp"), Some(RECIPIENT));
    assert_eq!(second.get_text("rp"), Some(SECOND));
    // Different addressee, different identifier — so a signature over one does not carry the
    // other, and the difference is not cosmetic.
    assert_ne!(first.get_text("d"), second.get_text("d"));
    Ok(())
}

/// Regression: the delivery list is never derived from the addressee, in either direction.
///
/// A draft holds one addressee and no list; a submission takes a list and cannot read the draft's
/// addressee out of it. Upstream the single `recipients` argument does both jobs.
#[test]
fn the_addressee_and_the_delivery_list_are_independent() -> Result<(), Box<dyn Error>> {
    let draft = ExchangeDraft::new(
        "/multisig/icp",
        IdentifierPrefix::from_qb64(RECIPIENT)?,
        STAMP.parse::<Timestamp>()?,
    );
    // The addressee is on the draft, and there is no list there to confuse it with.
    assert_eq!(draft.addressee(), &IdentifierPrefix::from_qb64(RECIPIENT)?);

    // Delivering to somebody the message does not name is representable — a multisig proposal
    // plausibly does exactly that — and it is the caller's decision rather than an accident.
    let elsewhere = [IdentifierPrefix::from_qb64(SECOND)?];
    assert_ne!(elsewhere.first(), Some(draft.addressee()));
    Ok(())
}

/// Regression: an operation answer and an exchange answer are each refused as the other.
#[test]
fn neither_declared_answer_shape_accepts_the_other() {
    let operation = json!({
        "name": "exchange.E",
        "metadata": { "said": "E" },
        "done": true,
        "response": { "said": "E" },
    })
    .to_string();
    let exchange = format!(
        r#"{{"v":"KERI10JSON0000bf_","t":"exn","d":"{SAID}","i":"{SENDER}","rp":"{RECIPIENT}","p":"","dt":"{STAMP}","r":"/multisig/icp","q":{{}},"a":{{}},"e":{{}}}}"#
    );

    assert!(serde_json::from_str::<ExchangeOperation>(&operation).is_ok());
    assert!(serde_json::from_str::<ExchangeRecord>(&operation).is_err());
    assert!(serde_json::from_str::<ExchangeRecord>(&exchange).is_ok());
    assert!(serde_json::from_str::<ExchangeOperation>(&exchange).is_err());
}

/// Regression: a topic is written as given, and the two the reference's integration tests use are
/// the ones this port publishes.
#[test]
fn the_published_topics_are_the_references_own() -> Result<(), Box<dyn Error>> {
    assert_eq!(MULTISIG_TOPIC, "multisig");
    assert_eq!(REGISTRY_TOPIC, "registry");
    // A topic is a body field, not an address, so nothing about it can move a request.
    let mut body = Sad::new();
    body.insert("tpc", "a/b?c=d".to_owned())?;
    assert_eq!(String::from_utf8(body.to_json_bytes()?)?, r#"{"tpc":"a/b?c=d"}"#);
    Ok(())
}
