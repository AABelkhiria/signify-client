//! Invariants of IPEX message construction.
//!
//! Every keeper here uses the ephemeral derivation cost. The production profile costs 64 MiB per
//! key, which a property test would multiply by its case count; nothing under test depends on the
//! profile, and the cross-language vectors cover the production one exactly — signatures included.

use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keria_types::api::KeyState;
use proptest::prelude::*;
use signify_acdc::credential::{Credential, CredentialAttributes, CredentialBuilder, RegistryIdentifier};
use signify_acdc::error::IpexError;
use signify_acdc::ipex::{
    ANCHOR_EMBED, ATTRIBUTES_LABEL, CREDENTIAL_EMBED, Disclosure, ISSUANCE_EMBED, IpexEnvelope, IpexMessage, IpexRoute,
    MAX_MESSAGE_BYTES, MESSAGE_LABEL, SCHEMA_LABEL, admit, agree, apply, grant, offer,
};
use signify_acdc::issuance::{IssuanceEvent, issue_credential};
use signify_keri::event::Timestamp;
use signify_keri::event::kind::EventKind;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest, incept_identifier};
use signify_keri::manager::{DerivationCost, IdentifierKeeper, KeeperFactory, ManagedSignatures};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::{DEFAULT_SAID_LABEL, Said, SaidVerification};
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};

const SENDER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const RECIPIENT: &str = "ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k";
const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const HOLDER: &str = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";
const REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const DIGEST: &str = "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW";
const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";

fn fail(error: impl core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

/// A salty keeper at the ephemeral cost.
fn keeper() -> Result<Box<dyn IdentifierKeeper>, Box<dyn std::error::Error>> {
    let factory = KeeperFactory::new(Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?);
    Ok(factory.create(request().keeper_request(0)?)?)
}

fn request() -> CreateIdentifierRequest {
    CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: Some("0123456789abcdefghijk".to_owned()),
        tier: SecurityTier::Low,
        current_count: 1,
        next_count: 1,
        cost: DerivationCost::Ephemeral,
    })
}

fn envelope(message: &str) -> Result<IpexEnvelope, Box<dyn std::error::Error>> {
    Ok(IpexEnvelope::new(
        IdentifierPrefix::from_qb64(SENDER)?,
        IdentifierPrefix::from_qb64(RECIPIENT)?,
        message,
        STAMP.parse::<Timestamp>()?,
    )?)
}

fn credential(value: &str) -> Result<Credential, Box<dyn std::error::Error>> {
    Ok(CredentialBuilder::new(
        IdentifierPrefix::from_qb64(ISSUER)?,
        RegistryIdentifier::from_qb64(REGISTRY)?,
        Said::from_qb64(SCHEMA)?,
        CredentialAttributes::new(STAMP.parse::<Timestamp>()?)
            .issuee(&IdentifierPrefix::from_qb64(HOLDER)?)?
            .timestamp()?
            .text("LEI", value)?,
    )
    .build()?)
}

/// A disclosure whose three attachments are all derived from a real signed issuance.
fn disclosure(keeper: &dyn IdentifierKeeper, credential: Credential) -> Result<Disclosure, Box<dyn std::error::Error>> {
    let state: KeyState = serde_json::from_value(serde_json::json!({
        "i": ISSUER,
        "s": "0",
        "p": "",
        "d": DIGEST,
        "f": "0",
        "dt": STAMP,
        "et": "icp",
        "kt": "1",
        "k": ["DAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"],
        "nt": "1",
        "n": [DIGEST],
        "bt": "0",
        "b": [],
        "c": [],
        "ee": {"s": "0", "d": DIGEST, "br": [], "ba": []},
        "di": "",
    }))?;
    let artifacts = issue_credential(keeper, &state, credential)?;
    Ok(Disclosure::from_issuance(&artifacts)?)
}

/// Every property a signed IPEX message must hold regardless of route.
fn assert_well_formed(message: &IpexMessage, route: IpexRoute, envelope: &IpexEnvelope) -> Result<(), TestCaseError> {
    prop_assert_eq!(message.route(), route);
    prop_assert_eq!(message.exchange().sad().get_text("r"), Some(route.as_str()));
    prop_assert_eq!(
        message.exchange().sad().get_text("t"),
        Some(EventKind::Exchange.as_str())
    );

    // The message carries its own identifier and reparses byte for byte.
    message
        .said()
        .verify(message.exchange().sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())
        .map_err(fail)?;
    let reparsed = SerializedEvent::parse(message.raw()).map_err(fail)?;
    prop_assert_eq!(reparsed.sad(), message.exchange().sad());
    prop_assert_eq!(message.exchange().serialized().size(), message.raw().len());

    // The recipient is written first, before the payload, and the message text follows it.
    let payload = message
        .exchange()
        .sad()
        .get("a")
        .and_then(SadValue::as_map)
        .ok_or_else(|| TestCaseError::fail("no attribute block"))?;
    prop_assert_eq!(payload.first_label(), Some("i"));
    let recipient = envelope.recipient().qb64().map_err(fail)?;
    prop_assert_eq!(payload.get_text("i"), Some(recipient.as_str()));
    prop_assert_eq!(payload.get_text(MESSAGE_LABEL), Some(envelope.message()));

    // Exactly one signature, indexed, over the message bytes.
    match message.signatures() {
        ManagedSignatures::Indexed(signatures) => prop_assert_eq!(signatures.len(), 1),
        ManagedSignatures::Unindexed(_) => return Err(TestCaseError::fail("an IPEX message must be indexed")),
    }

    // An attachment stream is always a whole number of quadlets.
    prop_assert_eq!(message.attachments().len() % 4, 0);
    Ok(())
}

proptest! {
    /// Every route produces a well-formed, deterministic, self-consistent message whose payload
    /// opens with the recipient and carries the message text.
    #[test]
    fn every_route_produces_a_well_formed_message(text in "[ -~]{0,64}") {
        let keeper = keeper().map_err(fail)?;
        let envelope = envelope(&text).map_err(fail)?;
        let schema = Said::from_qb64(SCHEMA).map_err(fail)?;
        let prior = Said::from_qb64(DIGEST).map_err(fail)?;
        let credential = credential("1").map_err(fail)?;

        let messages = [
            (IpexRoute::Apply, apply(keeper.as_ref(), &envelope, schema, Sad::new()).map_err(fail)?),
            (IpexRoute::Offer, offer(keeper.as_ref(), &envelope, &credential, None).map_err(fail)?),
            (IpexRoute::Agree, agree(keeper.as_ref(), &envelope, prior).map_err(fail)?),
            (IpexRoute::Admit, admit(keeper.as_ref(), &envelope, prior).map_err(fail)?),
        ];
        for (route, message) in &messages {
            assert_well_formed(message, *route, &envelope)?;
        }

        // The same inputs always produce the same bytes.
        let again = agree(keeper.as_ref(), &envelope, prior).map_err(fail)?;
        prop_assert_eq!(again.raw(), messages[2].1.raw());
        prop_assert_eq!(again.signatures().qb64().ok(), messages[2].1.signatures().qb64().ok());
    }

    /// The route is part of the message's identity: five messages that differ only by route have
    /// five different identifiers.
    #[test]
    fn the_route_changes_the_identifier(text in "[ -~]{0,32}") {
        let keeper = keeper().map_err(fail)?;
        let envelope = envelope(&text).map_err(fail)?;
        let prior = Said::from_qb64(DIGEST).map_err(fail)?;

        let agree_message = agree(keeper.as_ref(), &envelope, prior).map_err(fail)?;
        let admit_message = admit(keeper.as_ref(), &envelope, prior).map_err(fail)?;
        prop_assert_ne!(agree_message.said(), admit_message.said());
        prop_assert_ne!(agree_message.raw(), admit_message.raw());
        // Their payloads are identical, so only the route can account for the difference.
        prop_assert_eq!(
            agree_message.exchange().sad().get("a"),
            admit_message.exchange().sad().get("a")
        );
    }

    /// A prior identifier is part of the message: one naming a prior and one naming none differ,
    /// and the absent one writes an empty field rather than omitting it.
    #[test]
    fn a_prior_identifier_is_committed_to(text in "[ -~]{0,32}") {
        let keeper = keeper().map_err(fail)?;
        let envelope = envelope(&text).map_err(fail)?;
        let credential = credential("1").map_err(fail)?;
        let prior = Said::from_qb64(DIGEST).map_err(fail)?;

        let with = offer(keeper.as_ref(), &envelope, &credential, Some(prior)).map_err(fail)?;
        let without = offer(keeper.as_ref(), &envelope, &credential, None).map_err(fail)?;
        prop_assert_ne!(with.said(), without.said());
        prop_assert_eq!(with.exchange().sad().get_text("p"), Some(DIGEST));
        prop_assert_eq!(without.exchange().sad().get_text("p"), Some(""));
        // The field is present either way, so the two differ in content rather than in shape.
        prop_assert_eq!(
            with.exchange().sad().len(),
            without.exchange().sad().len()
        );
    }

    /// An apply carries the schema and its attributes; every other route carries the message
    /// alone. The attribute block is committed verbatim.
    #[test]
    fn an_apply_carries_its_schema_and_attributes(
        labels in prop::collection::vec("[A-Za-z_][A-Za-z0-9_]{0,8}", 0..4),
        text in "[ -~]{0,32}",
    ) {
        let keeper = keeper().map_err(fail)?;
        let envelope = envelope(&text).map_err(fail)?;
        let schema = Said::from_qb64(SCHEMA).map_err(fail)?;

        let mut attributes = Sad::new();
        let mut seen = Vec::new();
        for label in &labels {
            if label == "i" || seen.contains(label) {
                continue;
            }
            seen.push(label.clone());
            attributes.insert(label.clone(), SadValue::text("v")).map_err(fail)?;
        }

        let message = apply(keeper.as_ref(), &envelope, schema, attributes.clone()).map_err(fail)?;
        let payload = message
            .exchange()
            .sad()
            .get("a")
            .and_then(SadValue::as_map)
            .ok_or_else(|| TestCaseError::fail("no attribute block"))?;
        let payload_labels: Vec<&str> = payload.entries().map(|(label, _)| label).collect();
        prop_assert_eq!(payload_labels, ["i", MESSAGE_LABEL, SCHEMA_LABEL, ATTRIBUTES_LABEL]);
        prop_assert_eq!(payload.get_text(SCHEMA_LABEL), Some(SCHEMA));
        prop_assert_eq!(
            payload.get(ATTRIBUTES_LABEL).and_then(SadValue::as_map),
            Some(&attributes)
        );
    }

    /// Only a grant carries attachments, and its stream carries one pathed group per embed, in the
    /// order the embeds appear.
    #[test]
    fn only_a_grant_carries_attachments(text in "[ -~]{0,32}") {
        let keeper = keeper().map_err(fail)?;
        let envelope = envelope(&text).map_err(fail)?;
        let credential = credential("1").map_err(fail)?;
        let disclosure = disclosure(keeper.as_ref(), credential.clone()).map_err(fail)?;
        let prior = Said::from_qb64(DIGEST).map_err(fail)?;

        for message in [
            apply(keeper.as_ref(), &envelope, Said::from_qb64(SCHEMA).map_err(fail)?, Sad::new()).map_err(fail)?,
            offer(keeper.as_ref(), &envelope, &credential, None).map_err(fail)?,
            agree(keeper.as_ref(), &envelope, prior).map_err(fail)?,
            admit(keeper.as_ref(), &envelope, prior).map_err(fail)?,
        ] {
            prop_assert!(message.attachments().is_empty(), "{:?} carries an attachment", message.route());
        }

        let granted = grant(keeper.as_ref(), &envelope, &disclosure, None).map_err(fail)?;
        assert_well_formed(&granted, IpexRoute::Grant, &envelope)?;
        let stream = core::str::from_utf8(granted.attachments()).map_err(fail)?;
        prop_assert!(!stream.is_empty());
        for label in [CREDENTIAL_EMBED, ISSUANCE_EMBED, ANCHOR_EMBED] {
            prop_assert!(stream.contains(&format!("-e-{label}")), "no path for {label}");
        }
        // The three appear in the order the embeds are written.
        let acdc_at = stream.find("-e-acdc").unwrap_or(usize::MAX);
        let iss_at = stream.find("-e-iss").unwrap_or(usize::MAX);
        let anc_at = stream.find("-e-anc").unwrap_or(usize::MAX);
        prop_assert!(acdc_at < iss_at && iss_at < anc_at);
    }

    /// A grant embeds all three artifacts verbatim, and the block's own identifier verifies over
    /// them — which is what lets a recipient trust what it received.
    #[test]
    fn a_grant_embeds_all_three_artifacts_verbatim(value in "[ -~]{0,16}") {
        let keeper = keeper().map_err(fail)?;
        let envelope = envelope("").map_err(fail)?;
        let credential = credential(&value).map_err(fail)?;
        let issuance = IssuanceEvent::for_credential(&credential).map_err(fail)?;
        let disclosure = disclosure(keeper.as_ref(), credential.clone()).map_err(fail)?;

        let granted = grant(keeper.as_ref(), &envelope, &disclosure, None).map_err(fail)?;
        let embeds = granted
            .exchange()
            .sad()
            .get("e")
            .and_then(SadValue::as_map)
            .ok_or_else(|| TestCaseError::fail("no embed block"))?;
        let labels: Vec<&str> = embeds.entries().map(|(label, _)| label).collect();
        prop_assert_eq!(labels, [CREDENTIAL_EMBED, ISSUANCE_EMBED, ANCHOR_EMBED, DEFAULT_SAID_LABEL]);

        let embedded_credential = embeds
            .get(CREDENTIAL_EMBED)
            .and_then(SadValue::as_map)
            .ok_or_else(|| TestCaseError::fail("no embedded credential"))?;
        prop_assert_eq!(embedded_credential, credential.sad());
        let embedded_issuance = embeds
            .get(ISSUANCE_EMBED)
            .and_then(SadValue::as_map)
            .ok_or_else(|| TestCaseError::fail("no embedded issuance"))?;
        prop_assert_eq!(embedded_issuance, issuance.sad());

        // The embed block's identifier is a SAID over the three, so tampering with any of them
        // would be detectable without re-deriving the whole message.
        let block_said = Said::from_qb64(
            embeds.get_text(DEFAULT_SAID_LABEL).unwrap_or_default()
        ).map_err(fail)?;
        block_said
            .verify(embeds, DEFAULT_SAID_LABEL, SaidVerification::strict())
            .map_err(fail)?;
    }

    /// A message is accepted exactly when it fits the bound, and the failure names the real length.
    #[test]
    fn a_message_is_accepted_exactly_inside_its_bound(length in 0_usize..(MAX_MESSAGE_BYTES + 8)) {
        let built = IpexEnvelope::new(
            IdentifierPrefix::from_qb64(SENDER).map_err(fail)?,
            IdentifierPrefix::from_qb64(RECIPIENT).map_err(fail)?,
            "m".repeat(length),
            STAMP.parse::<Timestamp>().map_err(fail)?,
        );
        if length <= MAX_MESSAGE_BYTES {
            prop_assert!(built.is_ok());
        } else {
            prop_assert!(
                matches!(built, Err(IpexError::MessageTooLong { actual, .. }) if actual == length),
                "an oversized message did not report its real length"
            );
        }
    }

    /// An apply whose attributes name the recipient label is refused, because the reference would
    /// let it readdress the message.
    #[test]
    fn attributes_may_not_readdress_the_message(value in "[ -~]{1,32}") {
        let keeper = keeper().map_err(fail)?;
        let envelope = envelope("").map_err(fail)?;
        let mut attributes = Sad::new();
        attributes.insert("i", SadValue::text(value)).map_err(fail)?;
        prop_assert!(
            matches!(
                apply(keeper.as_ref(), &envelope, Said::from_qb64(SCHEMA).map_err(fail)?, attributes),
                Err(IpexError::ReservedPayloadLabel { label: "i" })
            ),
            "a payload naming the recipient label was accepted"
        );
    }
}

/// Regression: a disclosure built from a real issuance chains all the way to a signed key event —
/// the credential's attachment names the issuance, the issuance's names the anchor, and the
/// anchor's is the issuer's own signature over it.
#[test]
fn a_disclosure_chains_to_a_signed_key_event() -> Result<(), Box<dyn std::error::Error>> {
    let mut keeper = keeper()?;
    let inception = incept_identifier(keeper.as_mut(), &request())?;
    let event: serde_json::Value = serde_json::from_slice(inception.event.raw())?;
    let state: KeyState = serde_json::from_value(serde_json::json!({
        "i": event.get("i"),
        "s": "0",
        "p": "",
        "d": event.get("d"),
        "f": "0",
        "dt": STAMP,
        "et": "icp",
        "kt": event.get("kt"),
        "k": event.get("k"),
        "nt": event.get("nt"),
        "n": event.get("n"),
        "bt": "0",
        "b": [],
        "c": [],
        "ee": {"s": "0", "d": event.get("d"), "br": [], "ba": []},
        "di": "",
    }))?;

    let credential = credential("5493001KJTIIGC8Y1R17")?;
    let artifacts = issue_credential(keeper.as_ref(), &state, credential)?;
    let disclosure = Disclosure::from_issuance(&artifacts)?;

    // The three artifacts are exactly what Roadmap 6.2 produced.
    assert_eq!(disclosure.credential().raw(), artifacts.credential.raw());
    assert_eq!(disclosure.issuance().raw(), artifacts.issuance.raw());
    assert_eq!(disclosure.anchor().raw(), artifacts.anchor.event.raw());

    let message = grant(keeper.as_ref(), &envelope("")?, &disclosure, None)?;
    let stream = core::str::from_utf8(message.attachments())?;

    // The credential's group names the issuance event; the issuance's names the anchor; the
    // anchor's is a controller signature group.
    assert!(stream.contains(&artifacts.issuance.said().qb64()?));
    assert!(stream.contains(&artifacts.anchor.event.said().qb64()?));
    assert!(stream.contains("-e-anc-AAB"));
    let signatures = artifacts.anchor.signatures.qb64()?;
    for signature in &signatures {
        assert!(
            stream.contains(signature),
            "the anchor's signature is not in the stream"
        );
    }
    Ok(())
}

/// Regression: a disclosure whose anchor carries no indexed signatures is refused, because a grant
/// built from it would disclose a credential the recipient cannot verify.
#[test]
fn an_unsigned_anchor_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let keeper = keeper()?;
    let state: KeyState = serde_json::from_value(serde_json::json!({
        "i": ISSUER,
        "s": "0",
        "p": "",
        "d": DIGEST,
        "f": "0",
        "dt": STAMP,
        "et": "icp",
        "kt": "1",
        "k": ["DAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"],
        "nt": "1",
        "n": [DIGEST],
        "bt": "0",
        "b": [],
        "c": [],
        "ee": {"s": "0", "d": DIGEST, "br": [], "ba": []},
        "di": "",
    }))?;
    let mut artifacts = issue_credential(keeper.as_ref(), &state, credential("1")?)?;

    // A real issuance signs; emptying the signatures is the state this refusal exists for.
    assert!(Disclosure::from_issuance(&artifacts).is_ok());
    artifacts.anchor.signatures = ManagedSignatures::Indexed(Vec::new());
    assert!(matches!(
        Disclosure::from_issuance(&artifacts),
        Err(IpexError::UnsignedAnchor)
    ));
    Ok(())
}
