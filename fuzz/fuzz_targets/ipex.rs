#![no_main]

//! Fuzzes IPEX message construction over hostile message text, attributes, and disclosures.
//!
//! IPEX is where a credential leaves the issuer's control. Three of its inputs come from outside:
//! the message text a peer will read, the selective-disclosure attributes a disclosee chooses, and
//! — for a grant — the three artifacts and three attachments being disclosed, which for a
//! re-disclosure came from someone else entirely. A message that embeds an artifact it did not
//! check, or that lets a payload field readdress it, discloses a credential to the wrong party.
//!
//! The target asserts that nothing panics, that every rejection is a typed [`IpexError`] with a
//! non-empty description, and that anything accepted holds the properties that make an IPEX
//! message trustworthy: it carries its own identifier and reparses byte for byte; its attribute
//! block **always opens with the recipient**, so no payload can readdress it; it carries exactly
//! one indexed signature; its route is the one asked for; and only a grant produces a
//! quadlet-aligned attachment stream, which always names all three embeds.

use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keria_types::api::KeyState;
use libfuzzer_sys::fuzz_target;
use signify_acdc::credential::{CredentialAttributes, CredentialBuilder, RegistryIdentifier};
use signify_acdc::error::IpexError;
use signify_acdc::ipex::{
    ANCHOR_EMBED, CREDENTIAL_EMBED, Disclosure, ISSUANCE_EMBED, IpexEnvelope, IpexMessage, IpexRoute,
    MAX_MESSAGE_BYTES, MESSAGE_LABEL, admit, agree, apply, grant, offer,
};
use signify_acdc::issuance::issue_credential;
use signify_keri::event::Timestamp;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest};
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

thread_local! {
    /// The sender's keeper, derived **once** per process rather than per iteration.
    ///
    /// Deriving it costs an Argon2 run even at the ephemeral profile, and the keeper is not what
    /// this target exercises — the messages built with it are.
    static KEEPER: Option<Box<dyn IdentifierKeeper>> = keeper();
}

/// A salty keeper at the ephemeral cost.
fn keeper() -> Option<Box<dyn IdentifierKeeper>> {
    let factory = KeeperFactory::new(Salt::from_raw(b"0123456789abcdef", SecurityTier::Low).ok()?);
    let request = CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: Some("0123456789abcdefghijk".to_owned()),
        tier: SecurityTier::Low,
        current_count: 1,
        next_count: 1,
        cost: DerivationCost::Ephemeral,
    });
    factory.create(request.keeper_request(0).ok()?).ok()
}

fn key_state() -> Option<KeyState> {
    serde_json::from_value(serde_json::json!({
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
    }))
    .ok()
}

/// Every property a signed IPEX message must hold, whatever the input was.
fn assert_well_formed(message: &IpexMessage, route: IpexRoute, envelope: &IpexEnvelope) {
    assert_eq!(message.route(), route);
    assert_eq!(message.exchange().sad().get_text("r"), Some(route.as_str()));

    message
        .said()
        .verify(message.exchange().sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())
        .expect("an IPEX message must carry its own identifier");
    let reparsed = SerializedEvent::parse(message.raw()).expect("an accepted message must reparse");
    assert_eq!(reparsed.sad(), message.exchange().sad());
    assert_eq!(message.exchange().serialized().size(), message.raw().len());

    // The property that keeps a message addressed where it was aimed.
    let payload = message
        .exchange()
        .sad()
        .get("a")
        .and_then(SadValue::as_map)
        .expect("an IPEX message carries an attribute block");
    assert_eq!(payload.first_label(), Some("i"), "the recipient must be written first");
    let recipient = envelope.recipient().qb64().expect("a typed prefix encodes");
    assert_eq!(payload.get_text("i"), Some(recipient.as_str()));
    assert_eq!(payload.get_text(MESSAGE_LABEL), Some(envelope.message()));

    match message.signatures() {
        ManagedSignatures::Indexed(signatures) => assert_eq!(signatures.len(), 1),
        ManagedSignatures::Unindexed(_) => panic!("an IPEX message must be signed indexed"),
    }

    let attachments = message.attachments();
    assert_eq!(attachments.len() % 4, 0, "an attachment stream must be quadlet aligned");
    if route == IpexRoute::Grant {
        let stream = core::str::from_utf8(attachments).expect("an attachment stream is CESR text");
        for label in [CREDENTIAL_EMBED, ISSUANCE_EMBED, ANCHOR_EMBED] {
            assert!(stream.contains(&format!("-e-{label}")), "a grant must path {label}");
        }
    } else {
        assert!(attachments.is_empty(), "only a grant carries attachments");
    }
}

fuzz_target!(|data: &[u8]| {
    KEEPER.with(|keeper| match keeper.as_deref() {
        Some(keeper) => drive(keeper, data),
        None => {}
    });
});

/// One fuzz iteration, given a keeper that was derived once.
fn drive(keeper: &dyn IdentifierKeeper, data: &[u8]) {
    let [control, sections @ ..] = data else {
        return;
    };
    let Some(state) = key_state() else {
        return;
    };
    let (Ok(sender), Ok(recipient), Ok(issuer), Ok(holder), Ok(registry), Ok(schema), Ok(prior), Ok(stamp)) = (
        IdentifierPrefix::from_qb64(SENDER),
        IdentifierPrefix::from_qb64(RECIPIENT),
        IdentifierPrefix::from_qb64(ISSUER),
        IdentifierPrefix::from_qb64(HOLDER),
        RegistryIdentifier::from_qb64(REGISTRY),
        Said::from_qb64(SCHEMA),
        Said::from_qb64(DIGEST),
        STAMP.parse::<Timestamp>(),
    ) else {
        return;
    };

    // The input splits into the message text, the attribute labels, and a credential value.
    let mut parts = sections.split(|&byte| byte == 0xff);
    let text = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let labels: Vec<String> = parts
        .next()
        .unwrap_or_default()
        .split(|&byte| byte == 0)
        .take(6)
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    let value = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();

    let envelope = match IpexEnvelope::new(sender, recipient, text.clone(), stamp.clone()) {
        Ok(envelope) => {
            assert!(text.len() <= MAX_MESSAGE_BYTES);
            envelope
        }
        Err(error) => {
            assert!(!error.to_string().is_empty());
            assert!(matches!(error, IpexError::MessageTooLong { .. }));
            assert!(text.len() > MAX_MESSAGE_BYTES);
            return;
        }
    };

    // The attribute block a disclosee chooses, whose labels come from the input.
    let mut attributes = Sad::new();
    let mut names_recipient = false;
    for label in &labels {
        if label == "i" {
            names_recipient = true;
        }
        // A duplicate simply loses the field, which is what the caller asked for.
        let _ = attributes.insert(label.clone(), SadValue::text("v"));
    }

    match apply(keeper, &envelope, schema, attributes.clone()) {
        Ok(message) => {
            assert!(!names_recipient, "a payload naming the recipient label was accepted");
            assert_well_formed(&message, IpexRoute::Apply, &envelope);
        }
        Err(error) => {
            assert!(!error.to_string().is_empty());
            if names_recipient {
                assert!(matches!(error, IpexError::ReservedPayloadLabel { label: "i" }));
            }
        }
    }

    // One of the two routes that carry nothing but a message and a prior. Only one is driven per
    // iteration because a salty keeper re-derives its key on every `sign`, so each signature costs
    // an Argon2 run; alternating keeps both covered without paying for both every time.
    let (route, built) = if control & 0x02 == 0 {
        (IpexRoute::Agree, agree(keeper, &envelope, prior))
    } else {
        (IpexRoute::Admit, admit(keeper, &envelope, prior))
    };
    match built {
        Ok(message) => assert_well_formed(&message, route, &envelope),
        Err(error) => assert!(!error.to_string().is_empty()),
    }

    // Likewise for the two routes that embed: an offer is cheap and a grant needs a signed
    // issuance first, so the input picks which one this iteration exercises.
    let embeds_a_grant = control & 0x04 != 0;

    // A credential whose one attribute value comes from the input, offered and granted.
    let Ok(attributes) = CredentialAttributes::new(stamp)
        .issuee(&holder)
        .and_then(|block| block.timestamp())
        .and_then(|block| block.text("LEI", value))
    else {
        return;
    };
    let Ok(credential) = CredentialBuilder::new(issuer, registry, schema, attributes).build() else {
        return;
    };

    let carries_prior = control & 0x01 != 0;
    if !embeds_a_grant {
        match offer(keeper, &envelope, &credential, carries_prior.then_some(prior)) {
            Ok(message) => {
                assert_well_formed(&message, IpexRoute::Offer, &envelope);
                // An offer embeds the credential verbatim beside the block's own identifier.
                let embeds = message
                    .exchange()
                    .sad()
                    .get("e")
                    .and_then(SadValue::as_map)
                    .expect("an offer carries an embed block");
                let labels: Vec<&str> = embeds.entries().map(|(label, _)| label).collect();
                assert_eq!(labels, [CREDENTIAL_EMBED, DEFAULT_SAID_LABEL]);
                assert_eq!(
                    embeds.get(CREDENTIAL_EMBED).and_then(SadValue::as_map),
                    Some(credential.sad())
                );
                assert_eq!(
                    message.exchange().sad().get_text("p"),
                    Some(if carries_prior { DIGEST } else { "" })
                );
            }
            Err(error) => assert!(!error.to_string().is_empty()),
        }
        return;
    }

    let Ok(artifacts) = issue_credential(keeper, &state, credential) else {
        return;
    };
    let disclosure = match Disclosure::from_issuance(&artifacts) {
        Ok(disclosure) => disclosure,
        Err(error) => {
            assert!(!error.to_string().is_empty());
            return;
        }
    };

    match grant(keeper, &envelope, &disclosure, carries_prior.then_some(prior)) {
        Ok(message) => {
            assert_well_formed(&message, IpexRoute::Grant, &envelope);
            // A grant embeds all three artifacts, in order, verbatim.
            let embeds = message
                .exchange()
                .sad()
                .get("e")
                .and_then(SadValue::as_map)
                .expect("a grant carries an embed block");
            let labels: Vec<&str> = embeds.entries().map(|(label, _)| label).collect();
            assert_eq!(
                labels,
                [CREDENTIAL_EMBED, ISSUANCE_EMBED, ANCHOR_EMBED, DEFAULT_SAID_LABEL]
            );
            assert_eq!(
                embeds.get(CREDENTIAL_EMBED).and_then(SadValue::as_map),
                Some(disclosure.credential().sad())
            );
            assert_eq!(
                embeds.get(ISSUANCE_EMBED).and_then(SadValue::as_map),
                Some(disclosure.issuance().sad())
            );
            assert_eq!(
                embeds.get(ANCHOR_EMBED).and_then(SadValue::as_map),
                Some(disclosure.anchor().sad())
            );
            // And the embed block's own identifier commits to all three.
            let block_said =
                Said::from_qb64(embeds.get_text(DEFAULT_SAID_LABEL).unwrap_or_default()).expect("a block SAID parses");
            block_said
                .verify(embeds, DEFAULT_SAID_LABEL, SaidVerification::strict())
                .expect("an embed block must carry its own identifier");
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }
}
