#![no_main]

//! Fuzzes credential issuance and revocation artifacts over hostile key state and inputs.
//!
//! The untrusted input here is different from Roadmap 6.1's. A transaction event's own fields are
//! typed and short, but the **key state** the anchor is built over is whatever a KERIA agent
//! returned: its identifier, its position, its digest, and its configuration are all remote text.
//! An issuer that anchors over a state it should have refused signs a key event committing to a
//! log position it does not occupy.
//!
//! The target asserts that nothing panics, that every rejection is a typed [`TransactionError`]
//! with a non-empty description, and that anything accepted holds four properties: the transaction
//! event carries its own digest and reparses byte for byte; the anchor lands exactly one position
//! past the state and seals exactly one event; an establishment-only state is *always* refused, by
//! both entry points; and the credential attachment is a well-formed quadlet-aligned triple naming
//! the event it authenticates.

use keria_types::api::KeyState;
use libfuzzer_sys::fuzz_target;
use signify_acdc::credential::{CredentialAttributes, CredentialBuilder, RegistryIdentifier};
use signify_acdc::error::TransactionError;
use signify_acdc::issuance::{ISSUANCE_SEQUENCE_NUMBER, IssuanceEvent};
use signify_acdc::revocation::RevocationEventBuilder;
use signify_acdc::transaction::{TransactionSeal, anchor_event, is_establishment_only};
use signify_keri::event::Timestamp;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::{DEFAULT_SAID_LABEL, Said, SaidVerification};
use signify_keri::serialization::{SadValue, SerializedEvent};

const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const HOLDER: &str = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";
const REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const DIGEST: &str = "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW";
const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";

/// Builds a key state from the fuzzer's bytes: its position, its digest, and its configuration all
/// come from the input, which is exactly what a remote agent controls.
fn key_state(position: &str, digest: &str, configuration: &[String]) -> Option<KeyState> {
    serde_json::from_value(serde_json::json!({
        "i": ISSUER,
        "s": position,
        "p": "",
        "d": digest,
        "f": "0",
        "dt": STAMP,
        "et": "icp",
        "kt": "1",
        "k": ["DAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"],
        "nt": "1",
        "n": [DIGEST],
        "bt": "0",
        "b": [],
        "c": configuration,
        "ee": {"s": "0", "d": DIGEST, "br": [], "ba": []},
        "di": "",
    }))
    .ok()
}

fuzz_target!(|data: &[u8]| {
    let [control, sections @ ..] = data else {
        return;
    };
    let (Ok(issuer), Ok(holder), Ok(registry), Ok(schema), Ok(stamp), Ok(digest)) = (
        IdentifierPrefix::from_qb64(ISSUER),
        IdentifierPrefix::from_qb64(HOLDER),
        RegistryIdentifier::from_qb64(REGISTRY),
        Said::from_qb64(SCHEMA),
        STAMP.parse::<Timestamp>(),
        Said::from_qb64(DIGEST),
    ) else {
        return;
    };

    // The input splits into the state's position, its digest, its configuration, and one
    // credential attribute.
    let mut parts = sections.split(|&byte| byte == 0xff);
    let position = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let state_digest = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let configuration: Vec<String> = parts
        .next()
        .unwrap_or_default()
        .split(|&byte| byte == 0)
        .take(4)
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    let attribute = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();

    // A credential, whose one caller-supplied attribute value comes from the input.
    let mut attributes = CredentialAttributes::new(stamp.clone());
    if control & 0x01 != 0 {
        let Ok(next) = attributes.issuee(&holder) else {
            return;
        };
        attributes = next;
    }
    let Ok(attributes) = attributes.timestamp().and_then(|block| block.text("LEI", attribute)) else {
        return;
    };
    let Ok(credential) = CredentialBuilder::new(issuer, registry.clone(), schema, attributes).build() else {
        return;
    };

    // The transaction event. Both kinds are driven, because a revocation adds one field and can
    // sit anywhere in the log.
    let Ok(issuance) = IssuanceEvent::for_credential(&credential) else {
        // Nothing about a credential built above can make this fail; if it ever does, that is the
        // finding.
        panic!("a credential built here must always yield an issuance");
    };
    assert_eq!(issuance.credential(), credential.said());
    assert_eq!(issuance.sequence_number(), ISSUANCE_SEQUENCE_NUMBER);
    assert_eq!(issuance.timestamp(), credential.timestamp());
    issuance
        .said()
        .verify(issuance.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())
        .expect("a transaction event must carry its own identifier");
    let reparsed = SerializedEvent::parse(issuance.raw()).expect("an accepted event must reparse");
    assert_eq!(reparsed.sad(), issuance.sad());
    assert_eq!(issuance.serialized().size(), issuance.raw().len());

    // The credential attachment: a quadlet-aligned triple naming the event above.
    let attachment = issuance
        .credential_attachment()
        .expect("an accepted event must encode its attachment");
    assert_eq!(attachment.len() % 4, 0, "an attachment must be quadlet aligned");
    let text = core::str::from_utf8(&attachment).expect("an attachment is CESR text");
    assert!(
        text.starts_with("-IAB"),
        "a credential attachment is a seal-source triple"
    );
    assert_eq!(text.len(), 4 + 44 + 24 + 44);

    let seal = if control & 0x02 == 0 {
        issuance.seal()
    } else {
        let revocation = RevocationEventBuilder::new(credential.said(), registry, issuance.said(), stamp)
            .sequence_number(u128::from(*control))
            .build()
            .expect("a revocation of a credential built here must always build");
        revocation
            .said()
            .verify(revocation.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())
            .expect("a transaction event must carry its own identifier");
        assert_eq!(revocation.prior(), issuance.said());
        assert_eq!(revocation.sequence_number(), u128::from(*control));
        // A revocation names exactly one more field than an issuance.
        assert_eq!(revocation.sad().len(), issuance.sad().len() + 1);
        revocation.seal()
    };

    // A seal always renders three fields, whatever its position.
    let rendered = seal.to_sad().expect("a seal of typed values must render");
    assert_eq!(rendered.len(), 3);
    assert_eq!(
        rendered.get_text("s"),
        Some(format!("{:x}", seal.sequence_number()).as_str())
    );

    // The key state, which is the part a remote agent controls.
    let Some(state) = key_state(&position, &state_digest, &configuration) else {
        return;
    };
    let establishment_only = configuration.iter().any(|entry| entry == "EO");
    assert_eq!(is_establishment_only(&state), establishment_only);

    match anchor_event(&state, &seal) {
        Ok(event) => {
            // An establishment-only state must never reach here.
            assert!(!establishment_only, "an establishment-only issuer was accepted");

            // The anchor lands exactly one position past the state it was built over.
            let current = u128::from_str_radix(&position, 16).expect("an accepted state parses its position");
            assert_eq!(event.sequence_number(), current + 1);
            assert_eq!(event.sad().get_text("p"), Some(state_digest.as_str()));
            assert_eq!(event.sad().get_text("i"), Some(ISSUER));

            // And it seals exactly one event, the one asked for.
            let anchors = event
                .sad()
                .get("a")
                .and_then(SadValue::as_array)
                .expect("an interaction event carries an anchor list");
            assert_eq!(anchors.len(), 1, "an anchor must seal exactly one transaction event");
            let sealed = anchors
                .first()
                .and_then(SadValue::as_map)
                .expect("an anchor is a field map");
            assert_eq!(sealed.get_text("d"), rendered.get_text("d"));
            assert_eq!(sealed.get_text("s"), rendered.get_text("s"));

            assert_eq!(event.serialized().size(), event.raw().len());
            let reparsed = SerializedEvent::parse(event.raw()).expect("an accepted anchor must reparse");
            assert_eq!(reparsed.sad(), event.sad());
        }
        Err(error) => {
            assert!(!error.to_string().is_empty());
            // The only refusals reachable from a well-formed seal are about the key state.
            assert!(
                matches!(
                    error,
                    TransactionError::EstablishmentOnlyIssuer { .. }
                        | TransactionError::SequenceNumberOverflow { .. }
                        | TransactionError::Prefix { .. }
                        | TransactionError::Said { .. }
                ),
                "an unexpected refusal shape: {error}"
            );
        }
    }

    // The establishment-only refusal is unconditional: adding the trait to any accepted state
    // makes it fail, whatever else that state says.
    if !establishment_only && let Some(mut refused) = key_state(&position, &state_digest, &configuration) {
        refused.configuration.push("EO".to_owned());
        assert!(matches!(
            anchor_event(&refused, &seal),
            Err(TransactionError::EstablishmentOnlyIssuer { trait_code: "EO" })
        ));
    }

    // A seal built from arbitrary digests still renders, which is what makes the anchor's own
    // failure modes state-only.
    let arbitrary = TransactionSeal::new(digest, u128::from(*control), digest);
    assert_eq!(arbitrary.to_sad().map(|sad| sad.len()).unwrap_or_default(), 3);
});
