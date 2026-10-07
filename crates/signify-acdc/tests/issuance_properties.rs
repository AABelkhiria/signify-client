//! Invariants of credential issuance and revocation artifacts.
//!
//! Every keeper here uses the ephemeral derivation cost. The production profile costs 64 MiB per
//! key, which a property test would multiply by its case count; nothing under test depends on the
//! profile, and the cross-language vectors cover the production one exactly.

use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keria_types::api::KeyState;
use proptest::prelude::*;
use signify_acdc::credential::{CredentialAttributes, CredentialBuilder, RegistryIdentifier};
use signify_acdc::error::TransactionError;
use signify_acdc::issuance::{ISSUANCE_SEQUENCE_NUMBER, IssuanceEvent, issue_credential};
use signify_acdc::revocation::{DEFAULT_REVOCATION_SEQUENCE_NUMBER, RevocationEventBuilder, revoke_credential};
use signify_acdc::transaction::{TransactionSeal, anchor, anchor_event, is_establishment_only};
use signify_keri::event::Timestamp;
use signify_keri::event::kind::EventKind;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest, incept_identifier};
use signify_keri::manager::{DerivationCost, IdentifierKeeper, KeeperFactory};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::{DEFAULT_SAID_LABEL, Said, SaidVerification};
use signify_keri::serialization::SerializedEvent;

const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const HOLDER: &str = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";
const REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
const OTHER_REGISTRY: &str = "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const ISSUANCE: &str = "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW";
const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";

fn fail(error: impl core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

fn stamp() -> Result<Timestamp, TestCaseError> {
    STAMP.parse().map_err(fail)
}

fn credential(registry: &str, value: &str) -> Result<signify_acdc::credential::Credential, TestCaseError> {
    CredentialBuilder::new(
        IdentifierPrefix::from_qb64(ISSUER).map_err(fail)?,
        RegistryIdentifier::from_qb64(registry).map_err(fail)?,
        Said::from_qb64(SCHEMA).map_err(fail)?,
        CredentialAttributes::new(stamp()?)
            .issuee(&IdentifierPrefix::from_qb64(HOLDER).map_err(fail)?)
            .map_err(fail)?
            .timestamp()
            .map_err(fail)?
            .text("LEI", value.to_owned())
            .map_err(fail)?,
    )
    .build()
    .map_err(fail)
}

/// A key state carrying only the fields anchoring reads.
fn key_state(sequence_number: u128, configuration: &[&str]) -> Result<KeyState, TestCaseError> {
    let document = serde_json::json!({
        "i": ISSUER,
        "s": format!("{sequence_number:x}"),
        "p": "",
        "d": ISSUANCE,
        "f": "0",
        "dt": STAMP,
        "et": "icp",
        "kt": "1",
        "k": ["DAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"],
        "nt": "1",
        "n": [ISSUANCE],
        "bt": "0",
        "b": [],
        "c": configuration,
        "ee": {"s": "0", "d": ISSUANCE, "br": [], "ba": []},
        "di": "",
    });
    serde_json::from_value(document).map_err(fail)
}

proptest! {
    /// Both transaction events are pure functions of their inputs: the same inputs always produce
    /// the same bytes, and the result is self-consistent — it reparses losslessly, its declared
    /// size is its real size, and its identifier verifies against the data carrying it.
    #[test]
    fn a_transaction_event_is_deterministic_and_self_consistent(
        value in "[ -~]{0,24}",
        position in 0_u128..1_000_000,
    ) {
        let credential = credential(REGISTRY, &value)?;
        let registry = RegistryIdentifier::from_qb64(REGISTRY).map_err(fail)?;

        let issuance = IssuanceEvent::for_credential(&credential).map_err(fail)?;
        let again = IssuanceEvent::for_credential(&credential).map_err(fail)?;
        prop_assert_eq!(issuance.raw(), again.raw());
        prop_assert_eq!(issuance.serialized().size(), issuance.raw().len());
        let reparsed = SerializedEvent::parse(issuance.raw()).map_err(fail)?;
        prop_assert_eq!(reparsed.sad(), issuance.sad());
        issuance
            .said()
            .verify(issuance.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())
            .map_err(fail)?;

        let build_revocation = || {
            RevocationEventBuilder::new(
                credential.said(),
                registry.clone(),
                issuance.said(),
                stamp().ok()?,
            )
            .sequence_number(position)
            .build()
            .ok()
        };
        let revocation = build_revocation().ok_or_else(|| TestCaseError::fail("revocation failed"))?;
        let revocation_again = build_revocation().ok_or_else(|| TestCaseError::fail("revocation failed"))?;
        prop_assert_eq!(revocation.raw(), revocation_again.raw());
        prop_assert_eq!(revocation.serialized().size(), revocation.raw().len());
        let reparsed = SerializedEvent::parse(revocation.raw()).map_err(fail)?;
        prop_assert_eq!(reparsed.sad(), revocation.sad());
        revocation
            .said()
            .verify(revocation.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())
            .map_err(fail)?;
    }

    /// The two events differ in exactly one field: a revocation names the event it supersedes and
    /// an issuance has nothing to name, so an issuance is always the shorter of the two.
    #[test]
    fn a_revocation_adds_exactly_the_prior_field(value in "[ -~]{0,24}") {
        let credential = credential(REGISTRY, &value)?;
        let issuance = IssuanceEvent::for_credential(&credential).map_err(fail)?;
        let revocation = RevocationEventBuilder::new(
            credential.said(),
            RegistryIdentifier::from_qb64(REGISTRY).map_err(fail)?,
            issuance.said(),
            stamp()?,
        )
        .build()
        .map_err(fail)?;

        let issuance_labels: Vec<&str> = issuance.sad().entries().map(|(label, _)| label).collect();
        let revocation_labels: Vec<&str> = revocation.sad().entries().map(|(label, _)| label).collect();
        prop_assert_eq!(issuance_labels, ["v", "t", "d", "i", "s", "ri", "dt"]);
        prop_assert_eq!(revocation_labels, ["v", "t", "d", "i", "s", "ri", "p", "dt"]);
        prop_assert!(issuance.raw().len() < revocation.raw().len());

        // Everything but the ilk, the position, and the prior is identical between them.
        prop_assert_eq!(issuance.sad().get_text("i"), revocation.sad().get_text("i"));
        prop_assert_eq!(issuance.sad().get_text("ri"), revocation.sad().get_text("ri"));
        prop_assert_eq!(issuance.sad().get_text("dt"), revocation.sad().get_text("dt"));
        prop_assert_eq!(issuance.sad().get_text("t"), Some("iss"));
        prop_assert_eq!(revocation.sad().get_text("t"), Some("rev"));
    }

    /// Every field a transaction event names is part of its identity: changing the credential, the
    /// registry, the timestamp, the position, or a revocation's prior changes both its identifier
    /// and its bytes.
    #[test]
    fn every_named_field_changes_the_identifier(
        value in "[ -~]{0,16}",
        other_value in "[ -~]{0,16}",
    ) {
        prop_assume!(value != other_value);
        let registry = RegistryIdentifier::from_qb64(REGISTRY).map_err(fail)?;
        let other = RegistryIdentifier::from_qb64(OTHER_REGISTRY).map_err(fail)?;

        let reference = IssuanceEvent::for_credential(&credential(REGISTRY, &value)?).map_err(fail)?;
        for variant in [
            IssuanceEvent::for_credential(&credential(REGISTRY, &other_value)?).map_err(fail)?,
            IssuanceEvent::for_credential(&credential(OTHER_REGISTRY, &value)?).map_err(fail)?,
            IssuanceEvent::new(
                reference.credential(),
                registry.clone(),
                "2021-06-27T21:26:21.233257+00:00".parse().map_err(fail)?,
            )
            .map_err(fail)?,
        ] {
            prop_assert_ne!(variant.said(), reference.said());
        }

        let base = RevocationEventBuilder::new(reference.credential(), registry.clone(), reference.said(), stamp()?)
            .build()
            .map_err(fail)?;
        for variant in [
            RevocationEventBuilder::new(reference.credential(), other, reference.said(), stamp()?)
                .build()
                .map_err(fail)?,
            RevocationEventBuilder::new(reference.credential(), registry.clone(), reference.credential(), stamp()?)
                .build()
                .map_err(fail)?,
            RevocationEventBuilder::new(reference.credential(), registry, reference.said(), stamp()?)
                .sequence_number(2)
                .build()
                .map_err(fail)?,
        ] {
            prop_assert_ne!(variant.said(), base.said());
            prop_assert_ne!(variant.raw(), base.raw());
        }
    }

    /// A seal names its event exactly, and the anchor lands one position past the key state and
    /// carries that seal alone.
    #[test]
    fn an_anchor_seals_one_event_at_the_next_position(position in 0_u128..100_000) {
        let credential = credential(REGISTRY, "1")?;
        let issuance = IssuanceEvent::for_credential(&credential).map_err(fail)?;
        let state = key_state(position, &[])?;
        let event = anchor_event(&state, &issuance.seal()).map_err(fail)?;

        prop_assert_eq!(event.kind(), EventKind::Interaction);
        prop_assert_eq!(event.sequence_number(), position + 1);
        prop_assert_eq!(event.sad().get_text("p"), Some(ISSUANCE));
        prop_assert_eq!(event.sad().get_text("i"), Some(ISSUER));

        let anchors = event
            .sad()
            .get("a")
            .and_then(signify_keri::serialization::SadValue::as_array)
            .ok_or_else(|| TestCaseError::fail("no anchor list"))?;
        prop_assert_eq!(anchors.len(), 1);
        let sealed = anchors
            .first()
            .and_then(signify_keri::serialization::SadValue::as_map)
            .ok_or_else(|| TestCaseError::fail("anchor is not a map"))?;
        prop_assert_eq!(sealed.get_text("i"), issuance.sad().get_text("i"));
        prop_assert_eq!(sealed.get_text("s"), Some("0"));
        prop_assert_eq!(sealed.get_text("d"), issuance.sad().get_text("d"));

        // The event is self-consistent, as any key event must be.
        prop_assert_eq!(event.serialized().size(), event.raw().len());
        let reparsed = SerializedEvent::parse(event.raw()).map_err(fail)?;
        prop_assert_eq!(reparsed.sad(), event.sad());
    }

    /// A seal is a pure function of the three values it holds, and its position is written in
    /// lowercase hexadecimal exactly as the protocol writes a sequence number.
    #[test]
    fn a_seal_renders_its_position_as_the_protocol_does(position in 0_u128..u128::from(u64::MAX)) {
        let said = Said::from_qb64(ISSUANCE).map_err(fail)?;
        let seal = TransactionSeal::new(said, position, said);
        let sad = seal.to_sad().map_err(fail)?;
        let rendered = format!("{position:x}");
        prop_assert_eq!(sad.get_text("s"), Some(rendered.as_str()));
        prop_assert_eq!(sad.len(), 3);
        prop_assert_eq!(seal.sequence_number(), position);
    }

    /// An establishment-only issuer is refused before anything is built, whichever entry of its
    /// configuration carries the trait.
    #[test]
    fn an_establishment_only_issuer_is_always_refused(
        position in 0_usize..4,
        extra in prop::collection::vec("(DND|NB)", 0..3),
    ) {
        let mut configuration: Vec<&str> = extra.iter().map(String::as_str).collect();
        let index = position.min(configuration.len());
        configuration.insert(index, "EO");
        let state = key_state(1, &configuration)?;
        prop_assert!(is_establishment_only(&state));

        let credential = credential(REGISTRY, "1")?;
        let issuance = IssuanceEvent::for_credential(&credential).map_err(fail)?;
        prop_assert!(
            matches!(
                anchor_event(&state, &issuance.seal()),
                Err(TransactionError::EstablishmentOnlyIssuer { .. })
            ),
            "an establishment-only issuer was accepted"
        );

        // Without the trait the same state anchors happily.
        let permitted = key_state(1, &extra.iter().map(String::as_str).collect::<Vec<_>>())?;
        prop_assert!(!is_establishment_only(&permitted));
        prop_assert!(anchor_event(&permitted, &issuance.seal()).is_ok());
    }

    /// The credential attachment names the issuance and the issuance attachment names the anchor,
    /// so following the two in order walks from the credential to a signed key event.
    #[test]
    fn the_attachments_chain_the_three_artifacts(value in "[ -~]{0,16}") {
        let credential = credential(REGISTRY, &value)?;
        let issuance = IssuanceEvent::for_credential(&credential).map_err(fail)?;
        let attachment = issuance.credential_attachment().map_err(fail)?;
        let text = core::str::from_utf8(&attachment).map_err(fail)?;

        // A seal-source triple with no pipelining: counter, credential, position, digest.
        prop_assert!(text.starts_with("-IAB"));
        prop_assert_eq!(text.len(), 4 + 44 + 24 + 44);
        prop_assert!(text.contains(issuance.sad().get_text("i").unwrap_or_default()));
        prop_assert!(text.contains(issuance.sad().get_text("d").unwrap_or_default()));
        prop_assert_eq!(attachment.len() % 4, 0);
    }
}

/// The keeper-backed path, run once rather than as a property: a real salty keeper signs a real
/// anchor for an identifier it just incepted, for both issuance and revocation.
#[test]
fn a_keeper_signs_both_anchors_and_agrees_with_the_unsigned_event() -> Result<(), Box<dyn std::error::Error>> {
    let factory = KeeperFactory::new(Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?);
    let request = CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: Some("0123456789abcdefghijk".to_owned()),
        tier: SecurityTier::Low,
        current_count: 1,
        next_count: 1,
        cost: DerivationCost::Ephemeral,
    });
    let mut keeper: Box<dyn IdentifierKeeper> = factory.create(request.keeper_request(0)?)?;
    let inception = incept_identifier(keeper.as_mut(), &request)?;

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

    let issuer = IdentifierPrefix::from_qb64(&state.identifier)?;
    let credential = CredentialBuilder::new(
        issuer,
        RegistryIdentifier::from_qb64(REGISTRY)?,
        Said::from_qb64(SCHEMA)?,
        CredentialAttributes::new(STAMP.parse()?)
            .issuee(&IdentifierPrefix::from_qb64(HOLDER)?)?
            .timestamp()?
            .text("LEI", "5493001KJTIIGC8Y1R17")?,
    )
    .build()?;

    // Issuance: the signed anchor and the unsigned event are the same bytes.
    let artifacts = issue_credential(keeper.as_ref(), &state, credential.clone())?;
    assert_eq!(artifacts.issuance.sequence_number(), ISSUANCE_SEQUENCE_NUMBER);
    assert_eq!(artifacts.anchor.event.sequence_number(), 1);
    assert_ne!(artifacts.anchor.signatures.qb64()?, [] as [String; 0]);
    let unsigned = anchor_event(&state, &artifacts.issuance.seal())?;
    assert_eq!(unsigned.raw(), artifacts.anchor.event.raw());
    assert_eq!(
        anchor(keeper.as_ref(), &state, &artifacts.issuance.seal())?.event.raw(),
        unsigned.raw()
    );

    // Both attachments are derivable from the artifacts alone.
    assert_eq!(
        artifacts.credential_attachment()?,
        artifacts.issuance.credential_attachment()?
    );
    let issuance_attachment = artifacts.issuance_attachment()?;
    assert!(core::str::from_utf8(&issuance_attachment)?.starts_with("-VAS-GAB"));
    assert_eq!(issuance_attachment.len() % 4, 0);

    // Revocation: the same path, one position further along.
    let mut advanced = state.clone();
    advanced.sequence_number = "1".to_owned();
    advanced.digest = artifacts.anchor.event.said().qb64()?;
    let revocation = RevocationEventBuilder::new(
        credential.said(),
        RegistryIdentifier::from_qb64(REGISTRY)?,
        artifacts.issuance.said(),
        STAMP.parse()?,
    )
    .build()?;
    let revoked = revoke_credential(keeper.as_ref(), &advanced, revocation)?;
    assert_eq!(revoked.revocation.sequence_number(), DEFAULT_REVOCATION_SEQUENCE_NUMBER);
    assert_eq!(revoked.anchor.event.sequence_number(), 2);
    assert_ne!(revoked.anchor.signatures.qb64()?, [] as [String; 0]);
    assert_eq!(
        anchor_event(&advanced, &revoked.revocation.seal())?.raw(),
        revoked.anchor.event.raw()
    );
    Ok(())
}

/// Regression: an establishment-only issuer must be refused by the signing path too, not only by
/// the unsigned one — the check is on the key state, so both entry points share it.
#[test]
fn the_signing_path_refuses_an_establishment_only_issuer() -> Result<(), Box<dyn std::error::Error>> {
    let factory = KeeperFactory::new(Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?);
    let request = CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: Some("0123456789abcdefghijk".to_owned()),
        tier: SecurityTier::Low,
        current_count: 1,
        next_count: 1,
        cost: DerivationCost::Ephemeral,
    });
    let keeper: Box<dyn IdentifierKeeper> = factory.create(request.keeper_request(0)?)?;

    let document = serde_json::json!({
        "i": ISSUER,
        "s": "0",
        "p": "",
        "d": ISSUANCE,
        "f": "0",
        "dt": STAMP,
        "et": "icp",
        "kt": "1",
        "k": ["DAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"],
        "nt": "1",
        "n": [ISSUANCE],
        "bt": "0",
        "b": [],
        "c": ["EO"],
        "ee": {"s": "0", "d": ISSUANCE, "br": [], "ba": []},
        "di": "",
    });
    let state: KeyState = serde_json::from_value(document)?;

    let credential = CredentialBuilder::new(
        IdentifierPrefix::from_qb64(ISSUER)?,
        RegistryIdentifier::from_qb64(REGISTRY)?,
        Said::from_qb64(SCHEMA)?,
        CredentialAttributes::new(STAMP.parse()?).timestamp()?,
    )
    .build()?;

    assert!(matches!(
        issue_credential(keeper.as_ref(), &state, credential.clone()),
        Err(TransactionError::EstablishmentOnlyIssuer { trait_code: "EO" })
    ));

    let revocation = RevocationEventBuilder::new(
        credential.said(),
        RegistryIdentifier::from_qb64(REGISTRY)?,
        Said::from_qb64(ISSUANCE)?,
        STAMP.parse()?,
    )
    .build()?;
    assert!(matches!(
        revoke_credential(keeper.as_ref(), &state, revocation),
        Err(TransactionError::EstablishmentOnlyIssuer { trait_code: "EO" })
    ));
    Ok(())
}

/// Regression: a key state at the largest representable position cannot advance, and the failure
/// names the number rather than wrapping to zero.
#[test]
fn a_key_event_log_at_the_ceiling_cannot_advance() -> Result<(), Box<dyn std::error::Error>> {
    let document = serde_json::json!({
        "i": ISSUER,
        "s": format!("{:x}", u128::MAX),
        "p": "",
        "d": ISSUANCE,
        "f": "0",
        "dt": STAMP,
        "et": "icp",
        "kt": "1",
        "k": ["DAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"],
        "nt": "1",
        "n": [ISSUANCE],
        "bt": "0",
        "b": [],
        "c": [],
        "ee": {"s": "0", "d": ISSUANCE, "br": [], "ba": []},
        "di": "",
    });
    let state: KeyState = serde_json::from_value(document)?;
    let said = Said::from_qb64(ISSUANCE)?;
    assert!(matches!(
        anchor_event(&state, &TransactionSeal::new(said, 0, said)),
        Err(TransactionError::SequenceNumberOverflow { current }) if current == u128::MAX
    ));
    Ok(())
}
