//! Exact IPEX vectors recorded from the pinned TypeScript reference's own `Ipex` methods.
//!
//! Unlike Roadmap 6.1's and 6.2's fixtures, this one does not re-express the ported code: the
//! generator replaces `globalThis.fetch`, derives the sender's habitat by the same route the
//! pinned `test/app/test-utils.ts` derives its mock, and drives `Ipex.apply`, `.offer`, `.agree`,
//! `.grant`, and `.admit` end to end at the reference's production Argon2 cost. So the recorded
//! bytes, signatures, and attachment streams are the reference's real output — and the fixture
//! also proves each one appears among the literals `credentialing.test.ts` asserts.
//!
//! These tests therefore compare against the reference twice over: the message bytes and
//! attachments are rebuilt here, and the signatures are reproduced with a keeper derived from the
//! same published passcode.

use std::collections::BTreeMap;
use std::error::Error;

use serde::Deserialize;
use signify_acdc::credential::{Credential, RegistryIdentifier};
use signify_acdc::ipex::{
    ANCHOR_EMBED, ATTRIBUTES_LABEL, CREDENTIAL_EMBED, Disclosure, ISSUANCE_EMBED, IpexEnvelope, IpexRoute,
    MESSAGE_LABEL, SCHEMA_LABEL, admit, agree, apply, grant, offer,
};
use signify_crypto::salt::{Salt, SecurityTier};
use signify_keri::event::Timestamp;
use signify_keri::manager::{DerivationCost, IdentifierKeeper, KeeperFactory};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/acdc-ipex/v1.json");

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    generated_on: String,
    sources: Vec<String>,
    provenance: Provenance,
    declarations: Declarations,
    embedded_artifacts: EmbeddedArtifacts,
    messages: BTreeMap<String, MessageRecord>,
    pinned_confirmations: BTreeMap<String, serde_json::Value>,
    reference_quirks: Quirks,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    passcode: String,
    passcode_note: String,
    sender: String,
    recipient: String,
    timestamp: String,
    credential: String,
    issuance: String,
    anchor: String,
    anchor_attachment: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    routes: BTreeMap<String, String>,
    shapes: BTreeMap<String, Shape>,
    create_exchange_message: String,
    notes: DeclarationNotes,
}

#[derive(Debug, Deserialize)]
struct Shape {
    call: String,
    payload: Option<String>,
    embeds_argument: String,
    embeds_declaration: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeclarationNotes {
    payloads: String,
    embeds: String,
    signing: String,
}

#[derive(Debug, Deserialize)]
struct EmbeddedArtifacts {
    acdc_raw: String,
    iss_raw: String,
    anc_raw: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct MessageRecord {
    note: String,
    raw: String,
    said: String,
    size: usize,
    route: String,
    prior: String,
    embed_labels: Vec<String>,
    attachment: String,
    signatures: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Quirks {
    admit_message_has_no_default: AdmitQuirk,
    offer_embeds_an_undefined_attachment: OfferQuirk,
    grant_signs_the_anchor_when_no_attachment_is_given: ExpressionQuirk,
    routes_are_string_literals: ScanQuirk,
    sender_and_recipient_are_unvalidated: NoteQuirk,
    attributes_are_an_untyped_record: PayloadQuirk,
}

#[derive(Debug, Deserialize)]
struct AdmitQuirk {
    raw: String,
    said: String,
    payload_labels: Vec<String>,
    carries_message_field: bool,
    differs_from_empty_message: bool,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct OfferQuirk {
    embed_expression: String,
    attachment: String,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct ExpressionQuirk {
    expression: String,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct ScanQuirk {
    scan: Scan,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct NoteQuirk {
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct PayloadQuirk {
    payload_expression: String,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct Scan {
    needle: String,
    total: usize,
    files: Vec<ScanHit>,
    scanned_files: usize,
}

#[derive(Debug, Deserialize)]
struct ScanHit {
    file: String,
    count: usize,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(FIXTURE)?)
}

const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const LEI: &str = "5493001KJTIIGC8Y1R17";

/// The sender's keeper, derived from the passcode the pinned tests publish at the reference's own
/// production cost, so its signatures are the ones the reference recorded.
fn keeper(passcode: &str) -> Result<Box<dyn IdentifierKeeper>, Box<dyn Error>> {
    let salt = Salt::from_qb64(&format!("0AA{}", &passcode[..21]), SecurityTier::Low)?;
    let factory = KeeperFactory::new(salt);
    let request =
        signify_keri::identifier::CreateIdentifierRequest::new(signify_keri::identifier::CreateAlgorithm::Salty {
            passcode: Some(passcode.to_owned()),
            tier: SecurityTier::Low,
            current_count: 1,
            next_count: 1,
            cost: DerivationCost::Production,
        });
    Ok(factory.create(request.keeper_request(0)?)?)
}

fn envelope(fixture: &Fixture, message: &str) -> Result<IpexEnvelope, Box<dyn Error>> {
    Ok(IpexEnvelope::new(
        IdentifierPrefix::from_qb64(&fixture.provenance.sender)?,
        IdentifierPrefix::from_qb64(&fixture.provenance.recipient)?,
        message,
        fixture.provenance.timestamp.parse::<Timestamp>()?,
    )?)
}

/// The credential the pinned suite discloses, rebuilt from the fixture's recorded bytes.
fn credential(fixture: &Fixture) -> Result<Credential, Box<dyn Error>> {
    use signify_acdc::credential::{CredentialAttributes, CredentialBuilder};
    let sad = Sad::from_json_bytes(fixture.embedded_artifacts.acdc_raw.as_bytes())?;
    let attributes = sad
        .get("a")
        .and_then(SadValue::as_map)
        .ok_or("the recorded credential has no attribute block")?;
    Ok(CredentialBuilder::new(
        IdentifierPrefix::from_qb64(sad.get_text("i").ok_or("no issuer")?)?,
        RegistryIdentifier::from_qb64(sad.get_text("ri").ok_or("no registry")?)?,
        Said::from_qb64(sad.get_text("s").ok_or("no schema")?)?,
        CredentialAttributes::new(attributes.get_text("dt").ok_or("no timestamp")?.parse::<Timestamp>()?)
            .issuee(&IdentifierPrefix::from_qb64(
                attributes.get_text("i").ok_or("no issuee")?,
            )?)?
            .timestamp()?
            .text("LEI", attributes.get_text("LEI").ok_or("no LEI")?)?,
    )
    .build()?)
}

/// The disclosure a grant carries, assembled from the fixture's three recorded artifacts.
fn disclosure(fixture: &Fixture) -> Result<Disclosure, Box<dyn Error>> {
    use signify_acdc::issuance::IssuanceEvent;
    use signify_keri::attachment::{AttachmentFraming, SealSourceCouple};

    let credential = credential(fixture)?;
    let issuance = IssuanceEvent::for_credential(&credential)?;
    let anchor = SerializedEvent::parse(fixture.embedded_artifacts.anc_raw.as_bytes())?;
    let anchor_said = Said::from_qb64(anchor.said().ok_or("the anchor carries no identifier")?)?;
    let anchor_sequence = anchor
        .sequence_number()?
        .ok_or("the anchor carries no sequence number")?
        .value();
    let couple = SealSourceCouple::new(anchor_sequence.into(), anchor_said);

    Ok(Disclosure::new(
        credential.serialized().clone(),
        issuance.credential_attachment()?,
        issuance.serialized().clone(),
        couple.attachment(AttachmentFraming::Pipelined)?,
        anchor,
        fixture.provenance.anchor_attachment.clone().into_bytes(),
    ))
}

#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert!(fixture.upstream.contains("WebOfTrust/signify-ts"));
    assert!(!fixture.generated_on.is_empty());
    assert!(
        fixture
            .sources
            .iter()
            .any(|source| source.ends_with("credentialing.ts"))
    );
    assert!(fixture.sources.iter().any(|source| source.ends_with("exchanging.ts")));
    assert!(!fixture.provenance.note.is_empty());
    assert!(fixture.provenance.passcode_note.contains("PUBLIC TEST MATERIAL"));
    assert!(!fixture.embedded_artifacts.note.is_empty());
    assert_eq!(fixture.messages.len(), 8);
    Ok(())
}

#[test]
fn the_routes_are_the_literals_the_reference_writes() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let routes = &fixture.declarations.routes;
    assert_eq!(routes.len(), IpexRoute::ALL.len());
    for route in IpexRoute::ALL {
        let name = match route {
            IpexRoute::Apply => "apply",
            IpexRoute::Offer => "offer",
            IpexRoute::Agree => "agree",
            IpexRoute::Grant => "grant",
            IpexRoute::Admit => "admit",
        };
        assert_eq!(routes.get(name).map(String::as_str), Some(route.as_str()), "{name}");
    }

    // Only offer and grant declare an embed literal; only apply's payload names more than the
    // message.
    let shapes = &fixture.declarations.shapes;
    // Three routes embed nothing at all, and the two that do are the two whose Rust functions
    // take an artifact.
    for name in ["apply", "agree", "admit"] {
        let shape = shapes.get(name).ok_or_else(|| format!("no shape for {name}"))?;
        assert_eq!(shape.embeds_argument, "{}", "{name} embeds something");
        assert!(shape.embeds_declaration.is_none(), "{name}");
        assert!(!shape.call.is_empty(), "{name}");
    }
    let offer_shape = shapes.get("offer").ok_or("no shape for offer")?;
    assert!(offer_shape.embeds_argument.contains("acdc"));
    assert!(offer_shape.embeds_argument.contains("undefined"));
    let grant_shape = shapes.get("grant").ok_or("no shape for grant")?;
    let grant_embeds = grant_shape
        .embeds_declaration
        .as_deref()
        .ok_or("grant declares no embed literal")?;
    for label in [CREDENTIAL_EMBED, ISSUANCE_EMBED, ANCHOR_EMBED] {
        assert!(grant_embeds.contains(label), "grant does not embed {label}");
    }
    let apply_payload = shapes
        .get("apply")
        .and_then(|shape| shape.payload.as_deref())
        .ok_or("no apply payload")?;
    assert!(apply_payload.contains("s: args.schemaSaid"));
    assert!(apply_payload.contains("a: args.attributes"));

    assert!(fixture.declarations.create_exchange_message.contains("exchange("));
    assert!(fixture.declarations.create_exchange_message.contains("keeper.sign"));
    assert!(!fixture.declarations.notes.payloads.is_empty());
    assert!(!fixture.declarations.notes.embeds.is_empty());
    assert!(!fixture.declarations.notes.signing.is_empty());
    Ok(())
}

#[test]
fn every_message_matches_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let keeper = keeper(&fixture.provenance.passcode)?;
    let credential = credential(&fixture)?;
    let disclosure = disclosure(&fixture)?;
    let schema = Said::from_qb64(SCHEMA)?;

    let said_of = |name: &str| -> Result<Said, Box<dyn Error>> {
        let record = fixture.messages.get(name).ok_or_else(|| format!("no message {name}"))?;
        Ok(Said::from_qb64(&record.said)?)
    };

    let mut attributes = Sad::new();
    attributes.insert("LEI", SadValue::text(LEI))?;

    for (name, expected) in &fixture.messages {
        let built = match name.as_str() {
            "apply" => apply(
                keeper.as_ref(),
                &envelope(&fixture, "Applying")?,
                schema,
                attributes.clone(),
            )?,
            "apply_defaults" => apply(keeper.as_ref(), &envelope(&fixture, "")?, schema, Sad::new())?,
            "offer" => offer(
                keeper.as_ref(),
                &envelope(&fixture, "How about this")?,
                &credential,
                Some(said_of("apply")?),
            )?,
            "offer_without_apply" => offer(
                keeper.as_ref(),
                &envelope(&fixture, "How about this")?,
                &credential,
                None,
            )?,
            "agree" => agree(keeper.as_ref(), &envelope(&fixture, "OK!")?, said_of("offer")?)?,
            "grant" => grant(
                keeper.as_ref(),
                &envelope(&fixture, "")?,
                &disclosure,
                Some(said_of("agree")?),
            )?,
            "grant_without_agree" => grant(keeper.as_ref(), &envelope(&fixture, "")?, &disclosure, None)?,
            "admit" => admit(keeper.as_ref(), &envelope(&fixture, "")?, said_of("grant")?)?,
            other => return Err(format!("unknown message case {other:?}").into()),
        };

        assert!(!expected.note.is_empty(), "{name}");
        assert_eq!(built.raw(), expected.raw.as_bytes(), "{name}");
        assert_eq!(built.said().qb64()?, expected.said, "{name}");
        assert_eq!(built.raw().len(), expected.size, "{name}");
        assert_eq!(built.route().as_str(), expected.route, "{name}");
        assert_eq!(
            built.exchange().sad().get_text("p"),
            Some(expected.prior.as_str()),
            "{name}"
        );
        assert_eq!(
            core::str::from_utf8(built.attachments())?,
            expected.attachment,
            "{name}"
        );

        // The embed labels the reference wrote, in order, including the block's own identifier.
        let embeds: Vec<&str> = built
            .exchange()
            .sad()
            .get("e")
            .and_then(SadValue::as_map)
            .map(|block| block.entries().map(|(label, _)| label).collect())
            .unwrap_or_default();
        assert_eq!(embeds, expected.embed_labels, "{name}");

        // And the signatures the reference's own keeper produced.
        assert_eq!(built.signatures().qb64()?, expected.signatures, "{name}");
    }
    Ok(())
}

#[test]
fn the_payloads_carry_the_fields_each_route_names() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for (name, expected) in &fixture.messages {
        let sad = Sad::from_json_bytes(expected.raw.as_bytes())?;
        let payload = sad
            .get("a")
            .and_then(SadValue::as_map)
            .ok_or_else(|| format!("{name} has no attribute block"))?;
        let labels: Vec<&str> = payload.entries().map(|(label, _)| label).collect();

        // The recipient is always written first, before the payload the route supplies.
        assert_eq!(labels.first(), Some(&"i"), "{name}");
        assert_eq!(
            payload.get_text("i"),
            Some(fixture.provenance.recipient.as_str()),
            "{name}"
        );
        assert!(payload.contains(MESSAGE_LABEL), "{name}");

        if expected.route == IpexRoute::Apply.as_str() {
            assert_eq!(labels, ["i", MESSAGE_LABEL, SCHEMA_LABEL, ATTRIBUTES_LABEL], "{name}");
            assert_eq!(payload.get_text(SCHEMA_LABEL), Some(SCHEMA), "{name}");
        } else {
            assert_eq!(labels, ["i", MESSAGE_LABEL], "{name}");
        }
    }
    Ok(())
}

#[test]
fn only_a_grant_carries_attachments() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for (name, expected) in &fixture.messages {
        if expected.route == IpexRoute::Grant.as_str() {
            assert!(!expected.attachment.is_empty(), "{name}");
            // One pathed group per embed, in the order the embeds appear.
            assert!(expected.attachment.contains("-e-acdc"), "{name}");
            assert!(expected.attachment.contains("-e-iss"), "{name}");
            assert!(expected.attachment.contains("-e-anc"), "{name}");
            assert_eq!(expected.attachment.len() % 4, 0, "{name}");
            assert_eq!(
                expected.embed_labels,
                [CREDENTIAL_EMBED, ISSUANCE_EMBED, ANCHOR_EMBED, "d"]
            );
        } else {
            assert!(expected.attachment.is_empty(), "{name} carries an attachment");
        }
    }
    Ok(())
}

#[test]
fn the_conversation_chains_by_prior_identifier() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let said = |name: &str| -> Option<&str> { fixture.messages.get(name).map(|record| record.said.as_str()) };
    let prior = |name: &str| -> Option<&str> { fixture.messages.get(name).map(|record| record.prior.as_str()) };

    // The pinned suite's full conversation: apply → offer → agree → grant → admit.
    assert_eq!(prior("apply"), Some(""));
    assert_eq!(prior("offer"), said("apply"));
    assert_eq!(prior("agree"), said("offer"));
    assert_eq!(prior("grant"), said("agree"));
    assert_eq!(prior("admit"), said("grant"));

    // And the two openings that carry no prior at all.
    assert_eq!(prior("offer_without_apply"), Some(""));
    assert_eq!(prior("grant_without_agree"), Some(""));
    assert!(IpexRoute::Offer.may_open_a_conversation());
    assert!(IpexRoute::Grant.may_open_a_conversation());
    Ok(())
}

#[test]
fn every_message_appears_among_the_literals_the_pinned_test_asserts() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for route in ["apply", "offer", "agree", "grant", "admit"] {
        let confirmation = fixture
            .pinned_confirmations
            .get(route)
            .ok_or_else(|| format!("no confirmation for {route}"))?;
        assert_eq!(
            confirmation
                .get("said_is_published")
                .and_then(serde_json::Value::as_bool),
            Some(true),
            "{route}"
        );
        assert_eq!(
            confirmation
                .get("signature_is_published")
                .and_then(serde_json::Value::as_bool),
            Some(true),
            "{route}"
        );
        assert_eq!(
            confirmation.get("route").and_then(serde_json::Value::as_str),
            Some(format!("/ipex/{route}").as_str()),
            "{route}"
        );
    }
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = &fixture.reference_quirks;
    let pairs: [(&str, &str); 6] = [
        (
            &quirks.admit_message_has_no_default.note,
            &quirks.admit_message_has_no_default.rust_decision,
        ),
        (
            &quirks.offer_embeds_an_undefined_attachment.note,
            &quirks.offer_embeds_an_undefined_attachment.rust_decision,
        ),
        (
            &quirks.grant_signs_the_anchor_when_no_attachment_is_given.note,
            &quirks.grant_signs_the_anchor_when_no_attachment_is_given.rust_decision,
        ),
        (
            &quirks.routes_are_string_literals.note,
            &quirks.routes_are_string_literals.rust_decision,
        ),
        (
            &quirks.sender_and_recipient_are_unvalidated.note,
            &quirks.sender_and_recipient_are_unvalidated.rust_decision,
        ),
        (
            &quirks.attributes_are_an_untyped_record.note,
            &quirks.attributes_are_an_untyped_record.rust_decision,
        ),
    ];
    for (index, (note, decision)) in pairs.iter().enumerate() {
        assert!(!note.is_empty(), "divergence {index} records no reference behaviour");
        assert!(!decision.is_empty(), "divergence {index} records no Rust decision");
    }
    Ok(())
}

#[test]
fn every_reference_quirk_holds_and_the_divergence_is_deliberate() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = &fixture.reference_quirks;

    // 1. An admit built with no message emits no `m` at all, and a different identifier from one
    //    carrying the empty string. Unrepresentable here: the message is required.
    let admit_quirk = &quirks.admit_message_has_no_default;
    assert!(!admit_quirk.carries_message_field);
    assert_eq!(admit_quirk.payload_labels, ["i"]);
    assert!(admit_quirk.differs_from_empty_message);
    assert!(!admit_quirk.raw.contains(r#""m":"#));
    let recorded_admit = fixture.messages.get("admit").ok_or("no admit")?;
    assert_ne!(admit_quirk.said, recorded_admit.said);
    assert!(recorded_admit.raw.contains(r#""m":"""#));

    // 2. An offer embeds the credential with no attachment, which writes nothing to the stream —
    //    distinct from an explicitly empty attachment, which still writes its path.
    let offer_quirk = &quirks.offer_embeds_an_undefined_attachment;
    assert!(offer_quirk.embed_expression.contains("undefined"));
    assert!(offer_quirk.attachment.is_empty());
    let recorded_offer = fixture.messages.get("offer").ok_or("no offer")?;
    assert!(recorded_offer.attachment.is_empty());
    assert_eq!(recorded_offer.embed_labels, [CREDENTIAL_EMBED, "d"]);

    // 3. A grant with no anchor attachment signs the issuer's key event with the *sender's*
    //    keeper. Here the attachment is a required input.
    let signing_quirk = &quirks.grant_signs_the_anchor_when_no_attachment_is_given;
    assert!(signing_quirk.expression.contains("keeper.sign"));
    assert!(signing_quirk.expression.contains("messagize"));

    // 4. The routes are bare literals upstream and a typed enum here.
    let routes = &quirks.routes_are_string_literals;
    assert_eq!(routes.scan.needle, "/ipex/");
    assert!(routes.scan.total > 0);
    assert!(routes.scan.scanned_files > 100);
    assert!(
        routes
            .scan
            .files
            .iter()
            .any(|hit| hit.file.ends_with("credentialing.ts") && hit.count >= 5)
    );

    // 5. The recipient is free text upstream; an unparseable one is refused here.
    assert!(IdentifierPrefix::from_qb64("not an identifier").is_err());

    // 6. An apply's attributes are an untyped record upstream; here they are an ordered `Sad`, and
    //    one naming the recipient label is refused rather than silently readdressing the message.
    let attributes_quirk = &quirks.attributes_are_an_untyped_record;
    assert!(attributes_quirk.payload_expression.contains("args.attributes"));
    let keeper = keeper(&fixture.provenance.passcode)?;
    let mut hostile = Sad::new();
    hostile.insert("i", SadValue::text("EHIJACK"))?;
    assert!(matches!(
        apply(
            keeper.as_ref(),
            &envelope(&fixture, "")?,
            Said::from_qb64(SCHEMA)?,
            hostile,
        ),
        Err(signify_acdc::error::IpexError::ReservedPayloadLabel { label: "i" })
    ));
    Ok(())
}

#[test]
fn the_embedded_artifacts_are_the_ones_earlier_items_build() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let credential = credential(&fixture)?;
    assert_eq!(credential.raw(), fixture.embedded_artifacts.acdc_raw.as_bytes());
    assert_eq!(credential.said().qb64()?, fixture.provenance.credential);

    let issuance = signify_acdc::issuance::IssuanceEvent::for_credential(&credential)?;
    assert_eq!(issuance.raw(), fixture.embedded_artifacts.iss_raw.as_bytes());
    assert_eq!(issuance.said().qb64()?, fixture.provenance.issuance);

    let anchor = SerializedEvent::parse(fixture.embedded_artifacts.anc_raw.as_bytes())?;
    assert_eq!(anchor.said(), Some(fixture.provenance.anchor.as_str()));
    Ok(())
}
