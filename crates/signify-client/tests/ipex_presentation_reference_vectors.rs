//! Exact vectors for the IPEX presentation workflow.
//!
//! The five-step conversation and two group rounds, and the shared clock a group's agreement depends on.

mod support;

use std::error::Error;

use keria_types::api::{Credential, ExchangeResource};
use serde::Deserialize;
use serde_json::Value;
use signify_acdc::ipex::IpexRoute;
use signify_client::error::ClientError;
use signify_client::presentation::{
    ATTRIBUTE_FILTER_PREFIX, ReceivedStep, SCHEMA_FILTER, disclosure_of, requested_credentials,
};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-ipex-presentation/v1.json");

const EXCHANGE_ROUTE: &str = "/multisig/exn";

// --- Fixture model ---
#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    generated_on: String,
    sources: Vec<String>,
    provenance: Provenance,
    declarations: Declarations,
    identifier_record: Value,
    group_record: Value,
    held_credential: Credential,
    calls: Vec<Call>,
    pinned_confirmations: PinnedConfirmations,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    fixed_clock_ms: u64,
    shared_stamp: String,
    other_stamp: String,
    local_member_prefix: String,
    peer_prefix: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    grant_multisig: String,
    admit_multisig: String,
    multisig_admit_credential: String,
    waiter_return: String,
    admit_parameters: Parameters,
    grant_defaults: GrantDefaults,
    notification_waits: Vec<NotificationWait>,
    ipex_calls: Vec<IpexCall>,
    grant_arguments: Vec<GrantArguments>,
    said_guards: Guards,
    shared_clock: SharedClock,
    scanned_files: usize,
    notes: Value,
}

#[derive(Debug, Deserialize)]
struct Parameters {
    declared: Vec<String>,
    commented_out: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GrantDefaults {
    text: String,
    resigns_the_anchor: bool,
    credential_attachment_default: bool,
    issuance_attachment_default: bool,
}

#[derive(Debug, Deserialize)]
struct NotificationWait {
    file: String,
    enclosing: String,
    route: String,
    binds: Option<String>,
    discarded: bool,
}

#[derive(Debug, Deserialize)]
struct IpexCall {
    file: String,
    step: String,
    enclosing: String,
    arguments: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GrantArguments {
    file: String,
    enclosing: String,
    attachments: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Guards {
    #[serde(rename = "admitMultisig")]
    admit_multisig: bool,
    #[serde(rename = "multisigAdmitCredential")]
    multisig_admit_credential: bool,
    credentials_test_inline: bool,
}

#[derive(Debug, Deserialize)]
struct SharedClock {
    declaration: bool,
    text: String,
    file: String,
    asserted: bool,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
    requests: Vec<RecordedRequest>,
    result: Value,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    path: String,
    method: String,
    body: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PinnedConfirmations {
    group: String,
    schema: String,
    credential: String,
    apply: String,
    offer: String,
    agree: String,
    chain: Vec<ChainLink>,
    apply_slots: Vec<String>,
    offer_slots: Vec<String>,
    grant_slots: Vec<String>,
    issuance_grant_slots: Vec<String>,
    announcement_route: String,
    announcement_topic: String,
    announcement_slots: Vec<String>,
    announcement_attributes: Vec<String>,
    presentation_paths: Vec<String>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct ChainLink {
    step: String,
    said: String,
    prior: Option<String>,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(FIXTURE)?)
}

fn call<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a Call, Box<dyn Error>> {
    fixture
        .calls
        .iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| format!("no recorded call named {name}").into())
}

fn body(fixture: &Fixture, name: &str, ending: &str) -> Result<Value, Box<dyn Error>> {
    let recorded = call(fixture, name)?;
    let request = recorded
        .requests
        .iter()
        .find(|entry| entry.path.ends_with(ending))
        .ok_or_else(|| format!("{name} posted nothing to {ending}"))?;
    let text = request.body.as_deref().ok_or("the request carried no body")?;
    Ok(serde_json::from_str(text)?)
}

fn quirk<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a Value, Box<dyn Error>> {
    fixture
        .reference_quirks
        .get(name)
        .ok_or_else(|| format!("no recorded divergence named {name}").into())
}

// --- Provenance ---
#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert_eq!(fixture.upstream, "https://github.com/WebOfTrust/signify-ts.git");
    assert_eq!(fixture.generated_on, "2026-09-16");
    assert!(
        fixture
            .sources
            .contains(&"test-integration/credentials.test.ts".to_owned())
    );
    assert!(
        fixture
            .sources
            .contains(&"test-integration/utils/multisig-utils.ts".to_owned())
    );

    assert_eq!(fixture.provenance.bran, "0123456789abcdefghijk");
    assert_eq!(fixture.provenance.fixed_clock_ms, 1_700_000_000_123);
    assert_ne!(fixture.provenance.shared_stamp, fixture.provenance.other_stamp);
    assert!(fixture.provenance.note.contains("transpiled in memory"));
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    for record in [&fixture.identifier_record, &fixture.group_record] {
        let text = serde_json::to_string(record)?;
        assert!(text.contains("sxlt_opens_to"), "a sealed salt was recorded unopened");
        assert!(text.contains(r#""sxlt":"<SXLT>""#));
    }
    assert!(fixture.declarations.scanned_files > 100);
    assert!(!fixture.calls.is_empty());

    assert_eq!(fixture.provenance.local_member_prefix.len(), 44);
    assert_eq!(fixture.provenance.peer_prefix.len(), 44);
    assert_ne!(fixture.provenance.local_member_prefix, fixture.provenance.peer_prefix);
    Ok(())
}

#[test]
fn every_driven_round_succeeded() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.calls.len(), 16);
    for entry in &fixture.calls {
        assert!(entry.error.is_none(), "{} failed: {:?}", entry.name, entry.error);
        assert!(!entry.requests.is_empty(), "{} sent nothing", entry.name);
        assert_ne!(entry.note, "");

        assert!(
            entry.requests.iter().any(|request| request.method == "POST"),
            "{} only read",
            entry.name
        );
        assert!(
            entry
                .requests
                .iter()
                .any(|request| request.method == "GET" && request.path.starts_with("/identifiers/")),
            "{} never read its own identifier",
            entry.name
        );
    }

    for name in [
        "issuer_grants_the_credential",
        "holder_admits_the_grant",
        "verifier_applies",
        "holder_offers",
        "verifier_agrees",
        "holder_discloses",
    ] {
        let recorded = call(&fixture, name)?;
        assert!(
            recorded.result.get("said").and_then(Value::as_str).is_some(),
            "{name} recorded no message"
        );
    }
    Ok(())
}

// --- The chain: each step names the one it answers ---
#[test]
fn the_conversation_is_a_chain() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let chain = &fixture.pinned_confirmations.chain;
    assert_eq!(chain.len(), 4);

    let opening = chain.first().ok_or("the chain is empty")?;
    assert_eq!(opening.step, "apply");
    assert_eq!(opening.prior.as_deref(), Some(""));

    for window in chain.windows(2) {
        let [earlier, later] = window else {
            return Err("a chain window was not a pair".into());
        };
        assert_eq!(
            later.prior.as_deref(),
            Some(earlier.said.as_str()),
            "{} does not answer {}",
            later.step,
            earlier.step
        );
    }
    assert_eq!(
        chain.get(1).map(|link| link.said.as_str()),
        Some(fixture.pinned_confirmations.offer.as_str())
    );
    assert_eq!(
        chain.get(2).map(|link| link.said.as_str()),
        Some(fixture.pinned_confirmations.agree.as_str())
    );
    Ok(())
}

#[test]
fn each_step_embeds_what_its_route_carries() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_confirmations;

    assert_eq!(pinned.apply_slots, [] as [String; 0]);
    assert_eq!(pinned.offer_slots, ["acdc"]);
    assert_eq!(pinned.grant_slots, ["acdc", "iss", "anc"]);
    assert_eq!(pinned.issuance_grant_slots, pinned.grant_slots);

    assert_eq!(
        pinned.presentation_paths,
        ["GET /identifiers/member1", "POST /identifiers/member1/ipex/apply"]
    );
    assert!(pinned.note.contains("embed nothing"));
    Ok(())
}

// --- The findings ---
#[test]
fn a_group_round_agrees_only_on_a_shared_clock() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "a_group_round_agrees_only_on_a_shared_clock")?;

    assert_eq!(recorded.get("grants_agree").and_then(Value::as_bool), Some(true));
    assert_eq!(recorded.get("admits_agree").and_then(Value::as_bool), Some(true));

    assert_eq!(
        recorded.get("divergent_grant_agrees").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        recorded.get("divergent_admit_agrees").and_then(Value::as_bool),
        Some(false)
    );
    let errors = recorded
        .get("divergent_errors")
        .and_then(Value::as_array)
        .ok_or("no recorded errors")?;
    assert_eq!(errors.len(), 2);
    assert!(
        errors.iter().all(Value::is_null),
        "a divergent round reported something"
    );

    let clock = &fixture.declarations.shared_clock;
    assert!(clock.declaration, "the holder test no longer pins one clock");
    assert_eq!(clock.text, "const TIME = createTimestamp();");
    assert_eq!(clock.file, "test-integration/multisig-holder.test.ts");

    assert!(clock.asserted);
    assert_eq!(
        recorded.get("asserted_upstream").and_then(Value::as_str),
        Some("assert.equal(admitResult1.admitSaid, admitResult2.admitSaid)")
    );
    Ok(())
}

#[test]
fn a_joining_member_never_reads_the_proposal() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "a_joining_member_never_reads_the_proposal")?;

    assert_eq!(
        recorded.get("group_requests_made").and_then(Value::as_bool),
        Some(false)
    );

    let waits = recorded.get("waits").and_then(Value::as_array).ok_or("no waits")?;
    assert_eq!(waits.len(), 3);
    for wait in waits {
        assert_eq!(wait.get("route").and_then(Value::as_str), Some(EXCHANGE_ROUTE));
        assert_eq!(wait.get("discarded").and_then(Value::as_bool), Some(true));
        assert!(wait.get("binds").is_some_and(Value::is_null));
    }

    let bound: Vec<&NotificationWait> = fixture
        .declarations
        .notification_waits
        .iter()
        .filter(|wait| !wait.discarded)
        .collect();
    assert!(!bound.is_empty(), "no wait anywhere binds its SAID");
    assert!(
        bound.iter().all(|wait| wait.binds.is_some()),
        "a bound wait records no binding"
    );
    assert!(bound.iter().any(|wait| wait.route == "/exn/ipex/grant"));

    for wait in &fixture.declarations.notification_waits {
        assert!(!wait.file.is_empty() && !wait.enclosing.is_empty());
        assert!(wait.route.starts_with('/'), "a wait names no route");
    }
    Ok(())
}

#[test]
fn a_notification_need_not_name_a_message() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "a_notification_need_not_name_a_message")?;

    assert_eq!(
        fixture.declarations.waiter_return,
        "return notes[notes.length - 1]?.a.d ?? '';"
    );

    assert_eq!(recorded.get("admit_prior").and_then(Value::as_str), Some(""));
    assert!(recorded.get("error").is_some_and(Value::is_null));
    assert!(recorded.get("admit_said").and_then(Value::as_str).is_some());

    let guards = &fixture.declarations.said_guards;
    assert!(guards.credentials_test_inline, "the inline step no longer guards it");
    assert!(
        !guards.admit_multisig,
        "`admitMultisig` now guards it; the finding is stale"
    );
    assert!(!guards.multisig_admit_credential);
    Ok(())
}

#[test]
fn only_the_last_notification_survives() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "only_the_last_notification_survives")?;

    assert_eq!(
        fixture.declarations.admit_parameters.commented_out,
        ["numGrantMsgs: number"]
    );
    assert!(
        !fixture
            .declarations
            .admit_parameters
            .declared
            .iter()
            .any(|parameter| parameter.contains("numGrantMsgs")),
        "the parameter is declared after all"
    );
    assert_eq!(
        recorded
            .get("commented_out_parameter")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    Ok(())
}

#[test]
fn a_grant_assembles_its_attachments_three_ways() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "a_grant_assembles_its_attachments_three_ways")?;

    let mut sets: Vec<Vec<String>> = fixture
        .declarations
        .grant_arguments
        .iter()
        .map(|call| call.attachments.clone())
        .collect();
    sets.sort();
    sets.dedup();
    assert_eq!(sets.len(), 3, "the tree no longer disagrees with itself: {sets:?}");
    assert!(sets.contains(&Vec::new()));
    assert!(sets.contains(&vec!["ancAttachment".to_owned()]));
    assert!(sets.contains(&vec![
        "acdcAttachment".to_owned(),
        "ancAttachment".to_owned(),
        "issAttachment".to_owned()
    ]));
    assert!(
        fixture
            .declarations
            .grant_arguments
            .iter()
            .any(|call| call.enclosing == "grantMultisig" && call.attachments.is_empty()),
        "the group grant now passes attachments"
    );

    let files: std::collections::BTreeSet<&str> = fixture
        .declarations
        .grant_arguments
        .iter()
        .map(|call| call.file.as_str())
        .collect();
    assert!(files.len() >= 3, "the grants no longer span three files: {files:?}");

    let defaults = &fixture.declarations.grant_defaults;
    assert!(
        defaults.resigns_the_anchor,
        "the re-signing branch is gone; the finding is stale"
    );
    assert!(defaults.credential_attachment_default);
    assert!(defaults.issuance_attachment_default);
    assert!(defaults.text.contains("keeper.sign"));

    assert!(recorded.get("with_attachment").and_then(Value::as_str).is_some());
    assert!(recorded.get("without_attachment").and_then(Value::as_str).is_some());
    Ok(())
}

// --- What this port does with the same material ---
#[test]
fn the_recorded_apply_becomes_the_filter_the_reference_assembles_by_hand() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let posted = body(&fixture, "verifier_applies", "/ipex/apply")?;
    let exn = posted.get("exn").ok_or("the apply posted no message")?;
    let resource: ExchangeResource = serde_json::from_value(serde_json::json!({"exn": exn, "pathed": {}}))?;

    let step = ReceivedStep::of("", &resource)?;
    assert_eq!(step.route(), IpexRoute::Apply);
    assert_eq!(step.said()?.qb64()?, fixture.pinned_confirmations.apply);

    let written = String::from_utf8(requested_credentials(&step)?.to_json_bytes()?)?;
    let schema = &fixture.pinned_confirmations.schema;
    assert!(
        written.contains(&format!(r#""{SCHEMA_FILTER}":"{schema}""#)),
        "{written}"
    );
    assert!(
        written.contains(&format!(r#""{ATTRIBUTE_FILTER_PREFIX}LEI":"5493001KJTIIGC8Y1R17""#)),
        "{written}"
    );
    Ok(())
}

#[test]
fn the_recorded_credential_discloses_without_re_signing_anything() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;

    let disclosure = disclosure_of(&fixture.held_credential)?;
    assert_eq!(
        disclosure.credential().said(),
        Some(fixture.pinned_confirmations.credential.as_str()),
        "the credential did not survive the round trip"
    );
    assert_eq!(
        disclosure.issuance().said(),
        Some(fixture.held_credential.iss.digest.as_str())
    );
    assert_eq!(disclosure.anchor().said(), Some(fixture.held_credential.anc.digest()));

    assert_ne!(fixture.held_credential.atc, "");
    assert_ne!(fixture.held_credential.issatc, "");
    assert_ne!(fixture.held_credential.ancatc, [] as [String; 0]);
    Ok(())
}

#[test]
fn a_step_answers_only_the_step_it_was_given() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let posted = body(&fixture, "holder_offers", "/ipex/offer")?;
    let exn = posted.get("exn").ok_or("the offer posted no message")?;
    let resource: ExchangeResource = serde_json::from_value(serde_json::json!({"exn": exn, "pathed": {}}))?;

    let step = ReceivedStep::of("", &resource)?;
    assert_eq!(step.route(), IpexRoute::Offer);

    assert_eq!(
        step.answers()?.map(|said| said.qb64()).transpose()?,
        Some(fixture.pinned_confirmations.apply.clone())
    );

    let refused = matches!(
        requested_credentials(&step),
        Err(ClientError::WrongDisclosureStep { .. })
    );
    assert!(refused, "an offer was read as an apply");
    Ok(())
}

#[test]
fn a_group_announcement_carries_the_whole_message() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_confirmations;

    assert_eq!(pinned.announcement_route, EXCHANGE_ROUTE);
    assert_eq!(pinned.announcement_topic, "multisig");
    assert_eq!(pinned.announcement_slots, ["exn"]);
    // The reference's block is `{ i, gid }`: no member lists. This port writes `smids` and
    // `rmids` beside the group, which `driven::the_group_announcement_names_its_members` pins.
    assert_eq!(pinned.announcement_attributes, ["i", "gid"]);
    assert!(!pinned.announcement_attributes.contains(&"smids".to_owned()));
    let recorded = quirk(&fixture, "an_announcement_names_only_the_group")?;
    assert_eq!(
        recorded.get("announcement_attributes"),
        Some(&serde_json::json!(["i", "gid"]))
    );
    assert!(
        recorded
            .get("declaration")
            .and_then(Value::as_str)
            .is_some_and(|text| text.contains("gid: string") && !text.contains("smids")),
        "the reference's declaration names members"
    );
    assert!(
        recorded
            .get("recipients_source")
            .and_then(Value::as_str)
            .is_some_and(|text| text.contains("members.signing")),
        "the reference derives members from somewhere other than the members endpoint"
    );
    assert_eq!(pinned.group.len(), 44);

    let posted = body(&fixture, "group_proposes_the_admittance", "/exchanges")?;
    let text = serde_json::to_string(&posted)?;
    let route = text
        .find(r#""r":"/multisig/exn""#)
        .ok_or("no route in the announcement")?;
    let embed = text.find(r#""exn":{"#).ok_or("no embed in the announcement")?;
    assert!(route < text.len() && embed > 0);
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the divergences are not an object")?;
    assert_eq!(quirks.len(), 6);
    for (name, recorded) in quirks {
        let note = recorded.get("note").and_then(Value::as_str).unwrap_or_default();
        let decision = recorded
            .get("rust_decision")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(note.len() > 80, "{name} explains too little");
        assert!(decision.len() > 40, "{name} does not say what this port does");
    }

    for text in [
        &fixture.declarations.grant_multisig,
        &fixture.declarations.admit_multisig,
        &fixture.declarations.multisig_admit_credential,
    ] {
        assert!(text.contains("waitAndMarkNotification"), "a helper text is truncated");
        assert!(text.contains("ipex()"));
    }

    assert!(fixture.declarations.ipex_calls.len() >= 10);
    for entry in &fixture.declarations.ipex_calls {
        assert!(!entry.file.is_empty() && !entry.enclosing.is_empty());
        assert!(
            ["apply", "offer", "agree", "grant", "admit"].contains(&entry.step.as_str()),
            "{} is not an IPEX step",
            entry.step
        );
        assert_ne!(entry.arguments, [] as [String; 0]);
    }
    assert!(fixture.declarations.notes.get("waiter").is_some());
    Ok(())
}

/// The two group rounds driven through this port against a scripted agent.
///
/// The fixture records the reference's helpers, which take the peers as an argument. A joining
/// member here has no such argument: it reads them from the proposal, or asks the agent. Both are
/// driven, and so is the defect this replaced — a joining member that read the group's *keys* as
/// its members and never found itself.
mod driven {
    use super::*;
    use std::sync::Arc;

    use crate::support::{ADMIN, AgentTransport, BOOT, PASSCODE, agent_state, block_on, clock};
    use keri_cesr::crypto::cipher::Encrypter;
    use keri_cesr::crypto::salt::{Salt, SecurityTier};
    use keri_cesr::crypto::verifier::KeyTransferability;
    use signify_acdc::ipex::Disclosure;
    use signify_client::client::{ConnectedClient, SignifyClient};
    use signify_client::config::ClientConfig;
    use signify_client::multisig::GroupDisclosureRequest;
    use signify_http::transport::Transport;
    use signify_keri::event::Timestamp;
    use signify_keri::manager::DerivationCost;
    use signify_keri::prefix::IdentifierPrefix;
    use signify_keri::said::Said;

    const ALIAS: &str = "member1";
    const GROUP_NAME: &str = "multisig";
    const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
    const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
    const THIRD: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
    const STAMP: &str = "2023-11-14T22:13:20.123000+00:00";

    fn connected(bodies: &[&[u8]]) -> Result<(ConnectedClient, Arc<AgentTransport>), Box<dyn Error>> {
        let configuration = || {
            ClientConfig::new(ADMIN, PASSCODE)
                .and_then(|config| config.with_boot_url(BOOT))
                .map(|config| config.with_derivation_cost(DerivationCost::Ephemeral))
        };
        let probe = SignifyClient::new(
            configuration()?,
            AgentTransport::new(&[]) as Arc<dyn Transport>,
            clock(),
        )?;
        let prefix = probe.controller().prefix().qb64()?;
        let inception = core::str::from_utf8(probe.controller().current_event().raw())?.to_owned();

        let state = agent_state(&prefix, &inception);
        let mut answers: Vec<&[u8]> = vec![state.as_bytes(), b"{}"];
        answers.extend_from_slice(bodies);
        let transport = AgentTransport::new(&answers);

        let client = SignifyClient::new(configuration()?, Arc::clone(&transport) as Arc<dyn Transport>, clock())?;
        Ok((block_on(client.connect())?, transport))
    }

    type SentRequest = (String, String, Option<String>);

    fn sent(transport: &AgentTransport) -> Result<Vec<SentRequest>, Box<dyn Error>> {
        transport
            .requests()
            .into_iter()
            .skip(2)
            .map(|request| Ok((request.resource(), request.method().to_owned(), request.body_text())))
            .collect()
    }

    fn sealing_key() -> Result<Encrypter, Box<dyn Error>> {
        let salt = Salt::from_qb64(&format!("0AA{PASSCODE}"), SecurityTier::Low)?;
        let signer = salt.derive_signer("", KeyTransferability::NonTransferable)?;
        Ok(Encrypter::from_verification_key(signer.verifier())?)
    }

    /// Seals the salt a recorded `salty` block says it opens to, under the test passcode's key.
    fn seal(salty: &mut Value) -> Result<(), Box<dyn Error>> {
        let opens_to = salty
            .get("sxlt_opens_to")
            .and_then(Value::as_str)
            .ok_or("the recorded key-manager block carries no sealed salt")?
            .to_owned();
        let sealed = sealing_key()?
            .encrypt_salt(&Salt::from_qb64(&opens_to, SecurityTier::Low)?)?
            .qb64()?;
        let block = salty.as_object_mut().ok_or("the key-manager block is not an object")?;
        block.remove("sxlt_opens_to");
        block.insert("sxlt".to_owned(), Value::String(sealed));
        Ok(())
    }

    fn identifier_record(fixture: &Fixture) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut record = fixture.identifier_record.clone();
        seal(
            record
                .get_mut("salty")
                .ok_or("the recorded member has no key-manager block")?,
        )?;
        Ok(serde_json::to_vec(&record)?)
    }

    fn group_record(fixture: &Fixture) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut record = fixture.group_record.clone();
        let member = record
            .get_mut("group")
            .and_then(|group| group.get_mut("mhab"))
            .and_then(|member| member.get_mut("salty"))
            .ok_or("the recorded group has no member key-manager block")?;
        seal(member)?;
        Ok(serde_json::to_vec(&record)?)
    }

    /// The agent's listing of the group's members.
    fn members(signing: &[&str]) -> Vec<u8> {
        let entries: Vec<String> = signing
            .iter()
            .map(|aid| format!(r#"{{"aid":"{aid}","ends":{{}}}}"#))
            .collect();
        format!(r#"{{"signing":[{}],"rotation":[]}}"#, entries.join(",")).into_bytes()
    }

    /// One of the reference's own proposals, as `GET /multisig/request/{said}` lists it.
    ///
    /// Its attribute block is the reference's `{ i, gid }`; `named` adds the member lists this
    /// port writes.
    fn proposal(fixture: &Fixture, name: &str, named: Option<&[&str]>) -> Result<(Said, Vec<u8>), Box<dyn Error>> {
        let posted = body(fixture, name, "/exchanges")?;
        let mut exn = posted.get("exn").cloned().ok_or("the announcement carries no exn")?;
        if let Some(members) = named {
            let list = Value::Array(members.iter().map(|m| Value::String((*m).to_owned())).collect());
            let attributes = exn
                .get_mut("a")
                .and_then(Value::as_object_mut)
                .ok_or("the announcement has no attribute block")?;
            attributes.insert("smids".to_owned(), list.clone());
            attributes.insert("rmids".to_owned(), list);
        }
        let said = Said::from_qb64(exn.get("d").and_then(Value::as_str).ok_or("no SAID")?)?;
        let listing = serde_json::json!([{ "exn": exn, "paths": {} }]);
        Ok((said, serde_json::to_vec(&listing)?))
    }

    fn prefix(text: &str) -> Result<IdentifierPrefix, Box<dyn Error>> {
        Ok(IdentifierPrefix::from_qb64(text)?)
    }

    fn disclosure(fixture: &Fixture) -> Result<Disclosure, Box<dyn Error>> {
        Ok(disclosure_of(&fixture.held_credential)?)
    }

    /// The proposer's round, scripted whole: the member, the group twice, the grant's answer, the
    /// group, the member again, and the announcement's answer.
    #[test]
    fn the_group_announcement_names_its_members() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let member = identifier_record(&fixture)?;
        let group = group_record(&fixture)?;
        let (client, transport) = connected(&[&member, &group, &group, b"{}", &group, &member, b"{}"])?;

        let members = [prefix(LOCAL)?, prefix(PEER)?];
        let disclosed = block_on(client.multisig().propose_disclosure(&GroupDisclosureRequest {
            group_name: GROUP_NAME,
            local_member: ALIAS,
            members: &members,
            recipient: prefix(THIRD)?,
            disclosure: disclosure(&fixture)?,
            message: "from the group".to_owned(),
            timestamp: STAMP.parse::<Timestamp>()?,
        }))?;
        assert_eq!(disclosed.said().qb64()?.len(), 44);

        let requests = sent(&transport)?;
        let (path, method, body) = requests.last().ok_or("nothing was sent")?;
        assert_eq!(
            (path.as_str(), method.as_str()),
            ("/identifiers/member1/exchanges", "POST")
        );
        let posted: Value = serde_json::from_str(body.as_deref().ok_or("the announcement has no body")?)?;
        let exn = posted.get("exn").ok_or("no exn")?;
        assert_eq!(exn.get("r").and_then(Value::as_str), Some("/multisig/exn"));
        assert_eq!(exn.get("rp").and_then(Value::as_str), Some(PEER));
        let attributes = exn.get("a").ok_or("no attribute block")?;
        assert_eq!(
            attributes.get("gid").and_then(Value::as_str),
            Some(fixture.pinned_confirmations.group.as_str())
        );
        let both = Value::Array(vec![Value::String(LOCAL.to_owned()), Value::String(PEER.to_owned())]);
        assert_eq!(
            attributes.get("smids"),
            Some(&both),
            "the announcement does not name who signs"
        );
        assert_eq!(
            attributes.get("rmids"),
            Some(&both),
            "the announcement does not name who rotates"
        );
        // The reference's shape, pinned beside it: `{ i, gid }` and nothing else.
        assert_eq!(fixture.pinned_confirmations.announcement_attributes, ["i", "gid"]);
        assert_eq!(
            posted.get("rec"),
            Some(&Value::Array(vec![Value::String(PEER.to_owned())]))
        );
        Ok(())
    }

    #[test]
    fn a_joining_member_resolves_its_peers_through_the_members_endpoint() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (said, listing) = proposal(&fixture, "group_proposes_the_disclosure", None)?;
        let member = identifier_record(&fixture)?;
        let group = group_record(&fixture)?;
        let (client, transport) = connected(&[&member, &listing, &members(&[LOCAL, PEER]), &group])?;

        let outcome = block_on(
            client
                .multisig()
                .accept_disclosure(GROUP_NAME, ALIAS, &said, &disclosure(&fixture)?),
        );

        // The reference's proposal names nobody, so the agent is asked — and the answer names this
        // member, so the round goes on to build the grant under the group's alias.
        let requests = sent(&transport)?;
        let paths: Vec<&str> = requests.iter().map(|(path, _, _)| path.as_str()).collect();
        assert_eq!(
            paths.get(..4),
            Some(
                &[
                    "/identifiers/member1",
                    &format!("/multisig/request/{}", said.qb64()?)[..],
                    "/identifiers/multisig/members",
                    "/identifiers/multisig",
                ][..]
            ),
            "{paths:?}"
        );
        assert!(
            !matches!(outcome, Err(ClientError::LocalMemberNotAParticipant { .. })),
            "the joining member did not find itself: {outcome:?}"
        );
        Ok(())
    }

    #[test]
    fn a_joining_member_acknowledging_resolves_its_peers_the_same_way() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (said, listing) = proposal(&fixture, "group_proposes_the_admittance", None)?;
        let member = identifier_record(&fixture)?;
        let group = group_record(&fixture)?;
        let (client, transport) = connected(&[&member, &listing, &members(&[LOCAL, PEER]), &group])?;

        let outcome = block_on(client.multisig().accept_admittance(GROUP_NAME, ALIAS, &said));

        let requests = sent(&transport)?;
        assert_eq!(
            requests
                .get(2)
                .map(|(path, method, _)| (path.as_str(), method.as_str())),
            Some(("/identifiers/multisig/members", "GET"))
        );
        assert!(
            !matches!(outcome, Err(ClientError::LocalMemberNotAParticipant { .. })),
            "the joining member did not find itself: {outcome:?}"
        );
        Ok(())
    }

    #[test]
    fn a_members_listing_without_the_local_member_is_refused() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (said, listing) = proposal(&fixture, "group_proposes_the_disclosure", None)?;
        let member = identifier_record(&fixture)?;
        let (client, transport) = connected(&[&member, &listing, &members(&[PEER, THIRD])])?;

        let outcome = block_on(
            client
                .multisig()
                .accept_disclosure(GROUP_NAME, ALIAS, &said, &disclosure(&fixture)?),
        );
        assert!(
            matches!(&outcome, Err(ClientError::LocalMemberNotAParticipant { member }) if member == LOCAL),
            "{outcome:?}"
        );
        // Nothing is built or sent once the member knows it is not in the group.
        assert_eq!(sent(&transport)?.len(), 3);
        Ok(())
    }

    #[test]
    fn a_members_listing_with_nobody_is_refused() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (said, listing) = proposal(&fixture, "group_proposes_the_disclosure", None)?;
        let member = identifier_record(&fixture)?;
        let (client, transport) = connected(&[&member, &listing, &members(&[])])?;

        let outcome = block_on(
            client
                .multisig()
                .accept_disclosure(GROUP_NAME, ALIAS, &said, &disclosure(&fixture)?),
        );
        assert!(
            matches!(&outcome, Err(ClientError::NoRecordedMembers { group }) if group == GROUP_NAME),
            "{outcome:?}"
        );
        assert_eq!(sent(&transport)?.len(), 3);
        Ok(())
    }

    #[test]
    fn a_proposal_that_names_its_members_is_not_looked_up() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (said, listing) = proposal(&fixture, "group_proposes_the_disclosure", Some(&[LOCAL, PEER]))?;
        let member = identifier_record(&fixture)?;
        let group = group_record(&fixture)?;
        let (client, transport) = connected(&[&member, &listing, &group])?;

        let outcome = block_on(
            client
                .multisig()
                .accept_disclosure(GROUP_NAME, ALIAS, &said, &disclosure(&fixture)?),
        );

        // This port's own proposal carries `smids`, so the members are read from it and the agent
        // is never asked who they are.
        let requests = sent(&transport)?;
        assert!(
            requests.iter().all(|(path, _, _)| !path.ends_with("/members")),
            "the members were looked up although the proposal named them: {requests:?}"
        );
        assert_eq!(
            requests.get(2).map(|(path, _, _)| path.as_str()),
            Some("/identifiers/multisig")
        );
        assert!(
            !matches!(outcome, Err(ClientError::LocalMemberNotAParticipant { .. })),
            "{outcome:?}"
        );
        Ok(())
    }

    #[test]
    fn a_proposal_that_names_members_this_member_is_not_among_is_refused() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (said, listing) = proposal(&fixture, "group_proposes_the_disclosure", Some(&[PEER, THIRD]))?;
        let member = identifier_record(&fixture)?;
        let (client, transport) = connected(&[&member, &listing])?;

        let outcome = block_on(
            client
                .multisig()
                .accept_disclosure(GROUP_NAME, ALIAS, &said, &disclosure(&fixture)?),
        );
        assert!(
            matches!(&outcome, Err(ClientError::LocalMemberNotAParticipant { member }) if member == LOCAL),
            "{outcome:?}"
        );
        assert_eq!(sent(&transport)?.len(), 2);
        Ok(())
    }
}
