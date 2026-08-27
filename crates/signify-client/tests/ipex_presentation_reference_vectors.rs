//! Exact vectors for the IPEX presentation workflow.
//!
//! The five-step conversation — apply, offer, agree, grant, admit — and the two group rounds that
//! run a grant or an admit as a multisig. The single-signature half is written inline in
//! `test-integration/credentials.test.ts`, so each step is driven through the reference's own
//! `Ipex` method with the same arguments in the same order; the group half lives in
//! `test-integration/utils/multisig-utils.ts` and is transpiled in memory as Roadmap 8.3's is.
//!
//! **A group's IPEX round agrees only because one process handed both members one clock.** An IPEX
//! message's SAID covers its `dt`, and both helpers take the stamp as a parameter while
//! `multisig-holder.test.ts` reads a module-level `const TIME = createTimestamp()`. Driven a second
//! apart, the two members build different messages, the group reaches its threshold on neither, and
//! neither call fails. The reference's own `assert.equal(admitResult1.admitSaid,
//! admitResult2.admitSaid)` is the only thing that would notice, and it lives inside the process
//! that made them equal.

use std::error::Error;

use serde::Deserialize;
use serde_json::Value;
use signify_acdc::ipex::IpexRoute;
use signify_client::error::ClientError;
use signify_client::presentation::{
    ATTRIBUTE_FILTER_PREFIX, ReceivedStep, SCHEMA_FILTER, disclosure_of, requested_credentials,
};
use signify_types::api::{Credential, ExchangeResource};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-ipex-presentation/v1.json");

const EXCHANGE_ROUTE: &str = "/multisig/exn";

// ---------------------------------------------------------------------------
// Fixture model.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Provenance.
// ---------------------------------------------------------------------------

#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert_eq!(fixture.upstream, "https://github.com/WebOfTrust/signify-ts.git");
    assert_eq!(fixture.generated_on, "2026-08-27");
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

    // Both records keep what a sealed salt opens to rather than a blob only the reference can open.
    for record in [&fixture.identifier_record, &fixture.group_record] {
        let text = serde_json::to_string(record)?;
        assert!(text.contains("sxlt_opens_to"), "a sealed salt was recorded unopened");
        assert!(text.contains(r#""sxlt":"<SXLT>""#));
    }
    assert!(fixture.declarations.scanned_files > 100);
    assert!(!fixture.calls.is_empty());

    // The two identifiers the group rounds are run between.
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
        assert!(!entry.note.is_empty());

        // Every round posted something, and read the identifier it posts under first.
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

    // Each of the nine single-signature rounds returned what it built.
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

// ---------------------------------------------------------------------------
// The chain: each step names the one it answers.
// ---------------------------------------------------------------------------

#[test]
fn the_conversation_is_a_chain() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let chain = &fixture.pinned_confirmations.chain;
    assert_eq!(chain.len(), 4);

    // An apply opens the conversation and answers nothing.
    let opening = chain.first().ok_or("the chain is empty")?;
    assert_eq!(opening.step, "apply");
    assert_eq!(opening.prior.as_deref(), Some(""));

    // And every step after it names its predecessor, in order.
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

    // An apply and an agree embed nothing; an offer embeds the credential alone; a grant embeds
    // the credential, its issuance, and the anchoring key event.
    assert!(pinned.apply_slots.is_empty());
    assert_eq!(pinned.offer_slots, ["acdc"]);
    assert_eq!(pinned.grant_slots, ["acdc", "iss", "anc"]);
    assert_eq!(pinned.issuance_grant_slots, pinned.grant_slots);

    // And the two addresses the presentation used.
    assert_eq!(
        pinned.presentation_paths,
        ["GET /identifiers/member1", "POST /identifiers/member1/ipex/apply"]
    );
    assert!(pinned.note.contains("embed nothing"));
    Ok(())
}

// ---------------------------------------------------------------------------
// The findings.
// ---------------------------------------------------------------------------

#[test]
fn a_group_round_agrees_only_on_a_shared_clock() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "a_group_round_agrees_only_on_a_shared_clock")?;

    // Handed one stamp, the two members build one message — for both rounds.
    assert_eq!(recorded.get("grants_agree").and_then(Value::as_bool), Some(true));
    assert_eq!(recorded.get("admits_agree").and_then(Value::as_bool), Some(true));

    // Handed their own clocks, they do not — and neither call fails.
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

    // The stamp travels as an argument on both halves, and the holder test shares one constant.
    let clock = &fixture.declarations.shared_clock;
    assert!(clock.declaration, "the holder test no longer pins one clock");
    assert_eq!(clock.text, "const TIME = createTimestamp();");
    assert_eq!(clock.file, "test-integration/multisig-holder.test.ts");

    // And the reference's own equality assertion is the only check — inside the one process.
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

    // Not one of the six driven group rounds fetches a group request.
    assert_eq!(
        recorded.get("group_requests_made").and_then(Value::as_bool),
        Some(false)
    );

    // All three group helpers wait on `/multisig/exn` and discard what they wait for.
    let waits = recorded.get("waits").and_then(Value::as_array).ok_or("no waits")?;
    assert_eq!(waits.len(), 3);
    for wait in waits {
        assert_eq!(wait.get("route").and_then(Value::as_str), Some(EXCHANGE_ROUTE));
        assert_eq!(wait.get("discarded").and_then(Value::as_bool), Some(true));
        assert!(wait.get("binds").is_some_and(Value::is_null));
    }

    // The one wait in the tree whose SAID *is* bound is the grant a group admit answers, which is
    // why this finding is about the proposal rather than about waiting.
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

    // Every wait records where it is, so a reader can find it in the pinned tree.
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

    // The waiter's own return statement, verbatim.
    assert_eq!(
        fixture.declarations.waiter_return,
        "return notes[notes.length - 1]?.a.d ?? '';"
    );

    // Driven: the admit is built and posted acknowledging nothing, with no error.
    assert_eq!(recorded.get("admit_prior").and_then(Value::as_str), Some(""));
    assert!(recorded.get("error").is_some_and(Value::is_null));
    assert!(recorded.get("admit_said").and_then(Value::as_str).is_some());

    // The same value is guarded in the inline step and not in the helper beside it.
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

    // The parameter that would have said how many grants to expect is still there, commented out.
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

    // Three distinct sets across the tree: none, the anchor's, and all three.
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

    // And the disagreement spans files rather than being one file's habit.
    let files: std::collections::BTreeSet<&str> = fixture
        .declarations
        .grant_arguments
        .iter()
        .map(|call| call.file.as_str())
        .collect();
    assert!(files.len() >= 3, "the grants no longer span three files: {files:?}");

    // And passing none reaches the branch that signs the anchor with the sender's own keeper.
    let defaults = &fixture.declarations.grant_defaults;
    assert!(
        defaults.resigns_the_anchor,
        "the re-signing branch is gone; the finding is stale"
    );
    assert!(defaults.credential_attachment_default);
    assert!(defaults.issuance_attachment_default);
    assert!(defaults.text.contains("keeper.sign"));

    // Both driven grants succeeded; the one with no attachment produced its own.
    assert!(recorded.get("with_attachment").and_then(Value::as_str).is_some());
    assert!(recorded.get("without_attachment").and_then(Value::as_str).is_some());
    Ok(())
}

// ---------------------------------------------------------------------------
// What this port does with the same material.
// ---------------------------------------------------------------------------

#[test]
fn the_recorded_apply_becomes_the_filter_the_reference_assembles_by_hand() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let posted = body(&fixture, "verifier_applies", "/ipex/apply")?;
    let exn = posted.get("exn").ok_or("the apply posted no message")?;
    let resource: ExchangeResource = serde_json::from_value(serde_json::json!({"exn": exn, "pathed": {}}))?;

    let step = ReceivedStep::of("", &resource)?;
    assert_eq!(step.route(), IpexRoute::Apply);
    assert_eq!(step.said()?.qb64()?, fixture.pinned_confirmations.apply);

    // The reference builds this filter inline, one `filter['-a-' + key]` at a time.
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

    // The credential as the holder would read it back. Each of the three events is re-serialized
    // and required to reproduce its own bytes, because the SAID naming it is a digest of those
    // bytes — the reference rebuilds the same three with `new Serder(record.sad)` and checks
    // nothing.
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

    // The attachments come from the credential itself, so the branch that signs the anchoring event
    // with the *sender's* keeper — the one `multisig-holder.test.ts` reaches — has no path here.
    assert!(!fixture.held_credential.atc.is_empty());
    assert!(!fixture.held_credential.issatc.is_empty());
    assert!(!fixture.held_credential.ancatc.is_empty());
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

    // The offer the reference built names the apply it answers, which this port reads back.
    assert_eq!(
        step.answers()?.map(|said| said.qb64()).transpose()?,
        Some(fixture.pinned_confirmations.apply.clone())
    );

    // And an offer read as a request for credentials is refused rather than silently mis-filtered.
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

    // The reference announces on `/multisig/exn` under the `multisig` topic, embedding the IPEX
    // message whole in `exn` and naming only the group — which is what this port sends too.
    assert_eq!(pinned.announcement_route, EXCHANGE_ROUTE);
    assert_eq!(pinned.announcement_topic, "multisig");
    assert_eq!(pinned.announcement_slots, ["exn"]);
    assert!(pinned.announcement_attributes.contains(&"gid".to_owned()));
    assert_eq!(pinned.group.len(), 44);

    let posted = body(&fixture, "group_proposes_the_admittance", "/exchanges")?;
    let text = serde_json::to_string(&posted)?;
    // The order the wire carries, asserted on the text rather than on decoded keys.
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
    assert_eq!(quirks.len(), 5);
    for (name, recorded) in quirks {
        let note = recorded.get("note").and_then(Value::as_str).unwrap_or_default();
        let decision = recorded
            .get("rust_decision")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(note.len() > 80, "{name} explains too little");
        assert!(decision.len() > 40, "{name} does not say what this port does");
    }

    // Every helper's text is recorded whole, so a reader can check the claims against the source.
    for text in [
        &fixture.declarations.grant_multisig,
        &fixture.declarations.admit_multisig,
        &fixture.declarations.multisig_admit_credential,
    ] {
        assert!(text.contains("waitAndMarkNotification"), "a helper text is truncated");
        assert!(text.contains("ipex()"));
    }

    // And every IPEX call site in the three files is recorded with the arguments it names.
    assert!(fixture.declarations.ipex_calls.len() >= 10);
    for entry in &fixture.declarations.ipex_calls {
        assert!(!entry.file.is_empty() && !entry.enclosing.is_empty());
        assert!(
            ["apply", "offer", "agree", "grant", "admit"].contains(&entry.step.as_str()),
            "{} is not an IPEX step",
            entry.step
        );
        assert!(!entry.arguments.is_empty());
    }
    assert!(fixture.declarations.notes.get("waiter").is_some());
    Ok(())
}
