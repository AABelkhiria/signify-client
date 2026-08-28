//! Exact multisig-inception vectors recorded from the pinned reference's own helpers.
//!
//! The ported unit lives only in `test-integration/utils/multisig-utils.ts`, which imports the
//! package by name and is not built into `dist`. So the generator **transpiles that one file in
//! memory** with the reference's own pinned TypeScript and runs it against a recording agent —
//! nothing is written into the submodule, and what produced these requests is the reference's own
//! code rather than a re-expression of it.
//!
//! Six calls are recorded: the pinned scenario's two proposals, one acceptance of the first, and
//! three acceptances of proposals bent to make a latent defect observable.
//!
//! Four of those defects are the item. The initiator addresses its proposal to itself; the joining
//! member reads the rotation set and relays the signing set in its place; the joining member does
//! not await the message it sends; and the witness threshold is re-parsed out of a hexadecimal
//! field with a base-ten `parseInt`, which for `"10"` silently derives a different group.

use std::error::Error;

use serde::Deserialize;
use serde_json::Value;
use signify_client::endpoint::exchanges::{ClassifiedExchange, MultisigRoute};
use signify_client::multisig::{INCEPTION_ROUTE, INCEPTION_SLOT};
use signify_keri::prefix::IdentifierPrefix;
use signify_types::api::MultisigExchangeResource;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-multisig-inception/v1.json");

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";

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
    key_states: serde_json::Map<String, Value>,
    identifier_record: Value,
    calls: Vec<Call>,
    pinned_confirmations: PinnedConfirmations,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    fixed_clock_ms: u64,
    local_member_prefix: String,
    peer_prefix: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    start_multisig_incept: String,
    accept_multisig_incept: String,
    get_states: String,
    start_args: String,
    accept_args: String,
    send_calls: Vec<SendCall>,
    scenario_witnesses: Vec<String>,
    start_uses: Scan,
    accept_uses: Scan,
    no_source_file: bool,
    notes: Value,
}

#[derive(Debug, Deserialize)]
struct SendCall {
    enclosing: String,
    awaited: bool,
    text: String,
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
    scenario_group_names: Vec<String>,
    scenario_member_names: Vec<String>,
    scenario_route: Vec<String>,
    initiator_paths: Vec<String>,
    proposal_route: String,
    proposal_addressed_to: String,
    proposal_sender: String,
    proposal_delivered_to: Vec<String>,
    group_prefix: String,
    note: String,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(FIXTURE)?)
}

fn call<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a Call, Box<dyn Error>> {
    fixture
        .calls
        .iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| format!("no recorded call {name}").into())
}

/// The exchange submission one recorded call produced, parsed.
fn proposal(fixture: &Fixture, name: &str) -> Result<Value, Box<dyn Error>> {
    let request = call(fixture, name)?
        .requests
        .iter()
        .find(|entry| entry.path.ends_with("/exchanges"))
        .ok_or_else(|| format!("call {name} sent no exchange"))?;
    Ok(serde_json::from_str(request.body.as_deref().ok_or("no body")?)?)
}

fn quirk<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a Value, Box<dyn Error>> {
    fixture
        .reference_quirks
        .get(name)
        .ok_or_else(|| format!("no recorded divergence {name}").into())
}

// ---------------------------------------------------------------------------
// Manifest and provenance.
// ---------------------------------------------------------------------------

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
            .any(|source| source.ends_with("multisig-utils.ts"))
    );
    assert!(
        fixture
            .sources
            .iter()
            .any(|source| source.ends_with("multisig-inception.test.ts"))
    );
    assert_eq!(fixture.provenance.bran, "0123456789abcdefghijk");
    assert_eq!(fixture.provenance.fixed_clock_ms, 1_700_000_000_123);
    assert_eq!(fixture.provenance.local_member_prefix, LOCAL);
    assert_eq!(fixture.provenance.peer_prefix, PEER);
    assert!(fixture.provenance.note.contains("transpiled in memory"));
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 6);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        assert!(!entry.requests.is_empty(), "call {} sent nothing", entry.name);
        for request in &entry.requests {
            // Every read is a `GET` with no body and every write is a `POST` with one.
            match request.method.as_str() {
                "GET" => assert!(request.body.is_none(), "a read in {} carried a body", entry.name),
                "POST" => assert!(request.body.is_some(), "a write in {} carried none", entry.name),
                other => return Err(format!("call {} used {other}", entry.name).into()),
            }
        }
        // Five of the six succeed; the one that fails carries its message instead of an answer.
        assert_eq!(
            entry.result.is_null(),
            entry.error.is_some(),
            "call {} recorded both an answer and a failure, or neither",
            entry.name
        );
    }
    // The identifier record is the reference's own mock, with its sealed salt recorded as what it
    // opens to rather than as a blob only that controller can open.
    assert_eq!(
        fixture
            .identifier_record
            .get("salty")
            .and_then(|salty| salty.get("sxlt"))
            .and_then(Value::as_str),
        Some("<SXLT>")
    );
    assert!(
        fixture
            .identifier_record
            .get("salty")
            .and_then(|salty| salty.get("sxlt_opens_to"))
            .is_some()
    );
    Ok(())
}

#[test]
fn there_is_no_upstream_source_file() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // Neither helper exists under `src`: this is a Rust-only module, `PORTING.md` §4.5.
    assert!(fixture.declarations.no_source_file);
    assert_eq!(fixture.declarations.start_uses.scanned_files, 117);
    for scan in [&fixture.declarations.start_uses, &fixture.declarations.accept_uses] {
        assert!(scan.total >= 1, "{} is used nowhere", scan.needle);
        assert!(
            scan.files.iter().all(|hit| hit.file.starts_with("test-integration/")),
            "{} escaped the integration tree",
            scan.needle
        );
        assert_eq!(
            scan.files.iter().map(|hit| hit.count).sum::<usize>(),
            scan.total,
            "{}'s per-file counts do not add up to its total",
            scan.needle
        );
    }
    // And both helpers are real code rather than declarations.
    assert!(
        fixture
            .declarations
            .start_multisig_incept
            .contains("identifiers().create")
    );
    assert!(
        fixture
            .declarations
            .accept_multisig_incept
            .contains("groups().getRequest")
    );
    assert!(fixture.declarations.get_states.contains("keyStates().get"));
    assert!(fixture.declarations.start_args.contains("participants"));
    assert!(fixture.declarations.accept_args.contains("msgSaid"));
    assert!(fixture.declarations.notes.is_object());
    Ok(())
}

#[test]
fn the_scenarios_own_values_are_driven() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let confirmations = &fixture.pinned_confirmations;
    // The scenario names two groups, two members, one route, and three witnesses.
    assert!(confirmations.scenario_group_names.iter().any(|name| name == "multisig"));
    assert!(
        confirmations
            .scenario_group_names
            .iter()
            .any(|name| name == "multisig2")
    );
    assert_eq!(confirmations.scenario_member_names, ["member1", "member2"]);
    assert_eq!(confirmations.scenario_route, [INCEPTION_ROUTE]);
    assert_eq!(fixture.declarations.scenario_witnesses.len(), 3);
    assert!(!confirmations.note.is_empty());

    // And the workflow's shape: read the member, read each participant's key state, create, propose.
    assert_eq!(
        confirmations.initiator_paths,
        [
            "GET /identifiers/member1",
            &format!("GET /states?pre={LOCAL}"),
            &format!("GET /states?pre={PEER}"),
            "POST /identifiers",
            "POST /identifiers/member1/exchanges",
        ]
    );
    // And that summary is the recording rather than a restatement of it.
    let recorded: Vec<String> = call(&fixture, "start_multisig_incept")?
        .requests
        .iter()
        .map(|request| format!("{} {}", request.method, request.path))
        .collect();
    assert_eq!(recorded, confirmations.initiator_paths);
    assert_eq!(confirmations.proposal_route, INCEPTION_ROUTE);
    assert!(!confirmations.group_prefix.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// The four findings.
// ---------------------------------------------------------------------------

#[test]
fn the_initiator_addresses_its_proposal_to_itself() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let confirmations = &fixture.pinned_confirmations;

    // Driven: the message's `rp` is its own `i`, and its delivery list includes the sender.
    assert_eq!(confirmations.proposal_sender, LOCAL);
    assert_eq!(confirmations.proposal_addressed_to, LOCAL);
    assert_eq!(confirmations.proposal_delivered_to, [LOCAL, PEER]);

    // The recorded body says the same thing.
    let body = proposal(&fixture, "start_multisig_incept")?;
    let exn = body.get("exn").ok_or("no exn")?;
    assert_eq!(exn.get("i").and_then(Value::as_str), Some(LOCAL));
    assert_eq!(exn.get("rp").and_then(Value::as_str), Some(LOCAL));
    assert_eq!(
        exn.get("a").and_then(|block| block.get("i")).and_then(Value::as_str),
        Some(LOCAL),
        "the attribute block names the sender too"
    );

    // The accepting helper already filters itself out, which is the asymmetry.
    let accepted = proposal(&fixture, "accept_multisig_incept")?;
    assert_eq!(
        accepted.get("rec").and_then(Value::as_array).map(Vec::len),
        Some(1),
        "the accepting member kept itself in its own delivery list"
    );
    assert_eq!(
        accepted
            .get("exn")
            .and_then(|exn| exn.get("rp"))
            .and_then(Value::as_str),
        Some(PEER)
    );
    assert!(quirk(&fixture, "the_initiator_addresses_its_proposal_to_itself")?.is_object());
    Ok(())
}

#[test]
fn the_joining_member_relays_the_signing_set_where_the_rotation_set_belongs() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "the_accepting_member_discards_the_rotation_set")?;

    // The proposal it read named one rotation member and two signing members.
    let read: Vec<&str> = recorded
        .get("read_rmids")
        .and_then(Value::as_array)
        .ok_or("no recorded rmids")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(read, [PEER]);

    // What it relayed is the signing set instead.
    let relayed: Vec<&str> = recorded
        .get("relayed_rmids")
        .and_then(Value::as_array)
        .ok_or("no relayed rmids")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let signing: Vec<&str> = recorded
        .get("relayed_smids")
        .and_then(Value::as_array)
        .ok_or("no relayed smids")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(relayed, signing, "the two sets were not conflated after all");
    assert_ne!(relayed, read, "the rotation set survived the round trip");
    assert_eq!(signing, [LOCAL, PEER]);
    Ok(())
}

#[test]
fn the_joining_member_does_not_await_the_message_it_sends() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // One `send` per helper, and exactly one of them is awaited.
    let sends: Vec<&SendCall> = fixture
        .declarations
        .send_calls
        .iter()
        .filter(|call| ["startMultisigIncept", "acceptMultisigIncept"].contains(&call.enclosing.as_str()))
        .collect();
    assert_eq!(sends.len(), 2);

    let proposing = sends
        .iter()
        .find(|call| call.enclosing == "startMultisigIncept")
        .ok_or("no proposing send")?;
    let accepting = sends
        .iter()
        .find(|call| call.enclosing == "acceptMultisigIncept")
        .ok_or("no accepting send")?;
    assert!(proposing.awaited, "the proposing helper stopped awaiting its send");
    assert!(
        !accepting.awaited,
        "the accepting helper now awaits its send; the divergence is stale"
    );
    assert!(accepting.text.contains("send("));

    // The message still leaves — the fixture gives the microtask queue a turn — which is why this
    // is a defect about *reporting* rather than about delivery.
    assert!(
        call(&fixture, "accept_multisig_incept")?
            .requests
            .iter()
            .any(|request| request.path.ends_with("/exchanges"))
    );
    Ok(())
}

#[test]
fn a_hexadecimal_witness_threshold_derives_a_different_group() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "the_witness_threshold_is_read_in_the_wrong_base")?;

    // `"a"` is ten and `parseInt` gives `NaN`, which throws — loudly, at least.
    assert_eq!(
        recorded.get("loud_failure").and_then(Value::as_str),
        Some("Invalid num = NaN, too large to encode.")
    );
    assert_eq!(
        call(&fixture, "accept_with_hexadecimal_witness_threshold")?.error,
        Some("Invalid num = NaN, too large to encode.".to_owned())
    );

    // `"10"` is sixteen and `parseInt` gives ten, which throws nothing at all.
    let silent = recorded.get("silent").ok_or("no silent case")?;
    assert_eq!(silent.get("proposed_bt").and_then(Value::as_str), Some("10"));
    assert_eq!(silent.get("proposed_bt_means").and_then(Value::as_u64), Some(16));
    assert_eq!(silent.get("rebuilt_bt").and_then(Value::as_str), Some("a"));
    assert_eq!(silent.get("rebuilt_bt_means").and_then(Value::as_u64), Some(10));
    assert_eq!(silent.get("thresholds_agree").and_then(Value::as_bool), Some(false));
    assert_eq!(
        silent.get("error"),
        Some(&Value::Null),
        "the silent case failed after all"
    );
    assert!(
        silent
            .get("rebuilt_group")
            .and_then(Value::as_str)
            .is_some_and(|group| !group.is_empty())
    );

    // Here the threshold is read in the base the protocol writes it in, so the two agree at every
    // value rather than only below ten.
    for (written, means) in [("0", 0_u32), ("9", 9), ("a", 10), ("10", 16), ("ff", 255)] {
        assert_eq!(u32::from_str_radix(written, 16).ok(), Some(means), "{written}");
    }
    assert_ne!(u32::from_str_radix("10", 16).ok(), "10".parse::<u32>().ok());
    Ok(())
}

// ---------------------------------------------------------------------------
// The proposal itself.
// ---------------------------------------------------------------------------

#[test]
fn the_proposal_is_a_group_inception_this_port_classifies() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let body = proposal(&fixture, "start_multisig_incept")?;
    let exn = body.get("exn").ok_or("no exn")?.clone();

    // What Roadmap 8.2 would answer a joining member with, built from what the initiator sent.
    let listing = serde_json::json!([{ "exn": exn, "paths": {}, "groupName": "multisig",
        "memberName": "member1", "sender": LOCAL }]);
    let decoded: Vec<MultisigExchangeResource> = serde_json::from_value(listing)?;
    let entry = decoded.first().ok_or("empty listing")?;

    // And Roadmap 8.1 classifies it as the inception proposal it is.
    let classified = ClassifiedExchange::try_from(entry)?;
    let multisig = classified.as_multisig().ok_or("not a multisig proposal")?;
    assert_eq!(multisig.route, MultisigRoute::Inception);
    assert_eq!(
        multisig.attributes.group.qb64()?,
        fixture.pinned_confirmations.group_prefix
    );
    assert_eq!(
        multisig.attributes.signing_members.as_ref().map(Vec::len),
        Some(2),
        "the proposal names both members"
    );
    assert_eq!(multisig.proposed.digest.len(), 44);
    Ok(())
}

#[test]
fn the_proposal_embeds_the_event_it_proposes_with_its_attachment() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let body = proposal(&fixture, "start_multisig_incept")?;

    // The embed slot is the one Roadmap 8.1's table expects for this route.
    let embeds = body
        .get("exn")
        .and_then(|exn| exn.get("e"))
        .and_then(Value::as_object)
        .ok_or("no embed block")?;
    assert!(embeds.contains_key(INCEPTION_SLOT));
    assert!(embeds.contains_key("d"), "the embed block carries its own SAID");

    // The event embedded is the one the creation submitted, and its identifier is the group's.
    let created = call(&fixture, "start_multisig_incept")?
        .requests
        .iter()
        .find(|request| request.path == "/identifiers")
        .ok_or("no creation")?;
    let creation: Value = serde_json::from_str(created.body.as_deref().ok_or("no body")?)?;
    assert_eq!(creation.get("icp"), embeds.get(INCEPTION_SLOT));
    assert_eq!(
        embeds
            .get(INCEPTION_SLOT)
            .and_then(|event| event.get("i"))
            .and_then(Value::as_str),
        Some(fixture.pinned_confirmations.group_prefix.as_str())
    );

    // And the transposed attachment carries the member's signature over it.
    let attachment = body.get("atc").and_then(Value::as_str).ok_or("no attachment")?;
    assert!(!attachment.is_empty());
    assert!(attachment.starts_with("-L"), "the attachment is not a pathed group");
    Ok(())
}

#[test]
fn the_topic_is_the_groups_local_alias() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // The reference passes `groupName` as the topic, so a peer's notification is filed under the
    // *sender's* local name for a group nobody else has named yet.
    assert_eq!(
        proposal(&fixture, "start_multisig_incept")?
            .get("tpc")
            .and_then(Value::as_str),
        Some("multisig")
    );
    assert_eq!(
        proposal(&fixture, "start_multisig_incept_no_witnesses")?
            .get("tpc")
            .and_then(Value::as_str),
        Some("multisig2"),
        "the second group's topic is its own alias"
    );
    Ok(())
}

#[test]
fn a_witnessless_group_writes_no_witnesses_and_a_zero_threshold() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // The scenario's second group, which is the same proposal with the witnesses removed.
    let created = call(&fixture, "start_multisig_incept_no_witnesses")?
        .requests
        .iter()
        .find(|request| request.path == "/identifiers")
        .ok_or("no creation")?;
    let creation: Value = serde_json::from_str(created.body.as_deref().ok_or("no body")?)?;
    let event = creation.get("icp").ok_or("no inception")?;
    assert_eq!(event.get("b").and_then(Value::as_array).map(Vec::len), Some(0));
    assert_eq!(event.get("bt").and_then(Value::as_str), Some("0"));

    // And the witnessed group carries all three, with a threshold of two.
    let witnessed = call(&fixture, "start_multisig_incept")?
        .requests
        .iter()
        .find(|request| request.path == "/identifiers")
        .ok_or("no creation")?;
    let first: Value = serde_json::from_str(witnessed.body.as_deref().ok_or("no body")?)?;
    let witnessed_event = first.get("icp").ok_or("no inception")?;
    assert_eq!(
        witnessed_event.get("b").and_then(Value::as_array).map(Vec::len),
        Some(3)
    );
    assert_eq!(witnessed_event.get("bt").and_then(Value::as_str), Some("2"));
    // Two of two, which is what the scenario asks for.
    assert_eq!(witnessed_event.get("kt").and_then(Value::as_str), Some("2"));
    assert_eq!(witnessed_event.get("nt").and_then(Value::as_str), Some("2"));
    Ok(())
}

#[test]
fn the_two_members_converge_on_one_group_when_nothing_is_bent() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // The happy path: the joining member rebuilds the same event and derives the same identifier.
    let proposed = fixture.pinned_confirmations.group_prefix.as_str();
    let accepted = call(&fixture, "accept_multisig_incept")?
        .requests
        .iter()
        .find(|request| request.path == "/identifiers")
        .ok_or("no creation")?;
    let creation: Value = serde_json::from_str(accepted.body.as_deref().ok_or("no body")?)?;
    assert_eq!(
        creation
            .get("icp")
            .and_then(|event| event.get("i"))
            .and_then(Value::as_str),
        Some(proposed),
        "the two members derived different groups on the happy path"
    );
    // Which is the fact the whole workflow rests on, and the one the base-ten threshold breaks.
    assert!(IdentifierPrefix::from_qb64(proposed).is_ok());
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the recorded divergences are not an object")?;
    assert_eq!(quirks.len(), 5);
    for (name, finding) in quirks {
        let entry = finding.as_object().ok_or("a divergence is not an object")?;
        for label in ["note", "rust_decision"] {
            assert!(
                entry
                    .get(label)
                    .and_then(Value::as_str)
                    .is_some_and(|text| !text.is_empty()),
                "divergence {name} records no {label}"
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Driving this port against the same inputs.
//
// A group identifier is a digest over the event every member must build independently, so the
// claim that matters is not that two request bodies look alike — it is that both implementations
// derive **the same group** from the same participants, thresholds, and witnesses. That is what
// this half proves, and it is the fact the reference's base-ten witness threshold destroys.
// ---------------------------------------------------------------------------

mod driven {
    use super::{Fixture, LOCAL, PEER, call, fixture};

    use std::error::Error;

    use std::sync::Arc;

    use serde_json::Value;
    use signify_client::client::{ConnectedClient, SignifyClient};
    use signify_client::config::ClientConfig;
    use signify_client::error::ClientError;
    use signify_client::multisig::GroupInceptionRequest;
    use signify_crypto::cipher::Encrypter;
    use signify_crypto::salt::{Salt, SecurityTier};

    use signify_crypto::verifier::KeyTransferability;

    use signify_http::transport::Transport;
    use signify_keri::event::Timestamp;
    use signify_keri::manager::DerivationCost;
    use signify_keri::prefix::IdentifierPrefix;
    use signify_keri::threshold::SigningThreshold;
    use signify_testkit::{ADMIN, AgentTransport, BOOT, PASSCODE, agent_state, block_on, clock};

    const ALIAS: &str = "member1";
    const GROUP_NAME: &str = "multisig";
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

    /// One endpoint request as it left the transport: path, method, and body.
    type SentRequest = (String, String, Option<String>);

    /// Returns every request past the two the connection itself makes.
    fn sent(transport: &AgentTransport) -> Result<Vec<SentRequest>, Box<dyn Error>> {
        transport
            .requests()
            .into_iter()
            .skip(2)
            .map(|request| Ok((request.resource(), request.method().to_owned(), request.body_text())))
            .collect()
    }

    /// The sealing key this client's controller salt derives, so a recorded record can be re-sealed.
    fn sealing_key() -> Result<Encrypter, Box<dyn Error>> {
        let salt = Salt::from_qb64(&format!("0AA{PASSCODE}"), SecurityTier::Low)?;
        let signer = salt.derive_signer("", KeyTransferability::NonTransferable)?;
        Ok(Encrypter::from_verification_key(signer.verifier())?)
    }

    /// The member record the alias lookup answers with, re-sealed under this client's own key.
    ///
    /// The fixture records what the reference's sealed salt *opens to* rather than the blob itself,
    /// because only the reference's controller can open that blob. Roadmap 6.11 established this.
    fn identifier_record(fixture: &Fixture) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut record = fixture.identifier_record.clone();
        let opens_to = record
            .get("salty")
            .and_then(|salty| salty.get("sxlt_opens_to"))
            .and_then(Value::as_str)
            .ok_or("the recorded member carries no sealed salt")?
            .to_owned();
        let sealed = sealing_key()?
            .encrypt_salt(&Salt::from_qb64(&opens_to, SecurityTier::Low)?)?
            .qb64()?;
        let salty = record
            .get_mut("salty")
            .and_then(Value::as_object_mut)
            .ok_or("the recorded member has no key-manager block")?;
        salty.remove("sxlt_opens_to");
        salty.insert("sxlt".to_owned(), Value::String(sealed));
        Ok(serde_json::to_vec(&record)?)
    }

    /// The key state the agent answers each participant read with, taken from the fixture.
    fn key_state(fixture: &Fixture, member: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let state = fixture
            .key_states
            .get(member)
            .ok_or("the fixture records no key state for this member")?;
        Ok(serde_json::to_vec(&Value::Array(vec![state.clone()]))?)
    }

    fn prefix(text: &str) -> Result<IdentifierPrefix, Box<dyn Error>> {
        Ok(IdentifierPrefix::from_qb64(text)?)
    }

    fn witnesses(fixture: &Fixture) -> Result<Vec<IdentifierPrefix>, Box<dyn Error>> {
        fixture
            .declarations
            .scenario_witnesses
            .iter()
            .map(|witness| prefix(witness))
            .collect()
    }

    /// The pinned scenario's own proposal, as this port's request.
    fn scenario<'a>(
        participants: &'a [IdentifierPrefix],
        witnesses: &'a [IdentifierPrefix],
    ) -> Result<GroupInceptionRequest<'a>, Box<dyn Error>> {
        Ok(GroupInceptionRequest {
            group_name: GROUP_NAME,
            local_member: ALIAS,
            participants,
            signing_threshold: Some(SigningThreshold::numeric(2)),
            next_threshold: Some(SigningThreshold::numeric(2)),
            witnesses,
            witness_threshold: 2,
            delegator: None,
            timestamp: STAMP.parse::<Timestamp>()?,
        })
    }

    /// The answers a proposal reads, in the order this port asks for them.
    ///
    /// The member record is answered **twice**. Roadmap 7.7's `send` resolves its own sender from
    /// the alias rather than taking a record the caller already has — which is what keeps a
    /// message's `i` field and the key that signed it the same identifier — so this port reads the
    /// member once to build the group and once to sign the proposal, where the reference passes the
    /// hab it is already holding. One extra read, and no behaviour rests on it.
    fn answers(fixture: &Fixture) -> Result<Answers, Box<dyn Error>> {
        Ok(Answers {
            member: identifier_record(fixture)?,
            local: key_state(fixture, LOCAL)?,
            peer: key_state(fixture, PEER)?,
        })
    }

    /// The three recorded answers a proposal reads.
    struct Answers {
        member: Vec<u8>,
        local: Vec<u8>,
        peer: Vec<u8>,
    }

    impl Answers {
        /// Scripts them in the order this port asks, with `{}` for the two writes.
        fn scripted(&self) -> [&[u8]; 6] {
            [&self.member, &self.local, &self.peer, b"{}", &self.member, b"{}"]
        }
    }

    /// The recorded body of one request of one recorded call.
    fn recorded_body(fixture: &Fixture, name: &str, path: &str) -> Result<Value, Box<dyn Error>> {
        let request = call(fixture, name)?
            .requests
            .iter()
            .find(|entry| entry.path == path)
            .ok_or_else(|| format!("call {name} sent nothing to {path}"))?;
        Ok(serde_json::from_str(request.body.as_deref().ok_or("no body")?)?)
    }

    #[test]
    fn a_proposal_derives_the_group_the_reference_derived() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let answers = answers(&fixture)?;
        let (client, transport) = connected(&answers.scripted())?;

        let participants = [prefix(LOCAL)?, prefix(PEER)?];
        let witnesses = witnesses(&fixture)?;
        let proposal = block_on(
            client
                .multisig()
                .propose_inception(&scenario(&participants, &witnesses)?),
        )?;

        // The whole point of the workflow: both implementations, given the same participants,
        // thresholds, and witnesses, derive the same group.
        assert_eq!(proposal.group().qb64()?, fixture.pinned_confirmations.group_prefix);

        // And the event they derived it from is the same bytes, field for field.
        let recorded = recorded_body(&fixture, "start_multisig_incept", "/identifiers")?;
        let sent = sent(&transport)?;
        let creation = sent
            .iter()
            .find(|(path, _, _)| path == "/identifiers")
            .ok_or("this port created nothing")?;
        let body: Value = serde_json::from_str(creation.2.as_deref().ok_or("no body")?)?;
        assert_eq!(body.get("icp"), recorded.get("icp"));
        assert_eq!(body.get("name"), recorded.get("name"));
        assert_eq!(body.get("smids"), recorded.get("smids"));
        assert_eq!(body.get("rmids"), recorded.get("rmids"));
        Ok(())
    }

    #[test]
    fn a_proposal_reads_and_writes_what_the_reference_read_and_wrote() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let answers = answers(&fixture)?;
        let (client, transport) = connected(&answers.scripted())?;

        let participants = [prefix(LOCAL)?, prefix(PEER)?];
        let witnesses = witnesses(&fixture)?;
        let _ = block_on(
            client
                .multisig()
                .propose_inception(&scenario(&participants, &witnesses)?),
        )?;

        let addresses: Vec<String> = sent(&transport)?
            .iter()
            .map(|(path, method, _)| format!("{method} {path}"))
            .collect();

        // The reference's five, in its order — the member, each participant's key state, the
        // creation, the proposal — plus one.
        assert_eq!(
            addresses,
            [
                "GET /identifiers/member1",
                &format!("GET /states?pre={LOCAL}"),
                &format!("GET /states?pre={PEER}"),
                "POST /identifiers",
                // Roadmap 7.7's `send` resolves its own sender from the alias rather than taking a
                // record the caller is already holding, which is what keeps a message's `i` and
                // the key that signed it one identifier. So the member is read twice here and once
                // upstream: one extra read, no behaviour resting on it.
                "GET /identifiers/member1",
                "POST /identifiers/member1/exchanges",
            ]
        );

        // The reference's five are these six in order, with that one read removed.
        let mut recorded = fixture.pinned_confirmations.initiator_paths.iter();
        let mut matched = 0;
        for address in &addresses {
            if recorded.clone().next() == Some(address) {
                let _ = recorded.next();
                matched += 1;
            }
        }
        assert_eq!(matched, fixture.pinned_confirmations.initiator_paths.len());
        assert_eq!(addresses.len(), matched + 1);
        Ok(())
    }

    #[test]
    fn a_proposal_is_addressed_to_a_peer_where_the_reference_addresses_itself() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let answers = answers(&fixture)?;
        let (client, transport) = connected(&answers.scripted())?;

        let participants = [prefix(LOCAL)?, prefix(PEER)?];
        let witnesses = witnesses(&fixture)?;
        let _ = block_on(
            client
                .multisig()
                .propose_inception(&scenario(&participants, &witnesses)?),
        )?;

        let sent = sent(&transport)?;
        let submission = sent
            .iter()
            .find(|(path, _, _)| path.ends_with("/exchanges"))
            .ok_or("this port proposed nothing")?;
        let body: Value = serde_json::from_str(submission.2.as_deref().ok_or("no body")?)?;
        let recorded = recorded_body(&fixture, "start_multisig_incept", "/identifiers/member1/exchanges")?;

        // The divergence, driven on both sides: the reference addresses and delivers to itself.
        assert_eq!(
            recorded
                .get("exn")
                .and_then(|exn| exn.get("rp"))
                .and_then(Value::as_str),
            Some(LOCAL)
        );
        assert_eq!(
            body.get("exn").and_then(|exn| exn.get("rp")).and_then(Value::as_str),
            Some(PEER)
        );
        assert_eq!(
            body.get("rec"),
            Some(&Value::Array(vec![Value::String(PEER.to_owned())]))
        );
        assert_eq!(recorded.get("rec").and_then(Value::as_array).map(Vec::len), Some(2));

        // Everything the addressee does not decide is the same: the topic, the route, the sender,
        // the attribute block's group and members, and the embedded event with its own SAID.
        assert_eq!(body.get("tpc"), recorded.get("tpc"));
        for label in ["i", "r"] {
            assert_eq!(
                body.get("exn").and_then(|exn| exn.get(label)),
                recorded.get("exn").and_then(|exn| exn.get(label)),
                "the two proposals disagree about {label}"
            );
        }
        assert_eq!(
            body.get("exn").and_then(|exn| exn.get("e")),
            recorded.get("exn").and_then(|exn| exn.get("e"))
        );
        for label in ["gid", "smids", "rmids"] {
            assert_eq!(
                body.get("exn")
                    .and_then(|exn| exn.get("a"))
                    .and_then(|block| block.get(label)),
                recorded
                    .get("exn")
                    .and_then(|exn| exn.get("a"))
                    .and_then(|block| block.get(label)),
                "the two attribute blocks disagree about {label}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_member_that_is_not_a_participant_is_refused_before_anything_is_created() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let answers = answers(&fixture)?;
        let (client, transport) = connected(&answers.scripted())?;

        // The reference reads `participants[0]` as the addressee and never checks that the local
        // member is among them, so a member can propose a group it is not in.
        let participants = [prefix(PEER)?, prefix(THIRD)?];
        let witnesses = witnesses(&fixture)?;
        let refused = matches!(
            block_on(
                client
                    .multisig()
                    .propose_inception(&scenario(&participants, &witnesses)?)
            ),
            Err(ClientError::LocalMemberNotAParticipant { .. })
        );
        assert!(refused, "a group the proposer is not in was accepted");

        // And nothing was created: the only request is the member lookup that found the mismatch.
        assert_eq!(sent(&transport)?.len(), 1);
        Ok(())
    }

    #[test]
    fn a_group_of_one_is_refused() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let answers = answers(&fixture)?;
        let (client, transport) = connected(&answers.scripted())?;

        // One participant leaves no peer to address, which the reference reaches by sending a
        // message to itself.
        let participants = [prefix(LOCAL)?];
        let witnesses = witnesses(&fixture)?;
        let refused = matches!(
            block_on(
                client
                    .multisig()
                    .propose_inception(&scenario(&participants, &witnesses)?)
            ),
            Err(ClientError::LonelyGroup)
        );
        assert!(refused, "a group of one was accepted");
        assert_eq!(sent(&transport)?.len(), 1);
        Ok(())
    }
}
