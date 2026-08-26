//! Exact group-endpoint vectors recorded from the pinned reference's own `Groups`.
//!
//! `Groups` takes a whole `SignifyClient`, so the generator drives the real client with
//! `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would, with
//! the clock and the agent's key pinned.
//!
//! The evidence here has an unusual shape. The pinned unit case asserts **three addresses and three
//! methods and nothing else**, and it reaches them by passing a forty-six-character SAID, a rotation
//! whose event is `{}`, the signature `'sig'`, members named `1` and `a`, and — for the proposal —
//! no signature at all. So the three addresses reproduce exactly, and every one of those arguments
//! is proven unrepresentable: the pattern Roadmap 3.8, 6.9, and 7.1 used.
//!
//! Beside them the generator drives the same three calls with values a real member would send, and
//! records what the reference does with each.

use std::error::Error;

use serde::Deserialize;
use serde_json::Value;
use signify_client::endpoint::exchanges::{ClassifiedExchange, MULTISIG_TOPIC, MultisigRoute};
use signify_client::endpoint::groups::{JOIN_SEGMENT, MULTISIG_SEGMENT, REQUEST_SEGMENT};
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_http::request::ResourcePath;
use signify_keri::said::Said;
use signify_types::api::{GroupOperation, MultisigExchangeResource};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-groups/v1.json");

const REAL_SAID: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const GROUP: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const MEMBER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";

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
    pinned_arguments: PinnedArguments,
    calls: Vec<Call>,
    pinned_confirmations: PinnedConfirmations,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    admin_url: String,
    fixed_clock_ms: u64,
    agent_prefix: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    get_request_path: String,
    get_request_method: String,
    get_request_signature: Vec<String>,
    get_request_return_type: String,
    send_request_path: String,
    send_request_data: String,
    send_request_method: String,
    send_request_signature: Vec<String>,
    send_request_return_type: String,
    join_path: String,
    join_data: String,
    join_method: String,
    join_signature: Vec<String>,
    join_return_type: String,
    groups_members: Vec<String>,
    schema_exn_multisig: String,
    schema_group_operation_metadata: String,
    get_request_consumers: Consumers,
    send_request_consumers: Consumers,
    groups_accessor_uses: Scan,
    notes: Value,
}

#[derive(Debug, Deserialize)]
struct Consumers {
    total: usize,
    consumer_files: Vec<ScanHit>,
    consumer_total: usize,
    scanned_files: usize,
}

#[derive(Debug, Deserialize)]
struct Scan {
    needle: String,
    total: usize,
    scanned_files: usize,
}

#[derive(Debug, Deserialize)]
struct ScanHit {
    file: String,
    count: usize,
}

#[derive(Debug, Deserialize)]
struct PinnedArguments {
    said: String,
    said_length: usize,
    qualified_digest_length: usize,
    said_is_a_digest: bool,
    rotation: String,
    signatures: Vec<String>,
    signing_members: Vec<String>,
    rotation_members: Vec<String>,
    send_request_signatures: Vec<String>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
    answer: Value,
    request: Option<RecordedRequest>,
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
    send_request_path: String,
    send_request_method: String,
    get_request_path: String,
    get_request_method: String,
    join_path: String,
    join_method: String,
    published_paths: Vec<String>,
    every_pinned_assertion_is_driven: bool,
    every_published_path_is_driven: bool,
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

fn request_of<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a RecordedRequest, Box<dyn Error>> {
    call(fixture, name)?
        .request
        .as_ref()
        .ok_or_else(|| format!("call {name} recorded no request").into())
}

/// The address this port builds for a group read.
fn read_path(said: &Said) -> Result<ResourcePath, Box<dyn Error>> {
    Ok(ResourcePath::builder()
        .segment(MULTISIG_SEGMENT)
        .segment(REQUEST_SEGMENT)
        .segment(&said.qb64()?)
        .build()?)
}

/// The address this port builds for one of the two writes.
fn write_path(alias: &str, action: &str) -> Result<ResourcePath, Box<dyn Error>> {
    Ok(ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(alias)
        .segment(MULTISIG_SEGMENT)
        .segment(action)
        .build()?)
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
    assert!(fixture.sources.iter().any(|source| source.ends_with("grouping.ts")));
    assert!(
        fixture
            .sources
            .iter()
            .any(|source| source.ends_with("grouping.test.ts"))
    );
    assert_eq!(fixture.provenance.bran, "0123456789abcdefghijk");
    assert_eq!(fixture.provenance.admin_url, "http://127.0.0.1:3901");
    assert_eq!(fixture.provenance.fixed_clock_ms, 1_700_000_000_123);
    assert!(!fixture.provenance.agent_prefix.is_empty());
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 12);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        // The reference refuses none of the twelve, including every junk argument.
        assert_eq!(entry.error, None, "call {} was refused upstream", entry.name);
        assert!(entry.request.is_some(), "call {} sent nothing", entry.name);
    }
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    // Three methods, and this item ports all three.
    assert_eq!(
        declarations.groups_members,
        ["client", "<constructor>", "getRequest", "sendRequest", "join"]
    );

    // The read: one segment concatenated rather than interpolated, and never encoded.
    assert_eq!(declarations.get_request_path, "path = `/multisig/request/` + said");
    assert_eq!(declarations.get_request_method, "method = 'GET'");
    assert_eq!(declarations.get_request_signature, ["said: string"]);
    assert_eq!(declarations.get_request_return_type, "Promise<ExnMultisig[]>");

    // The proposal: three fields, and neither a topic nor a recipient list.
    assert_eq!(
        declarations.send_request_path,
        "path = `/identifiers/${name}/multisig/request`"
    );
    assert_eq!(declarations.send_request_method, "method = 'POST'");
    for field in ["exn:", "sigs:", "atc:"] {
        assert!(declarations.send_request_data.contains(field), "no {field}");
    }
    for absent in ["tpc:", "rec:"] {
        assert!(
            !declarations.send_request_data.contains(absent),
            "the body now writes {absent}"
        );
    }

    // The join: six fields, its topic a literal.
    assert_eq!(declarations.join_path, "path = `/identifiers/${name}/multisig/join`");
    assert_eq!(declarations.join_method, "method = 'POST'");
    assert!(declarations.join_data.contains("tpc: 'multisig'"));
    assert!(declarations.join_data.contains("rot: rot.sad"));
    for field in ["sigs:", "gid:", "smids:", "rmids:"] {
        assert!(declarations.join_data.contains(field), "no {field}");
    }
    // The two writes' signatures, which are where the loose arguments this port bundles come from.
    assert_eq!(
        declarations.send_request_signature,
        ["name: string", "exn: Exn", "sigs: string[]", "atc: string"]
    );
    assert_eq!(declarations.join_signature.len(), 6);
    assert!(
        declarations
            .join_signature
            .iter()
            .any(|parameter| parameter == "rot: any")
    );
    assert!(
        declarations
            .join_signature
            .iter()
            .any(|parameter| parameter.starts_with("gid:"))
    );

    assert!(declarations.notes.is_object());
    Ok(())
}

#[test]
fn two_of_the_three_methods_have_no_consumer() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    // The read is what this family is actually for.
    assert_eq!(declarations.get_request_consumers.scanned_files, 117);
    assert!(
        declarations.get_request_consumers.consumer_total >= 20,
        "getRequest is used {} times",
        declarations.get_request_consumers.consumer_total
    );
    assert!(
        declarations
            .get_request_consumers
            .consumer_files
            .iter()
            .all(|hit| hit.file.starts_with("test-integration/") && hit.count > 0)
    );

    // The proposal is called nowhere outside its own declaration and unit test.
    assert_eq!(declarations.send_request_consumers.consumer_total, 0);
    assert!(declarations.send_request_consumers.consumer_files.is_empty());
    assert!(declarations.send_request_consumers.total >= 2);

    // And the accessor itself is reached from the integration tree.
    assert_eq!(declarations.groups_accessor_uses.needle, ".groups()");
    assert!(declarations.groups_accessor_uses.total >= 1);
    assert_eq!(declarations.groups_accessor_uses.scanned_files, 117);
    Ok(())
}

#[test]
fn every_pinned_assertion_is_driven() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let confirmations = &fixture.pinned_confirmations;
    assert!(confirmations.every_pinned_assertion_is_driven);
    assert!(confirmations.every_published_path_is_driven);
    assert_eq!(confirmations.published_paths.len(), 3);
    assert_eq!(confirmations.send_request_path, "/identifiers/aid1/multisig/request");
    assert_eq!(confirmations.send_request_method, "POST");
    assert_eq!(confirmations.join_path, "/identifiers/aid1/multisig/join");
    assert_eq!(confirmations.join_method, "POST");
    assert_eq!(confirmations.get_request_method, "GET");
    // The read's address is the one that carries the pinned test's non-SAID; it is asserted by
    // name in `the_pinned_read_value_is_not_a_qualified_digest`.
    assert!(confirmations.get_request_path.starts_with("/multisig/request/"));
    assert!(!confirmations.note.is_empty());

    // The two writes reproduce byte for byte, because their addresses carry only the alias.
    assert_eq!(
        write_path("aid1", REQUEST_SEGMENT)?.as_str(),
        confirmations.send_request_path
    );
    assert_eq!(write_path("aid1", JOIN_SEGMENT)?.as_str(), confirmations.join_path);
    Ok(())
}

// ---------------------------------------------------------------------------
// The pinned case's arguments, each proven unrepresentable.
// ---------------------------------------------------------------------------

#[test]
fn the_pinned_read_value_is_not_a_qualified_digest() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_arguments;
    assert_eq!(pinned.said_length, 46);
    assert_eq!(pinned.qualified_digest_length, 44);
    assert!(!pinned.said_is_a_digest);

    // The reference sent it, and the address it produced is the one the test asserts.
    let recorded = request_of(&fixture, "get_request_pinned")?;
    assert_eq!(recorded.path, format!("/multisig/request/{}", pinned.said));
    assert_eq!(recorded.method, "GET");

    // Here it is refused, and the case the test is making reproduces with a real digest.
    assert!(pinned.said.parse::<Said>().is_err());
    let real = request_of(&fixture, "get_request_real_said")?;
    assert_eq!(read_path(&REAL_SAID.parse::<Said>()?)?.as_str(), real.path);
    assert_eq!(real.path, format!("/multisig/request/{REAL_SAID}"));
    Ok(())
}

#[test]
fn the_pinned_join_arguments_are_each_unrepresentable() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_arguments;
    assert!(!pinned.note.is_empty());

    // A rotation whose event is `{}`.
    assert_eq!(pinned.rotation, "{ sad: {} }");
    let recorded = request_of(&fixture, "join_pinned")?;
    let body: Value = serde_json::from_str(recorded.body.as_deref().ok_or("no body")?)?;
    assert_eq!(body.get("rot"), Some(&Value::Object(serde_json::Map::new())));

    // The signature `'sig'`, which is not qualified material.
    assert_eq!(pinned.signatures, ["sig"]);
    assert_eq!(
        body.get("sigs").and_then(Value::as_array).map(Vec::len),
        Some(1),
        "the recorded call sent one signature"
    );

    // Members named `1`, `2`, `3` and `a`, `b`, `c`, none of which is a prefix.
    assert_eq!(pinned.signing_members, ["1", "2", "3"]);
    assert_eq!(pinned.rotation_members, ["a", "b", "c"]);
    for member in pinned.signing_members.iter().chain(&pinned.rotation_members) {
        assert!(
            signify_keri::prefix::IdentifierPrefix::from_qb64(member).is_err(),
            "{member:?} was accepted as a member prefix"
        );
    }
    // And the group it names is the same forty-six-character non-digest.
    assert_eq!(body.get("gid").and_then(Value::as_str), Some(pinned.said.as_str()));
    assert!(
        signify_keri::prefix::IdentifierPrefix::from_qb64(&pinned.said).is_err(),
        "the pinned group identifier was accepted"
    );
    Ok(())
}

#[test]
fn the_pinned_proposal_carries_no_signature() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert!(fixture.pinned_arguments.send_request_signatures.is_empty());

    let recorded = request_of(&fixture, "send_request_pinned")?;
    let body: Value = serde_json::from_str(recorded.body.as_deref().ok_or("no body")?)?;
    // The reference sent it: an exchange nobody signed, for the agent to relay to every member.
    assert_eq!(body.get("sigs"), Some(&Value::Array(Vec::new())));
    assert_eq!(body.get("atc").and_then(Value::as_str), Some(""));
    // And its sender is the word `test`, which is not a prefix either.
    assert_eq!(
        body.get("exn").and_then(|exn| exn.get("i")).and_then(Value::as_str),
        Some("test")
    );
    assert!(signify_keri::prefix::IdentifierPrefix::from_qb64("test").is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// The addresses.
// ---------------------------------------------------------------------------

#[test]
fn the_real_read_reproduces_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "get_request_real_said")?;
    let path = read_path(&REAL_SAID.parse::<Said>()?)?;
    assert_eq!(path.as_str(), recorded.path);
    assert_eq!(recorded.method, "GET");
    assert_eq!(recorded.body, None);
    assert_eq!(path.query(), None);
    Ok(())
}

#[test]
fn none_of_the_three_dynamic_values_reaches_the_wire_unencoded() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;

    // An alias holding delimiters becomes two segments and a query upstream.
    let alias = request_of(&fixture, "send_request_escaping_alias")?;
    assert_eq!(alias.path, "/identifiers/a/b?c=d/multisig/request");
    assert_eq!(
        write_path("a/b?c=d", REQUEST_SEGMENT)?.as_str(),
        "/identifiers/a%2Fb%3Fc%3Dd/multisig/request"
    );

    // A SAID holding them climbs out of its own segment.
    let escaping = request_of(&fixture, "get_request_escaping_said")?;
    assert_eq!(escaping.path, "/multisig/request/../identifiers/aid1?x=1");
    assert!("../identifiers/aid1?x=1".parse::<Said>().is_err());

    // And the empty string the reference's own helper falls back to addresses the collection.
    let empty = request_of(&fixture, "get_request_empty_said")?;
    assert_eq!(empty.path, "/multisig/request/");
    assert!("".parse::<Said>().is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// The bodies.
// ---------------------------------------------------------------------------

#[test]
fn a_signed_proposal_writes_three_fields_and_no_topic() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "send_request_signed")?;
    let rendered = recorded.body.as_deref().ok_or("no body")?;
    let body: Value = serde_json::from_str(rendered)?;

    // Exactly the reference's three, in its order.
    assert!(rendered.starts_with(r#"{"exn":"#));
    let fields = body.as_object().ok_or("the body is not an object")?;
    assert_eq!(fields.len(), 3);
    for label in ["exn", "sigs", "atc"] {
        assert!(fields.contains_key(label), "no {label}");
    }
    // Where Roadmap 7.7's submission of the same message writes five.
    for absent in ["tpc", "rec"] {
        assert!(!fields.contains_key(absent), "the body now writes {absent}");
    }
    assert_eq!(
        body.get("sigs").and_then(Value::as_array).map(Vec::len),
        Some(1),
        "the signed proposal carries one signature"
    );
    assert_eq!(body.get("atc").and_then(Value::as_str), Some("-LAZ5AACAA-e-icp"));
    Ok(())
}

#[test]
fn a_real_join_writes_the_references_six_fields_in_order() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "join_real")?;
    let rendered = recorded.body.as_deref().ok_or("no body")?;
    let body: Value = serde_json::from_str(rendered)?;

    let mut previous = 0_usize;
    for label in [
        r#""tpc":"#,
        r#""rot":"#,
        r#""sigs":"#,
        r#""gid":"#,
        r#""smids":"#,
        r#""rmids":"#,
    ] {
        let at = rendered.find(label).ok_or_else(|| format!("no {label}"))?;
        assert!(at >= previous, "{label} is out of order in {rendered}");
        previous = at;
    }
    // The topic is the literal this port shares with Roadmap 7.7 rather than a second copy.
    assert_eq!(body.get("tpc").and_then(Value::as_str), Some(MULTISIG_TOPIC));
    assert_eq!(body.get("gid").and_then(Value::as_str), Some(GROUP));
    assert_eq!(
        body.get("rot").and_then(|rot| rot.get("t")).and_then(Value::as_str),
        Some("rot")
    );
    assert_eq!(body.get("smids").and_then(Value::as_array).map(Vec::len), Some(2));
    assert_eq!(body.get("rmids").and_then(Value::as_array).map(Vec::len), Some(2));
    Ok(())
}

#[test]
fn passing_the_event_instead_of_its_serder_sends_no_rotation() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // `join` declares `rot: any` and writes `rot.sad`, so passing the rotation event its own
    // JSDoc names drops the field entirely.
    let recorded = request_of(&fixture, "join_event_instead_of_serder")?;
    let body: Value = serde_json::from_str(recorded.body.as_deref().ok_or("no body")?)?;
    assert_eq!(body.get("rot"), None, "the event was sent after all");
    // The other five fields are still there, so nothing announces the loss.
    for label in ["tpc", "sigs", "gid", "smids", "rmids"] {
        assert!(body.get(label).is_some(), "no {label}");
    }
    Ok(())
}

#[test]
fn a_join_naming_no_member_is_sent_upstream_and_refused_here() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "join_no_members")?;
    let body: Value = serde_json::from_str(recorded.body.as_deref().ok_or("no body")?)?;
    // The reference sent both lists empty.
    assert_eq!(body.get("smids"), Some(&Value::Array(Vec::new())));
    assert_eq!(body.get("rmids"), Some(&Value::Array(Vec::new())));
    // Refused here — see the unit test `a_join_naming_no_signing_member_is_refused`, which
    // exercises the same check without needing a keeper.
    Ok(())
}

// ---------------------------------------------------------------------------
// The answers.
// ---------------------------------------------------------------------------

#[test]
fn a_request_listing_decodes_and_classifies() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "get_request_real_said")?;
    let listing: Vec<MultisigExchangeResource> = serde_json::from_value(recorded.answer.clone())?;
    assert_eq!(listing.len(), 1);

    let first = listing.first().ok_or("empty listing")?;
    assert_eq!(first.group_name.as_deref(), Some("multisig"));
    assert_eq!(first.member_name.as_deref(), Some("member1"));
    assert_eq!(first.sender.as_deref(), Some(MEMBER));

    // And this is what Roadmap 8.1 is for: the listing is exactly what its classifiers read.
    let classified = ClassifiedExchange::try_from(first)?;
    let proposal = classified.as_multisig().ok_or("not a multisig proposal")?;
    assert_eq!(proposal.route, MultisigRoute::Inception);
    assert_eq!(proposal.attributes.group.qb64()?, GROUP);
    assert_eq!(
        proposal.attributes.signing_members.as_ref().map(Vec::len),
        Some(2),
        "the proposal names both members"
    );
    Ok(())
}

#[test]
fn an_answer_that_is_not_a_listing_is_refused_where_the_reference_casts_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "get_request_wrong_shape")?;
    // The reference returned it as an `ExnMultisig[]`.
    assert_eq!(recorded.error, None);
    assert!(recorded.result.get("notes").is_some());
    assert!(serde_json::from_value::<Vec<MultisigExchangeResource>>(recorded.answer.clone()).is_err());
    Ok(())
}

#[test]
fn a_join_is_answered_with_the_operation_it_declares() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "join_real")?;
    let operation: GroupOperation = serde_json::from_value(recorded.answer.clone())?;
    assert_eq!(operation.name, format!("group.{GROUP}"));
    // Still running: a group rotation completes only when enough members have contributed.
    assert!(!operation.outcome.is_done());
    assert!(matches!(
        operation.outcome,
        signify_types::api::OperationOutcome::Pending
    ));

    // The two writes in this one class declare different answers, which is the §10 question
    // Roadmap 7.7 raised — a `join` says operation and a `sendRequest` says exchange message.
    assert_eq!(fixture.declarations.join_return_type, "Promise<GroupOperation>");
    assert_eq!(fixture.declarations.send_request_return_type, "Promise<Exn>");
    assert!(fixture.declarations.schema_group_operation_metadata.contains("pre"));
    assert!(fixture.declarations.schema_exn_multisig.contains("paths"));
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the recorded divergences are not an object")?;
    assert_eq!(quirks.len(), 7);
    for (name, quirk) in quirks {
        let entry = quirk.as_object().ok_or("a divergence is not an object")?;
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
