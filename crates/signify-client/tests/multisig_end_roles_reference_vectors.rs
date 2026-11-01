//! Exact vectors for a group's agent end-role round.
//!
//! What the reference's `addEndRoleMultisig` sends, and this port driven through the same round.

mod support;

use std::error::Error;

use serde::Deserialize;
use serde_json::Value;
use signify_client::multisig::{REPLY_ROUTE, REPLY_SLOT};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/client-multisig-end-roles/v1.json"
));
/// The multisig events fixture, for a genuine proposal on another route.
const INTERACTION_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/client-multisig-events/v1.json"
));

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    generated_on: String,
    sources: Vec<String>,
    provenance: Provenance,
    declarations: Declarations,
    members: Value,
    members_without_an_agent: Value,
    identifier_record: Value,
    group_record: Value,
    calls: Vec<Call>,
    pinned_confirmations: Pinned,
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
    add_end_role_multisig: String,
    notification_waits: Vec<String>,
    proposal_reads: Vec<String>,
    sends: Vec<String>,
    shared_stamp: bool,
    helper_uses: Value,
    scanned_files: usize,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
    requests: Vec<RecordedRequest>,
    waits: Vec<Wait>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    path: String,
    method: String,
    body: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Wait {
    route: String,
    min_count: u64,
}

#[derive(Debug, Deserialize)]
struct Pinned {
    group: String,
    stamp: String,
    agents: Vec<String>,
    members: Vec<String>,
    reply_route: String,
    announcement_route: String,
    announcement_topic: String,
    announcement_slot: String,
    propose_paths: Vec<String>,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(FIXTURE)?)
}

fn call<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a Call, Box<dyn Error>> {
    fixture
        .calls
        .iter()
        .find(|call| call.name == name)
        .ok_or_else(|| format!("the fixture records no call named {name}").into())
}

/// The bodies of one call's `POST` requests to paths ending in `ending`, as sent.
fn bodies<'a>(fixture: &'a Fixture, name: &str, ending: &str) -> Result<Vec<&'a str>, Box<dyn Error>> {
    Ok(call(fixture, name)?
        .requests
        .iter()
        .filter(|request| request.method == "POST" && request.path.ends_with(ending))
        .filter_map(|request| request.body.as_deref())
        .collect())
}

fn quirk<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a Value, Box<dyn Error>> {
    fixture
        .reference_quirks
        .get(name)
        .ok_or_else(|| format!("the fixture records no quirk named {name}").into())
}

#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert_eq!(fixture.upstream, "https://github.com/WebOfTrust/signify-ts.git");
    assert_eq!(fixture.generated_on, "2026-09-17");
    assert!(
        fixture
            .sources
            .contains(&"test-integration/utils/multisig-utils.ts".to_owned())
    );
    assert_eq!(fixture.provenance.bran, "0123456789abcdefghijk");
    assert_eq!(fixture.provenance.fixed_clock_ms, 1_700_000_000_123);
    assert!(fixture.provenance.note.contains("transpiled in memory"));
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));
    assert_ne!(fixture.provenance.local_member_prefix, fixture.provenance.peer_prefix);
    assert!(fixture.declarations.scanned_files > 100);
    assert!(
        fixture
            .declarations
            .add_end_role_multisig
            .starts_with("export async function addEndRoleMultisig(")
    );
    assert!(
        fixture
            .declarations
            .helper_uses
            .get("total")
            .and_then(Value::as_u64)
            .is_some_and(|total| total >= 4),
        "the helper is no longer called by the scenarios"
    );
    for call in &fixture.calls {
        assert!(!call.note.is_empty(), "{}", call.name);
    }
    Ok(())
}

#[test]
fn the_reference_authorizes_every_members_agent_one_announcement_each() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_confirmations;
    assert_eq!(
        pinned.members,
        [
            fixture.provenance.local_member_prefix.clone(),
            fixture.provenance.peer_prefix.clone()
        ]
    );
    assert_eq!(pinned.reply_route, "/end/role/add");
    assert_eq!(pinned.announcement_route, REPLY_ROUTE);
    assert_eq!(pinned.announcement_slot, REPLY_SLOT);
    assert_eq!(pinned.announcement_topic, "multisig");

    let replies = bodies(&fixture, "propose_the_end_roles", "/endroles")?;
    let announcements = bodies(&fixture, "propose_the_end_roles", "/exchanges")?;
    assert_eq!(replies.len(), 2);
    assert_eq!(announcements.len(), 2);
    for ((reply, announcement), agent) in replies.iter().zip(&announcements).zip(&pinned.agents) {
        let reply: Value = serde_json::from_str(reply)?;
        let rpy = reply.get("rpy").ok_or("a reply carries no rpy")?;
        assert_eq!(rpy.pointer("/a/eid").and_then(Value::as_str), Some(agent.as_str()));
        assert_eq!(rpy.pointer("/a/role").and_then(Value::as_str), Some("agent"));
        assert_eq!(
            rpy.pointer("/a/cid").and_then(Value::as_str),
            Some(pinned.group.as_str())
        );
        assert_eq!(rpy.get("dt").and_then(Value::as_str), Some(pinned.stamp.as_str()));

        let announcement: Value = serde_json::from_str(announcement)?;
        assert_eq!(
            announcement.pointer("/exn/r").and_then(Value::as_str),
            Some(REPLY_ROUTE)
        );
        assert_eq!(announcement.pointer("/exn/e/rpy"), Some(rpy));
        // The reference's attribute block is the group alone.
        let attributes = announcement
            .pointer("/exn/a")
            .and_then(Value::as_object)
            .ok_or("an announcement carries no attribute block")?;
        assert_eq!(attributes.keys().collect::<Vec<_>>(), ["gid", "i"]);
    }
    assert_eq!(
        pinned.propose_paths.first().map(String::as_str),
        Some("GET /identifiers/multisig/members")
    );
    Ok(())
}

#[test]
fn a_joining_member_never_reads_the_proposal() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.declarations.notification_waits.len(), 1);
    assert_eq!(fixture.declarations.proposal_reads, [] as [String; 0]);
    assert_eq!(fixture.declarations.sends.len(), 1);

    let joined = call(&fixture, "join_the_end_roles")?;
    assert_eq!(joined.waits.len(), 1);
    let wait = joined.waits.first().ok_or("no wait recorded")?;
    assert_eq!(wait.route, REPLY_ROUTE);
    assert_eq!(wait.min_count, 2, "one notification per signing member");
    assert!(
        fixture.calls.iter().all(|call| call
            .requests
            .iter()
            .all(|request| !request.path.starts_with("/multisig/request/"))),
        "a driven call read a group request"
    );
    let recorded = quirk(&fixture, "a_joining_member_never_reads_the_proposal")?;
    assert_eq!(recorded.get("group_requests_made"), Some(&Value::Bool(false)));
    Ok(())
}

#[test]
fn the_members_agree_only_on_a_shared_stamp() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert!(fixture.declarations.shared_stamp);
    let recorded = quirk(&fixture, "the_members_agree_only_on_a_shared_stamp")?;
    assert_eq!(recorded.get("agree"), Some(&Value::Bool(true)));
    assert_eq!(recorded.get("divergent_agrees"), Some(&Value::Bool(false)));
    assert_eq!(recorded.get("divergent_error"), Some(&Value::Null));
    assert!(call(&fixture, "join_the_end_roles_on_another_clock")?.error.is_none());
    assert_eq!(
        bodies(&fixture, "propose_the_end_roles", "/endroles")?,
        bodies(&fixture, "join_the_end_roles", "/endroles")?
    );
    Ok(())
}

#[test]
fn a_member_without_an_agent_throws_after_the_members_before_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let partial = call(&fixture, "propose_with_a_member_without_an_agent")?;
    assert_eq!(
        partial.error.as_deref(),
        Some("signing.ends.agent is null or undefined")
    );
    assert_eq!(
        bodies(&fixture, "propose_with_a_member_without_an_agent", "/endroles")?.len(),
        1
    );
    assert_eq!(
        bodies(&fixture, "propose_with_a_member_without_an_agent", "/exchanges")?.len(),
        1
    );
    Ok(())
}

#[test]
fn the_reference_seals_to_the_group_state_its_caller_passed() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for body in bodies(&fixture, "propose_with_a_stale_group_state", "/exchanges")? {
        assert!(body.contains("EStaleEstablishmentEventDigest00000000000000"));
    }
    let recorded = quirk(&fixture, "the_seal_is_the_callers_group_state")?;
    assert_eq!(
        recorded.get("stale_announcement_attachment_names_the_stale_digest"),
        Some(&Value::Bool(true))
    );
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
    Ok(())
}

/// This port, driven through the same round against a scripted agent.
mod driven {
    use super::*;
    use std::sync::Arc;

    use crate::support::{ADMIN, AgentTransport, BOOT, PASSCODE, agent_state, block_on, clock};
    use keri_cesr::crypto::cipher::Encrypter;
    use keri_cesr::crypto::salt::{Salt, SecurityTier};
    use keri_cesr::crypto::verifier::KeyTransferability;
    use keri_protocol::event::Timestamp;
    use keri_protocol::said::Said;
    use keria_types::api::Role;
    use signify_client::client::{ConnectedClient, SignifyClient};
    use signify_client::config::ClientConfig;
    use signify_client::error::ClientError;
    use signify_client::multisig::GroupEndRoleRequest;
    use signify_http::transport::Transport;
    use signify_keys::manager::DerivationCost;

    const ALIAS: &str = "member1";
    const GROUP_NAME: &str = "multisig";

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

    fn member(fixture: &Fixture) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut record = fixture.identifier_record.clone();
        seal(
            record
                .get_mut("salty")
                .ok_or("the recorded member has no key-manager block")?,
        )?;
        Ok(serde_json::to_vec(&record)?)
    }

    fn group(fixture: &Fixture) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut record = fixture.group_record.clone();
        let salty = record
            .pointer_mut("/group/mhab/salty")
            .ok_or("the recorded group has no member key-manager block")?;
        seal(salty)?;
        Ok(serde_json::to_vec(&record)?)
    }

    fn stamp(fixture: &Fixture) -> Result<Timestamp, Box<dyn Error>> {
        Ok(fixture.pinned_confirmations.stamp.parse::<Timestamp>()?)
    }

    /// The reference proposer's first announcement, as `GET /multisig/request/{said}` lists it.
    fn proposal(fixture: &Fixture, rewrite: impl Fn(&mut Value)) -> Result<(Said, Vec<u8>), Box<dyn Error>> {
        let announcement = bodies(fixture, "propose_the_end_roles", "/exchanges")?
            .first()
            .copied()
            .ok_or("the reference announced nothing")?;
        let posted: Value = serde_json::from_str(announcement)?;
        let mut exn = posted.get("exn").cloned().ok_or("the announcement carries no exn")?;
        rewrite(&mut exn);
        let said = Said::from_qb64(exn.get("d").and_then(Value::as_str).ok_or("no SAID")?)?;
        let listing = serde_json::json!([{ "exn": exn, "paths": {} }]);
        Ok((said, serde_json::to_vec(&listing)?))
    }

    /// The reference's own interaction proposal, recorded by the `client-multisig-events` fixture.
    fn interaction_exn() -> Result<Value, Box<dyn Error>> {
        let events: Value = serde_json::from_str(INTERACTION_FIXTURE)?;
        let announcement = events
            .get("calls")
            .and_then(Value::as_array)
            .and_then(|calls| {
                calls
                    .iter()
                    .find(|call| call.get("name").and_then(Value::as_str) == Some("announce_interaction"))
            })
            .and_then(|call| call.pointer("/requests/0/body"))
            .and_then(Value::as_str)
            .ok_or("the events fixture records no interaction announcement")?;
        let posted: Value = serde_json::from_str(announcement)?;
        Ok(posted.get("exn").ok_or("the announcement carries no exn")?.clone())
    }

    #[test]
    fn the_proposing_half_sends_the_references_replies_and_attachments() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let member = member(&fixture)?;
        let group = group(&fixture)?;
        let members = serde_json::to_vec(&fixture.members)?;
        let (client, transport) = connected(&[
            &member, &members, // the local member and the listing
            &group, b"{}", &group, &member, b"{}", // the first agent
            &group, b"{}", &group, &member, b"{}", // the second agent
        ])?;

        let replies = block_on(client.multisig().propose_agent_end_roles(&GroupEndRoleRequest {
            group_name: GROUP_NAME,
            local_member: ALIAS,
            timestamp: stamp(&fixture)?,
        }))?;
        assert_eq!(replies.len(), 2);

        let requests = sent(&transport)?;
        let posted = |ending: &str| -> Vec<String> {
            requests
                .iter()
                .filter(|(path, method, _)| method == "POST" && path.ends_with(ending))
                .filter_map(|(_, _, body)| body.clone())
                .collect()
        };

        // The replies are the reference's, byte for byte, signatures included.
        let reference_replies = bodies(&fixture, "propose_the_end_roles", "/endroles")?;
        assert_eq!(posted("/endroles"), reference_replies);

        // Each announcement is the reference's except for the payload: the same sender, addressee,
        // stamp, and route; the whole embed block — the reply and the block's own SAID — with the
        // same attachment, the group's seal and the same signature; and the members named beside
        // the group, which the reference leaves out. The payload decides the exn's SAID and the
        // signature over it, so those two are all that may differ.
        let reference_announcements = bodies(&fixture, "propose_the_end_roles", "/exchanges")?;
        let announcements = posted("/exchanges");
        assert_eq!(announcements.len(), 2);
        for (ours, theirs) in announcements.iter().zip(&reference_announcements) {
            let ours: Value = serde_json::from_str(ours)?;
            let theirs: Value = serde_json::from_str(theirs)?;
            for field in [
                "/exn/t", "/exn/i", "/exn/rp", "/exn/p", "/exn/dt", "/exn/r", "/exn/q", "/exn/e",
            ] {
                assert_eq!(ours.pointer(field), theirs.pointer(field), "{field} differs");
            }
            assert_eq!(
                ours.get("atc"),
                theirs.get("atc"),
                "the embedded reply's attachment differs"
            );
            assert_eq!(ours.get("tpc"), theirs.get("tpc"));
            assert_eq!(ours.get("rec"), theirs.get("rec"));
            assert_eq!(ours.pointer("/exn/a/gid"), theirs.pointer("/exn/a/gid"));
            assert_eq!(ours.pointer("/exn/a/i"), theirs.pointer("/exn/a/i"));
            let both = serde_json::json!(fixture.pinned_confirmations.members);
            assert_eq!(ours.pointer("/exn/a/smids"), Some(&both));
            assert_eq!(ours.pointer("/exn/a/rmids"), Some(&both));
            assert_eq!(theirs.pointer("/exn/a/smids"), None, "the reference now names members");
        }
        // And each reply reports what it authorized: the agent in the listing's order, the stamp
        // the request carried, and the reference's SAID.
        assert_eq!(fixture.pinned_confirmations.agents.len(), replies.len());
        for ((reply, theirs), agent) in replies
            .iter()
            .zip(&reference_replies)
            .zip(&fixture.pinned_confirmations.agents)
        {
            let theirs: Value = serde_json::from_str(theirs)?;
            assert_eq!(
                Some(reply.said().qb64()?.as_str()),
                theirs.pointer("/rpy/d").and_then(Value::as_str)
            );
            assert_eq!(reply.end_role().said, reply.said());
            assert_eq!(reply.end_role().role, Role::Agent);
            assert_eq!(&reply.end_role().endpoint.qb64()?, agent);
            assert_eq!(reply.end_role().stamp, stamp(&fixture)?);
            assert_eq!(
                reply.signing_members().len(),
                fixture.pinned_confirmations.members.len()
            );
        }
        Ok(())
    }

    #[test]
    fn a_member_without_an_agent_refuses_the_round_before_anything_is_sent() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let member = member(&fixture)?;
        let members = serde_json::to_vec(&fixture.members_without_an_agent)?;
        let (client, transport) = connected(&[&member, &members])?;

        let outcome = block_on(client.multisig().propose_agent_end_roles(&GroupEndRoleRequest {
            group_name: GROUP_NAME,
            local_member: ALIAS,
            timestamp: stamp(&fixture)?,
        }));
        assert!(
            matches!(&outcome, Err(ClientError::MemberHasNoAgent { member }) if *member == fixture.provenance.peer_prefix),
            "{outcome:?}"
        );
        assert!(
            sent(&transport)?.iter().all(|(_, method, _)| method == "GET"),
            "the round sent something before refusing"
        );
        Ok(())
    }

    #[test]
    fn a_joining_member_signs_the_proposers_reply_from_the_proposal() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let member = member(&fixture)?;
        let group = group(&fixture)?;
        let members = serde_json::to_vec(&fixture.members)?;
        let (said, listing) = proposal(&fixture, |_| {})?;
        let (client, transport) = connected(&[
            &member, &listing, &group, &members, &group, b"{}", &group, &member, b"{}",
        ])?;

        let reply = block_on(client.multisig().accept_end_role(GROUP_NAME, ALIAS, &said))?;

        // Stamp, role, and endpoint read from the proposal: the reply is the proposer's own.
        let requests = sent(&transport)?;
        let posted: Vec<&str> = requests
            .iter()
            .filter(|(path, method, _)| method == "POST" && path.ends_with("/endroles"))
            .filter_map(|(_, _, body)| body.as_deref())
            .collect();
        let reference = bodies(&fixture, "propose_the_end_roles", "/endroles")?;
        assert_eq!(posted.first(), reference.first());
        assert_eq!(posted.len(), 1);
        assert!(
            requests
                .iter()
                .any(|(path, _, _)| path == &format!("/multisig/request/{}", said.qb64().unwrap_or_default())),
            "the proposal was not read"
        );
        let announcements: Vec<&str> = requests
            .iter()
            .filter(|(path, method, _)| method == "POST" && path.ends_with("/exchanges"))
            .filter_map(|(_, _, body)| body.as_deref())
            .collect();
        assert_eq!(announcements.len(), 1, "one proposal is answered with one announcement");
        let announced: Value = serde_json::from_str(announcements.first().copied().ok_or("nothing was announced")?)?;
        assert_eq!(announced.pointer("/exn/r").and_then(Value::as_str), Some(REPLY_ROUTE));
        assert_eq!(
            announced.pointer("/exn/e/rpy/d").and_then(Value::as_str),
            Some(reply.said().qb64()?.as_str())
        );
        // This member is the reference's proposer, so the reply it signs from the proposal is the
        // one the reference proposed: the whole embed block and its attachment are the reference's
        // own, stamped as the proposal was.
        let theirs: Value = serde_json::from_str(
            bodies(&fixture, "propose_the_end_roles", "/exchanges")?
                .first()
                .copied()
                .ok_or("the reference announced nothing")?,
        )?;
        for field in ["/exn/i", "/exn/rp", "/exn/dt", "/exn/e"] {
            assert_eq!(announced.pointer(field), theirs.pointer(field), "{field} differs");
        }
        assert_eq!(announced.get("atc"), theirs.get("atc"), "the attachment differs");
        assert_eq!(announced.get("rec"), theirs.get("rec"));
        // And what was accepted is what the proposal carried.
        assert_eq!(reply.end_role().role, Role::Agent);
        assert_eq!(reply.end_role().stamp, stamp(&fixture)?);
        assert_eq!(
            Some(&reply.end_role().endpoint.qb64()?),
            fixture.pinned_confirmations.agents.first()
        );
        Ok(())
    }

    #[test]
    fn a_proposal_whose_reply_this_member_would_not_build_is_refused_unsent() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let member = member(&fixture)?;
        let group = group(&fixture)?;
        // The reply's SAID no longer matches its content — as a proposal from a member on another
        // clock whose stamp was rewritten would not.
        let (said, listing) = proposal(&fixture, |exn| {
            if let Some(stamp) = exn.pointer_mut("/e/rpy/dt") {
                *stamp = Value::String("2023-11-14T22:13:21.123000+00:00".to_owned());
            }
        })?;
        let (client, transport) = connected(&[&member, &listing, &group])?;

        let outcome = block_on(client.multisig().accept_end_role(GROUP_NAME, ALIAS, &said));
        assert!(
            matches!(outcome, Err(ClientError::ProposalMismatch { .. })),
            "{outcome:?}"
        );
        assert!(sent(&transport)?.iter().all(|(_, method, _)| method == "GET"));
        Ok(())
    }

    #[test]
    fn an_interaction_this_member_would_not_build_is_refused_unsent() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let member = member(&fixture)?;
        let group = group(&fixture)?;
        let mut exn = interaction_exn()?;
        let digest = exn
            .pointer_mut("/e/ixn/d")
            .ok_or("the proposal embeds no interaction")?;
        *digest = Value::String(fixture.pinned_confirmations.group.clone());
        let said = Said::from_qb64(exn.get("d").and_then(Value::as_str).ok_or("no SAID")?)?;
        let listing = serde_json::to_vec(&serde_json::json!([{ "exn": exn, "paths": {} }]))?;
        let (client, transport) = connected(&[&member, &listing, &group, b"{}"])?;

        let outcome = block_on(
            client
                .multisig()
                .accept_interaction(GROUP_NAME, ALIAS, &said, stamp(&fixture)?),
        );
        assert!(
            matches!(outcome, Err(ClientError::ProposalMismatch { .. })),
            "{outcome:?}"
        );
        let requests = sent(&transport)?;
        assert_eq!(requests.len(), 3, "the member, the proposal, and the group");
        assert!(requests.iter().all(|(_, method, _)| method == "GET"));
        Ok(())
    }

    #[test]
    fn a_reply_for_another_controller_or_route_is_refused() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let member = member(&fixture)?;
        let group = group(&fixture)?;
        let other = fixture.provenance.peer_prefix.clone();
        for (rewrite, label) in [
            (
                Box::new(move |exn: &mut Value| {
                    if let Some(cid) = exn.pointer_mut("/e/rpy/a/cid") {
                        *cid = Value::String(other.clone());
                    }
                }) as Box<dyn Fn(&mut Value)>,
                "another controller",
            ),
            (
                Box::new(|exn: &mut Value| {
                    if let Some(route) = exn.pointer_mut("/e/rpy/r") {
                        *route = Value::String("/loc/scheme".to_owned());
                    }
                }),
                "another route",
            ),
        ] {
            let (said, listing) = proposal(&fixture, rewrite)?;
            let (client, transport) = connected(&[&member, &listing, &group])?;
            let outcome = block_on(client.multisig().accept_end_role(GROUP_NAME, ALIAS, &said));
            assert!(
                matches!(outcome, Err(ClientError::NotAnEndRoleProposal { .. })),
                "{label}: {outcome:?}"
            );
            assert!(
                sent(&transport)?.iter().all(|(_, method, _)| method == "GET"),
                "{label}"
            );
        }
        Ok(())
    }

    /// The reference's own interaction proposal for this group, which the `client-multisig-events`
    /// fixture recorded, is handed to the end-role half. A route carries its own embed, so a
    /// relabelled reply would be refused as malformed before its route was ever compared; a genuine
    /// interaction proposal reaches the comparison.
    #[test]
    fn a_proposal_on_another_route_is_not_an_end_role() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let member = member(&fixture)?;
        let exn = interaction_exn()?;
        assert_eq!(
            exn.pointer("/a/gid").and_then(Value::as_str),
            Some(fixture.pinned_confirmations.group.as_str())
        );
        let said = Said::from_qb64(exn.get("d").and_then(Value::as_str).ok_or("no SAID")?)?;
        let listing = serde_json::to_vec(&serde_json::json!([{ "exn": exn, "paths": {} }]))?;

        let (client, transport) = connected(&[&member, &listing])?;
        let outcome = block_on(client.multisig().accept_end_role(GROUP_NAME, ALIAS, &said));
        assert!(
            matches!(
                outcome,
                Err(ClientError::NotAnEndRoleProposal { found: "/multisig/ixn" })
            ),
            "an interaction proposal was not refused as an end role: {outcome:?}"
        );
        assert!(
            sent(&transport)?.iter().all(|(_, method, _)| method == "GET"),
            "the round sent something before refusing"
        );
        Ok(())
    }
}
