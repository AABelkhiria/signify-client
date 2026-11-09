//! Exact vectors for a group's agent end-role round.
//!
//! What the reference's `addEndRoleMultisig` sends, and this port driven through the same round.

mod support;

use std::error::Error;

use serde::Deserialize;
use serde_json::Value;
use signify_client::multisig::{REPLY_ROUTE, REPLY_SLOT};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
/// The multisig events fixture, for a genuine proposal on another route.
const INTERACTION_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/client-multisig-events/v1.json"
));
/// The multisig credentials fixture, for genuine proposals on the credential routes.
const CREDENTIALS_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/client-multisig-credentials/v1.json"
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
    helper_uses: Value,
    scanned_files: usize,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
    requests: Vec<RecordedRequest>,
    waits: Vec<Wait>,
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
    support::fixture("client-multisig-end-roles")
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

    use crate::support::{AgentTransport, Harness, PASSCODE, SentRequest, block_on, connected, reseal, sent_all};
    use keri_acdc::credential::{Credential, CredentialAttributes, CredentialBuilder, RegistryIdentifier};

    use keri_protocol::event::Timestamp;
    use keri_protocol::prefix::IdentifierPrefix;
    use keri_protocol::said::Said;
    use keria_types::api::Role;

    use signify_client::error::ClientError;
    use signify_client::multisig::GroupEndRoleRequest;

    use signify_keys::acdc::revocation::{RevocationEvent, RevocationEventBuilder};

    const ALIAS: &str = "member1";
    const GROUP_NAME: &str = "multisig";

    fn member(fixture: &Fixture) -> Result<Vec<u8>, Box<dyn Error>> {
        reseal(&fixture.identifier_record, PASSCODE)
    }

    fn group(fixture: &Fixture) -> Result<Vec<u8>, Box<dyn Error>> {
        reseal(&fixture.group_record, PASSCODE)
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

    /// The reference's own proposal from `call` in the `client-multisig-credentials` fixture.
    fn credential_exn(call: &str) -> Result<Value, Box<dyn Error>> {
        let events: Value = serde_json::from_str(CREDENTIALS_FIXTURE)?;
        let announcement = events
            .get("calls")
            .and_then(Value::as_array)
            .and_then(|calls| {
                calls
                    .iter()
                    .find(|recorded| recorded.get("name").and_then(Value::as_str) == Some(call))
            })
            .and_then(|recorded| recorded.get("requests"))
            .and_then(Value::as_array)
            .and_then(|requests| requests.last())
            .and_then(|request| request.get("body"))
            .and_then(Value::as_str)
            .ok_or("the credentials fixture records no such announcement")?;
        let posted: Value = serde_json::from_str(announcement)?;
        Ok(posted.get("exn").ok_or("the announcement carries no exn")?.clone())
    }

    /// A proposal as `GET /multisig/request/{said}` lists it, with `pointer` set to `value`.
    fn listed(mut exn: Value, pointer: &str, value: &str) -> Result<(Said, Vec<u8>), Box<dyn Error>> {
        *exn.pointer_mut(pointer).ok_or("the proposal lacks that field")? = Value::String(value.to_owned());
        let said = Said::from_qb64(exn.get("d").and_then(Value::as_str).ok_or("no SAID")?)?;
        Ok((
            said,
            serde_json::to_vec(&serde_json::json!([{ "exn": exn, "paths": {} }]))?,
        ))
    }

    /// The agent's answers to a joining member, up to and including its submission.
    fn joining_answers<'a>(member: &'a [u8], listing: &'a [u8], members: &'a [u8], group: &'a [u8]) -> [&'a [u8]; 8] {
        [member, listing, members, group, b"{}", group, member, b"{}"]
    }

    /// Asserts a refused round read its four resources and wrote nothing.
    fn assert_nothing_written(transport: &AgentTransport) -> Result<(), Box<dyn Error>> {
        let requests = sent_all(transport)?;
        assert_eq!(
            requests.len(),
            4,
            "the member, the proposal, the members, and the group"
        );
        assert!(requests.iter().all(|SentRequest { method, .. }| method == "GET"));
        Ok(())
    }

    /// The first write a round made, as its method and resource.
    fn first_write(transport: &AgentTransport) -> Result<(String, String), Box<dyn Error>> {
        let SentRequest {
            path: resource, method, ..
        } = sent_all(transport)?
            .into_iter()
            .find(|SentRequest { method, .. }| method != "GET")
            .ok_or("nothing was written")?;
        Ok((method, resource))
    }

    /// One pinned value from the `client-multisig-credentials` fixture.
    fn credential_confirmation(field: &str) -> Result<String, Box<dyn Error>> {
        let events: Value = serde_json::from_str(CREDENTIALS_FIXTURE)?;
        let value = events
            .pointer(&format!("/pinned_confirmations/{field}"))
            .and_then(Value::as_str)
            .ok_or_else(|| format!("no {field}"))?;
        Ok(value.to_owned())
    }

    /// A credential the group issues, with attributes of this test's own.
    fn group_credential(fixture: &Fixture) -> Result<Credential, Box<dyn Error>> {
        let attributes = CredentialAttributes::new(stamp(fixture)?)
            .text("LEI", "5493001KJTIIGC8Y1R17")?
            .timestamp()?;
        Ok(CredentialBuilder::new(
            IdentifierPrefix::from_qb64(&fixture.pinned_confirmations.group)?,
            RegistryIdentifier::from_qb64(&credential_confirmation("registry")?)?,
            Said::from_qb64(&credential_confirmation("schema")?)?,
            attributes,
        )
        .build()?)
    }

    /// A revocation of the fixture's credential.
    fn group_revocation(fixture: &Fixture) -> Result<RevocationEvent, Box<dyn Error>> {
        let credential = Said::from_qb64(&credential_confirmation("credential")?)?;
        Ok(RevocationEventBuilder::new(
            credential,
            RegistryIdentifier::from_qb64(&credential_confirmation("registry")?)?,
            credential,
            fixture.pinned_confirmations.stamp.parse()?,
        )
        .build()?)
    }

    /// The reference's revocation proposal in the slot its route names.
    fn revocation_exn() -> Result<Value, Box<dyn Error>> {
        let mut exn = credential_exn("propose_the_revocation")?;
        let embeds = exn
            .get_mut("e")
            .and_then(Value::as_object_mut)
            .ok_or("the proposal embeds nothing")?;
        let revocation = embeds.remove("iss").ok_or("the reference moved its revocation")?;
        embeds.insert("rev".to_owned(), revocation);
        Ok(exn)
    }

    /// That proposal, as `GET /multisig/request/{said}` lists it, claiming `digest` for its event.
    fn interaction_proposal(digest: &str) -> Result<(Said, Vec<u8>), Box<dyn Error>> {
        listed(interaction_exn()?, "/e/ixn/d", digest)
    }

    #[test]
    fn the_proposing_half_sends_the_references_replies_and_attachments() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let member = member(&fixture)?;
        let group = group(&fixture)?;
        let members = serde_json::to_vec(&fixture.members)?;
        let Harness { client, transport, .. } = connected(&[
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

        let requests = sent_all(&transport)?;
        let posted = |ending: &str| -> Vec<String> {
            requests
                .iter()
                .filter(|SentRequest { path, method, .. }| method == "POST" && path.ends_with(ending))
                .filter_map(|SentRequest { body, .. }| body.clone())
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
        let Harness { client, transport, .. } = connected(&[&member, &members])?;

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
            sent_all(&transport)?
                .iter()
                .all(|SentRequest { method, .. }| method == "GET"),
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
        let Harness { client, transport, .. } = connected(&[
            &member, &listing, &group, &members, &group, b"{}", &group, &member, b"{}",
        ])?;

        let reply = block_on(client.multisig().accept_end_role(GROUP_NAME, ALIAS, &said))?;

        // Stamp, role, and endpoint read from the proposal: the reply is the proposer's own.
        let requests = sent_all(&transport)?;
        let posted: Vec<&str> = requests
            .iter()
            .filter(|SentRequest { path, method, .. }| method == "POST" && path.ends_with("/endroles"))
            .filter_map(|SentRequest { body, .. }| body.as_deref())
            .collect();
        let reference = bodies(&fixture, "propose_the_end_roles", "/endroles")?;
        assert_eq!(posted.first(), reference.first());
        assert_eq!(posted.len(), 1);
        assert!(
            requests
                .iter()
                .any(|SentRequest { path, .. }| path
                    == &format!("/multisig/request/{}", said.qb64().unwrap_or_default())),
            "the proposal was not read"
        );
        let announcements: Vec<&str> = requests
            .iter()
            .filter(|SentRequest { path, method, .. }| method == "POST" && path.ends_with("/exchanges"))
            .filter_map(|SentRequest { body, .. }| body.as_deref())
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
        let Harness { client, transport, .. } = connected(&[&member, &listing, &group])?;

        let outcome = block_on(client.multisig().accept_end_role(GROUP_NAME, ALIAS, &said));
        assert!(
            matches!(outcome, Err(ClientError::ProposalMismatch { .. })),
            "{outcome:?}"
        );
        assert!(
            sent_all(&transport)?
                .iter()
                .all(|SentRequest { method, .. }| method == "GET")
        );
        Ok(())
    }

    #[test]
    fn an_interaction_this_member_would_not_build_is_refused_unsent() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let member = member(&fixture)?;
        let group = group(&fixture)?;
        let (said, listing) = interaction_proposal(&fixture.pinned_confirmations.group)?;
        let Harness { client, transport, .. } = connected(&[&member, &listing, &group, b"{}"])?;

        let outcome = block_on(
            client
                .multisig()
                .accept_interaction(GROUP_NAME, ALIAS, &said, stamp(&fixture)?),
        );
        assert!(
            matches!(outcome, Err(ClientError::ProposalMismatch { .. })),
            "{outcome:?}"
        );
        let requests = sent_all(&transport)?;
        assert_eq!(requests.len(), 3, "the member, the proposal, and the group");
        assert!(requests.iter().all(|SentRequest { method, .. }| method == "GET"));
        Ok(())
    }

    #[test]
    fn an_approval_this_member_would_not_build_is_refused_unsent() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let member = member(&fixture)?;
        let group = group(&fixture)?;
        let (said, listing) = interaction_proposal(&fixture.pinned_confirmations.group)?;
        let Harness { client, transport, .. } = connected(&[&member, &listing, &group, b"{}"])?;

        let outcome = block_on(client.multisig().accept_delegation_approval(
            GROUP_NAME,
            ALIAS,
            &said,
            stamp(&fixture)?,
        ));
        let Err(ClientError::ProposalMismatch { built, .. }) = outcome else {
            return Err(format!("{outcome:?}").into());
        };
        let requests = sent_all(&transport)?;
        assert_eq!(requests.len(), 3, "the member, the proposal, and the group");
        assert!(requests.iter().all(|SentRequest { method, .. }| method == "GET"));

        // The same proposal naming the event this member builds goes through to the delegation address.
        let (said, listing) = interaction_proposal(&built)?;
        let Harness { client, transport, .. } = connected(&[&member, &listing, &group, b"{}", &group, &member, b"{}"])?;
        let outcome = block_on(client.multisig().accept_delegation_approval(
            GROUP_NAME,
            ALIAS,
            &said,
            stamp(&fixture)?,
        ));
        assert!(outcome.is_ok(), "{outcome:?}");
        let posted = sent_all(&transport)?
            .into_iter()
            .find(|SentRequest { method, .. }| method == "POST")
            .ok_or("nothing was posted")?;
        assert_eq!(posted.path, format!("/identifiers/{GROUP_NAME}/delegation"));
        Ok(())
    }

    #[test]
    fn a_registry_this_member_would_not_derive_is_refused_unsent() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (member, group) = (member(&fixture)?, group(&fixture)?);
        let members = serde_json::to_vec(&fixture.members)?;
        let exn = credential_exn("propose_the_registry")?;
        let proposed = exn
            .pointer("/e/vcp/i")
            .and_then(Value::as_str)
            .ok_or("no registry")?
            .to_owned();

        let (said, listing) = listed(exn.clone(), "/e/vcp/i", &fixture.pinned_confirmations.group)?;
        let Harness { client, transport, .. } = connected(&joining_answers(&member, &listing, &members, &group))?;
        let outcome =
            block_on(
                client
                    .multisig()
                    .accept_registry(GROUP_NAME, ALIAS, "registry", &said, stamp(&fixture)?),
            );
        assert!(
            matches!(outcome, Err(ClientError::ProposalMismatch { .. })),
            "{outcome:?}"
        );
        assert_nothing_written(&transport)?;

        let (said, listing) = listed(exn, "/e/vcp/i", &proposed)?;
        let Harness { client, transport, .. } = connected(&joining_answers(&member, &listing, &members, &group))?;
        let outcome =
            block_on(
                client
                    .multisig()
                    .accept_registry(GROUP_NAME, ALIAS, "registry", &said, stamp(&fixture)?),
            );
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(
            first_write(&transport)?,
            ("POST".to_owned(), format!("/identifiers/{GROUP_NAME}/registries"))
        );
        Ok(())
    }

    #[test]
    fn a_credential_this_member_would_not_derive_is_refused_unsent() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (member, group) = (member(&fixture)?, group(&fixture)?);
        let members = serde_json::to_vec(&fixture.members)?;
        let exn = credential_exn("propose_the_issuance")?;

        let (said, listing) = listed(exn.clone(), "/e/acdc/d", &fixture.pinned_confirmations.group)?;
        let Harness { client, transport, .. } = connected(&joining_answers(&member, &listing, &members, &group))?;
        let outcome = block_on(client.multisig().accept_issuance(
            GROUP_NAME,
            ALIAS,
            group_credential(&fixture)?,
            &said,
            stamp(&fixture)?,
        ));
        let Err(ClientError::ProposalMismatch { built, .. }) = outcome else {
            return Err(format!("{outcome:?}").into());
        };
        assert_nothing_written(&transport)?;

        let (said, listing) = listed(exn, "/e/acdc/d", &built)?;
        let Harness { client, transport, .. } = connected(&joining_answers(&member, &listing, &members, &group))?;
        let outcome = block_on(client.multisig().accept_issuance(
            GROUP_NAME,
            ALIAS,
            group_credential(&fixture)?,
            &said,
            stamp(&fixture)?,
        ));
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(
            first_write(&transport)?,
            ("POST".to_owned(), format!("/identifiers/{GROUP_NAME}/credentials"))
        );
        Ok(())
    }

    #[test]
    fn a_revocation_this_member_would_not_derive_is_refused_unsent() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let (member, group) = (member(&fixture)?, group(&fixture)?);
        let members = serde_json::to_vec(&fixture.members)?;
        let exn = revocation_exn()?;

        let (said, listing) = listed(exn.clone(), "/e/rev/d", &fixture.pinned_confirmations.group)?;
        let Harness { client, transport, .. } = connected(&joining_answers(&member, &listing, &members, &group))?;
        let outcome = block_on(client.multisig().accept_revocation(
            GROUP_NAME,
            ALIAS,
            group_revocation(&fixture)?,
            &said,
            stamp(&fixture)?,
        ));
        let Err(ClientError::ProposalMismatch { built, .. }) = outcome else {
            return Err(format!("{outcome:?}").into());
        };
        assert_nothing_written(&transport)?;

        let (said, listing) = listed(exn, "/e/rev/d", &built)?;
        let Harness { client, transport, .. } = connected(&joining_answers(&member, &listing, &members, &group))?;
        let revocation = group_revocation(&fixture)?;
        let credential = revocation.credential().qb64()?;
        let outcome =
            block_on(
                client
                    .multisig()
                    .accept_revocation(GROUP_NAME, ALIAS, revocation, &said, stamp(&fixture)?),
            );
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(
            first_write(&transport)?,
            (
                "DELETE".to_owned(),
                format!("/identifiers/{GROUP_NAME}/credentials/{credential}")
            )
        );
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
            let Harness { client, transport, .. } = connected(&[&member, &listing, &group])?;
            let outcome = block_on(client.multisig().accept_end_role(GROUP_NAME, ALIAS, &said));
            assert!(
                matches!(outcome, Err(ClientError::NotAnEndRoleProposal { .. })),
                "{label}: {outcome:?}"
            );
            assert!(
                sent_all(&transport)?
                    .iter()
                    .all(|SentRequest { method, .. }| method == "GET"),
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

        let Harness { client, transport, .. } = connected(&[&member, &listing])?;
        let outcome = block_on(client.multisig().accept_end_role(GROUP_NAME, ALIAS, &said));
        assert!(
            matches!(
                outcome,
                Err(ClientError::NotAnEndRoleProposal { found: "/multisig/ixn" })
            ),
            "an interaction proposal was not refused as an end role: {outcome:?}"
        );
        assert!(
            sent_all(&transport)?
                .iter()
                .all(|SentRequest { method, .. }| method == "GET"),
            "the round sent something before refusing"
        );
        Ok(())
    }
}
