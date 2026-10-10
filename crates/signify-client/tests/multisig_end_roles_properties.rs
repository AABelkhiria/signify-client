//! Invariants of a group's agent end-role round.
//!
//! Every member's agent is read in order or the round is refused whole, and what a proposed reply
//! authorizes — role, endpoint, stamp, SAID — survives the round trip exactly.

use keri_protocol::event::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keria_types::api::{GroupMember, ReplyRecord, Role};
use proptest::prelude::*;
use serde_json::Value;
use signify_client::error::ClientError;
use signify_client::multisig::{member_agents, proposed_end_role};
use signify_keri::identifier::end_role_reply;

/// Qualified self-addressing prefixes to draw members and agents from.
const PREFIXES: [&str; 6] = [
    "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
    "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p",
    "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1",
    "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
    "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk",
    "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
];
const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";

fn fail(error: impl std::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

fn prefix(text: &str) -> Result<IdentifierPrefix, TestCaseError> {
    IdentifierPrefix::from_qb64(text).map_err(fail)
}

/// One of the pinned prefixes, chosen by index.
fn pinned(index: usize) -> Result<&'static str, TestCaseError> {
    PREFIXES
        .get(index % PREFIXES.len())
        .copied()
        .ok_or_else(|| TestCaseError::fail("the prefix table is empty"))
}

/// A members listing: each entry a member and, when `Some`, the agent it authorizes.
fn listing(members: &[(usize, Option<usize>)]) -> Result<GroupMember, TestCaseError> {
    let mut records: Vec<Value> = Vec::with_capacity(members.len());
    for (member, agent) in members {
        let ends = match agent {
            Some(agent) => {
                serde_json::json!({ "agent": { pinned(*agent)?: { "http": "http://127.0.0.1:3902/" } } })
            }
            None => serde_json::json!({}),
        };
        records.push(serde_json::json!({ "aid": pinned(*member)?, "ends": ends }));
    }
    serde_json::from_value(serde_json::json!({ "signing": records, "rotation": [] })).map_err(fail)
}

fn stamp(seconds: u32, micros: u32) -> String {
    format!(
        "2023-11-14T22:{:02}:{:02}.{:06}+00:00",
        seconds / 60 % 60,
        seconds % 60,
        micros % 1_000_000
    )
}

/// A reply built by this port's own builder, read back as the record a proposal carries.
fn reply_record(role: &Role, endpoint: &str, stamp: &str) -> Result<(ReplyRecord, String), TestCaseError> {
    let reply = end_role_reply(
        &prefix(GROUP)?,
        role,
        Some(&prefix(endpoint)?),
        stamp.parse::<Timestamp>().map_err(fail)?,
    )
    .map_err(fail)?;
    let record: ReplyRecord = serde_json::from_slice(reply.raw()).map_err(fail)?;
    Ok((record, reply.said().qb64().map_err(fail)?))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn every_members_agent_is_read_in_the_listings_order(
        members in prop::collection::vec((0_usize..6, 0_usize..6), 0..8),
    ) {
        let entries: Vec<(usize, Option<usize>)> = members.iter().map(|(m, a)| (*m, Some(*a))).collect();
        let agents = member_agents(&listing(&entries)?).map_err(fail)?;
        prop_assert_eq!(agents.len(), entries.len());
        for (agent, (member, endpoint)) in agents.iter().zip(&members) {
            prop_assert_eq!(agent.member.qb64().map_err(fail)?, pinned(*member)?);
            prop_assert_eq!(agent.agent.qb64().map_err(fail)?, pinned(*endpoint)?);
        }
    }

    #[test]
    fn one_member_without_an_agent_refuses_the_whole_listing(
        members in prop::collection::vec((0_usize..6, 0_usize..6), 1..8),
        missing in 0_usize..8,
    ) {
        let position = missing % members.len();
        let entries: Vec<(usize, Option<usize>)> = members
            .iter()
            .enumerate()
            .map(|(index, (m, a))| (*m, (index != position).then_some(*a)))
            .collect();
        let outcome = member_agents(&listing(&entries)?);
        let missing_member = members.get(position).ok_or_else(|| TestCaseError::fail("no member at that position"))?.0;
        let expected = pinned(missing_member)?;
        prop_assert!(
            matches!(&outcome, Err(ClientError::MemberHasNoAgent { member }) if member == expected),
            "{:?}",
            outcome
        );
    }

    #[test]
    fn what_a_proposed_reply_authorizes_survives_the_round_trip(
        role in prop_oneof![
            Just(Role::Agent),
            Just(Role::Mailbox),
            Just(Role::Witness),
            "[a-z]{1,12}".prop_map(|role| Role::from(role.as_str())),
        ],
        endpoint in 0_usize..6,
        seconds in 0_u32..3600,
        micros in 0_u32..1_000_000,
    ) {
        let stamp = stamp(seconds, micros);
        let (record, said) = reply_record(&role, pinned(endpoint)?, &stamp)?;
        let proposed = proposed_end_role(&prefix(GROUP)?, &record).map_err(fail)?;
        prop_assert_eq!(proposed.role.as_str(), role.as_str());
        prop_assert_eq!(proposed.endpoint.qb64().map_err(fail)?, pinned(endpoint)?);
        prop_assert_eq!(proposed.stamp.to_string(), stamp);
        prop_assert_eq!(&proposed.said.qb64().map_err(fail)?, &said);

        // And rebuilding from what was read reproduces the SAID the proposal carried.
        let rebuilt = end_role_reply(&prefix(GROUP)?, &proposed.role, Some(&proposed.endpoint), proposed.stamp)
            .map_err(fail)?;
        prop_assert_eq!(rebuilt.said().qb64().map_err(fail)?, said);
    }

    #[test]
    fn a_reply_for_any_other_controller_is_refused(other in 0_usize..6, endpoint in 0_usize..6) {
        prop_assume!(pinned(other)? != GROUP);
        let (record, _) = reply_record(&Role::Agent, pinned(endpoint)?, "2023-11-14T22:13:20.123000+00:00")?;
        let outcome = proposed_end_role(&prefix(pinned(other)?)?, &record);
        prop_assert!(matches!(outcome, Err(ClientError::NotAnEndRoleProposal { .. })), "{:?}", outcome);
    }

    #[test]
    fn a_reply_missing_a_label_is_refused_not_defaulted(
        label in prop_oneof![Just("cid"), Just("role"), Just("eid")],
        endpoint in 0_usize..6,
    ) {
        let (mut record, _) = reply_record(&Role::Agent, pinned(endpoint)?, "2023-11-14T22:13:20.123000+00:00")?;
        if let Some(attributes) = record.attributes.as_object_mut() {
            attributes.remove(label);
        }
        let outcome = proposed_end_role(&prefix(GROUP)?, &record);
        prop_assert!(matches!(outcome, Err(ClientError::NotAnEndRoleProposal { .. })), "{}: {:?}", label, outcome);
    }

    #[test]
    fn a_reply_naming_an_empty_role_is_refused(endpoint in 0_usize..6) {
        let (mut record, _) = reply_record(&Role::Agent, pinned(endpoint)?, "2023-11-14T22:13:20.123000+00:00")?;
        if let Some(attributes) = record.attributes.as_object_mut() {
            attributes.insert("role".to_owned(), Value::String(String::new()));
        }
        let outcome = proposed_end_role(&prefix(GROUP)?, &record);
        prop_assert!(matches!(outcome, Err(ClientError::NotAnEndRoleProposal { .. })), "{:?}", outcome);
    }

    /// Near misses of a KERI timestamp: the right instant written another way, or not an instant.
    #[test]
    fn a_reply_whose_stamp_is_not_a_keri_timestamp_is_refused(
        stamp in prop_oneof![
            Just("2023-11-14T22:13:20.123000Z".to_owned()),
            Just("2023-11-14T22:13:20+00:00".to_owned()),
            Just("2023-11-14T22:13:20.123+00:00".to_owned()),
            Just("2023-11-14 22:13:20.123000+00:00".to_owned()),
            Just(String::new()),
            "[0-9T:.+-]{0,40}",
            "[ -~]{0,40}",
        ],
        endpoint in 0_usize..6,
    ) {
        prop_assume!(stamp.parse::<Timestamp>().is_err());
        let (mut record, _) = reply_record(&Role::Agent, pinned(endpoint)?, "2023-11-14T22:13:20.123000+00:00")?;
        record.stamp = stamp;
        let outcome = proposed_end_role(&prefix(GROUP)?, &record);
        prop_assert!(matches!(outcome, Err(ClientError::Timestamp { .. })), "{:?}", outcome);
    }

    /// Near misses of a qualified prefix in the controller or the endpoint: a pinned prefix
    /// truncated, extended, or with its code changed, or text that never was one.
    #[test]
    fn a_reply_naming_an_unqualified_prefix_is_refused(
        label in prop_oneof![Just("cid"), Just("eid")],
        damage in prop_oneof![
            Just("truncate"),
            Just("extend"),
            Just("recode"),
            Just("empty"),
            Just("text"),
        ],
        endpoint in 0_usize..6,
        text in "[A-Za-z0-9_-]{0,48}",
    ) {
        let (mut record, _) = reply_record(&Role::Agent, pinned(endpoint)?, "2023-11-14T22:13:20.123000+00:00")?;
        let sound = if label == "cid" { GROUP } else { pinned(endpoint)? };
        let broken = match damage {
            "truncate" => sound.get(..sound.len().saturating_sub(1)).unwrap_or_default().to_owned(),
            "extend" => format!("{sound}A"),
            "recode" => format!("#{}", sound.get(1..).unwrap_or_default()),
            "empty" => String::new(),
            _ => text,
        };
        prop_assume!(IdentifierPrefix::from_qb64(&broken).is_err());
        if let Some(attributes) = record.attributes.as_object_mut() {
            attributes.insert(label.to_owned(), Value::String(broken));
        }
        let outcome = proposed_end_role(&prefix(GROUP)?, &record);
        prop_assert!(matches!(outcome, Err(ClientError::Identifier { .. })), "{}: {:?}", label, outcome);
    }

    #[test]
    fn a_reply_whose_digest_is_not_a_said_is_refused(
        digest in prop_oneof![
            Just("EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5T".to_owned()),
            Just(String::new()),
            "[A-Za-z0-9_-]{0,48}",
        ],
        endpoint in 0_usize..6,
    ) {
        let (mut record, _) = reply_record(&Role::Agent, pinned(endpoint)?, "2023-11-14T22:13:20.123000+00:00")?;
        prop_assume!(keri_protocol::said::Said::from_qb64(&digest).is_err());
        record.digest = digest;
        let outcome = proposed_end_role(&prefix(GROUP)?, &record);
        prop_assert!(matches!(outcome, Err(ClientError::Said { .. })), "{:?}", outcome);
    }

    #[test]
    fn a_listing_naming_an_unqualified_member_or_agent_is_refused(
        members in prop::collection::vec((0_usize..6, 0_usize..6), 1..6),
        position in 0_usize..6,
        which in prop_oneof![Just("aid"), Just("agent")],
        text in "[A-Za-z0-9_-]{0,48}",
    ) {
        prop_assume!(IdentifierPrefix::from_qb64(&text).is_err());
        let entries: Vec<(usize, Option<usize>)> = members.iter().map(|(m, a)| (*m, Some(*a))).collect();
        let mut listing = serde_json::to_value(listing(&entries)?).map_err(fail)?;
        let position = position % members.len();
        let record = listing
            .pointer_mut(&format!("/signing/{position}"))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| TestCaseError::fail("no record at that position"))?;
        if which == "aid" {
            record.insert("aid".to_owned(), Value::String(text));
        } else {
            record.insert(
                "ends".to_owned(),
                serde_json::json!({ "agent": { text: { "http": "http://127.0.0.1:3902/" } } }),
            );
        }
        let listing: GroupMember = serde_json::from_value(listing).map_err(fail)?;
        let outcome = member_agents(&listing);
        prop_assert!(matches!(outcome, Err(ClientError::Identifier { .. })), "{}: {:?}", which, outcome);
    }

    /// Whatever bytes a reply record is read from, it is read or refused, never abandoned.
    #[test]
    fn arbitrary_bytes_are_read_or_refused(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        match serde_json::from_slice::<ReplyRecord>(&bytes) {
            Ok(record) => match proposed_end_role(&prefix(GROUP)?, &record) {
                Ok(proposed) => prop_assert_eq!(
                    Some(proposed.role.as_str()),
                    record.attributes.get("role").and_then(Value::as_str)
                ),
                Err(error) => prop_assert!(!error.to_string().is_empty()),
            },
            Err(error) => prop_assert!(!error.to_string().is_empty()),
        }
    }
}
