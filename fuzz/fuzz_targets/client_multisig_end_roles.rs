#![no_main]

//! Fuzzes a group's agent end-role round over hostile listings and proposals.
//!
//! Both reads take input from other parties: the members listing names the agents a proposing
//! member authorizes for the group, and a proposal's embedded reply names the role, endpoint, and
//! stamp a joining member signs. The reference reads neither defensively — it throws part way
//! through its loop on a member without an agent, and its joining half never reads the proposal.
//!
//! The target asserts that nothing panics; that a listing is read whole or refused whole, and in
//! its own order; that a proposed end role, when read, reports exactly the role, endpoint, and
//! stamp its reply carries, for the group it was read against; and that what was read rebuilds
//! into a reply that reads back the same — the step a joining member takes before it signs.

use keria_types::api::{GroupMember, ReplyRecord};
use libfuzzer_sys::fuzz_target;
use signify_client::multisig::{member_agents, proposed_end_role};
use signify_keri::identifier::end_role_reply;
use keri_protocol::prefix::IdentifierPrefix;

const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";

fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(2, |&byte| byte == 0xff);
    let listing = parts.next().unwrap_or_default();
    let reply = parts.next().unwrap_or_default();

    // -----------------------------------------------------------------------
    // A listing: whole or refused, in order.
    // -----------------------------------------------------------------------
    if let Ok(decoded) = serde_json::from_slice::<GroupMember>(listing)
        && let Ok(agents) = member_agents(&decoded)
    {
        assert_eq!(agents.len(), decoded.signing.len(), "a member was dropped or added");
        for (agent, record) in agents.iter().zip(&decoded.signing) {
            assert_eq!(
                agent.member.qb64().ok().as_deref(),
                Some(record.aid.as_str()),
                "a member was reordered"
            );
            let named = record.ends.agent.as_ref().is_some_and(|agents| {
                agents
                    .keys()
                    .any(|key| agent.agent.qb64().ok().as_deref() == Some(key.as_str()))
            });
            assert!(named, "an agent the member does not authorize was reported");
        }
    }

    // -----------------------------------------------------------------------
    // A proposed reply: exactly what it carries, for this group only.
    // -----------------------------------------------------------------------
    let Ok(group) = IdentifierPrefix::from_qb64(GROUP) else {
        return;
    };
    if let Ok(record) = serde_json::from_slice::<ReplyRecord>(reply)
        && let Ok(proposed) = proposed_end_role(&group, &record)
    {
        let attribute = |label: &str| record.attributes.get(label).and_then(serde_json::Value::as_str);
        assert_eq!(record.route, "/end/role/add", "a reply on another route was read");
        assert_eq!(attribute("cid"), Some(GROUP), "a reply for another controller was read");
        assert_eq!(
            Some(proposed.role.as_str()),
            attribute("role"),
            "the role was rewritten"
        );
        assert_eq!(
            proposed.endpoint.qb64().ok().as_deref(),
            attribute("eid"),
            "the endpoint was rewritten"
        );
        assert_eq!(proposed.stamp.to_string(), record.stamp, "the stamp was rewritten");
        assert_eq!(proposed.said.qb64().ok(), Some(record.digest), "the SAID was rewritten");

        // -------------------------------------------------------------------
        // Rebuilt from what was read, as a joining member does before signing: the role — any
        // text the reply carried — the endpoint, and the stamp pass through the reply builder,
        // and the reply that comes out reads back as the same end role, now with its own SAID.
        // The digest the hostile reply carried need not match; that mismatch is the accept
        // path's refusal, not a failure here.
        // -------------------------------------------------------------------
        let rebuilt = end_role_reply(&group, &proposed.role, Some(&proposed.endpoint), proposed.stamp.clone());
        let again = end_role_reply(&group, &proposed.role, Some(&proposed.endpoint), proposed.stamp.clone());
        assert_eq!(
            rebuilt.as_ref().map(|reply| reply.raw().to_vec()).ok(),
            again.as_ref().map(|reply| reply.raw().to_vec()).ok(),
            "rebuilding is not deterministic"
        );
        if let Ok(rebuilt) = rebuilt {
            let reread = serde_json::from_slice::<ReplyRecord>(rebuilt.raw())
                .ok()
                .and_then(|record| proposed_end_role(&group, &record).ok());
            assert!(
                reread.is_some(),
                "a reply this port built does not read back as an end role"
            );
            if let Some(reread) = reread {
                assert_eq!(reread.role, proposed.role, "the role did not survive the rebuild");
                assert_eq!(
                    reread.endpoint, proposed.endpoint,
                    "the endpoint did not survive the rebuild"
                );
                assert_eq!(reread.stamp, proposed.stamp, "the stamp did not survive the rebuild");
                assert_eq!(reread.said, rebuilt.said(), "the rebuilt reply's SAID is not its own");
            }
        }
    }
});
