//! Invariants of multisig group inception.
//!
//! A group identifier is a digest over the inception event, and every member builds that event
//! independently. So the invariants here are all forms of one statement: **what a member reads is
//! what it uses, and what it uses is what it tells the others.** Each of the reference's four
//! defects is a place that fails — the addressee it substitutes, the rotation set it discards, the
//! send it does not await, and the witness threshold it reads in the wrong base.
//!
//! Three things vary: the members a proposal names, the witness threshold it commits to, and the
//! shape of the message a joining member is handed. The last is a trust boundary — a group request
//! is a proposal *another member* wrote, asking this one to sign something it did not compose — so
//! the property there is that it decodes whole and classifies, or is refused with a reason.

use std::error::Error;

use proptest::prelude::*;
use signify_client::endpoint::exchanges::{
    ClassifiedExchange, GROUP_LABEL, MultisigRoute, ROTATION_MEMBERS_LABEL, SIGNING_MEMBERS_LABEL,
};
use signify_client::error::ClientError;
use signify_client::multisig::{INCEPTION_ROUTE, INCEPTION_SLOT, delivery_list};
use signify_keri::prefix::IdentifierPrefix;
use signify_types::api::{ExchangeEmbed, KeyEvent, MultisigExchangeResource};

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const THIRD: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const FOURTH: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";

/// The four members these properties draw from.
const MEMBERS: [&str; 4] = [LOCAL, PEER, THIRD, FOURTH];

fn prefix(text: &str) -> Result<IdentifierPrefix, Box<dyn Error>> {
    Ok(IdentifierPrefix::from_qb64(text)?)
}

/// A non-empty selection of the four members, as prefixes, in the order chosen.
fn members() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec(prop::sample::select(MEMBERS.to_vec()), 1..5).prop_map(|chosen| {
        let mut unique: Vec<String> = Vec::new();
        for member in chosen {
            if !unique.iter().any(|kept| kept == member) {
                unique.push(member.to_owned());
            }
        }
        unique
    })
}

fn as_prefixes(members: &[String]) -> Result<Vec<IdentifierPrefix>, TestCaseError> {
    members
        .iter()
        .map(|member| IdentifierPrefix::from_qb64(member).map_err(|error| TestCaseError::fail(error.to_string())))
        .collect()
}

fn quoted(members: &[String]) -> String {
    members
        .iter()
        .map(|member| format!("\"{member}\""))
        .collect::<Vec<String>>()
        .join(",")
}

/// One group request listing entry proposing an inception, of the shape the agent answers with.
fn proposal(signing: &[String], rotation: &[String], witness_threshold: &str, witnesses: &[String]) -> String {
    let event = format!(
        r#"{{"v":"KERI10JSON000_","t":"icp","d":"{GROUP}","i":"{GROUP}","s":"0","kt":"2","k":["DAA"],"nt":"2","n":["EAA"],"bt":"{witness_threshold}","b":[{witnesses}],"c":[],"a":[]}}"#,
        witnesses = quoted(witnesses)
    );
    let exn = format!(
        r#"{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{INCEPTION_ROUTE}","q":{{}},"a":{{"{GROUP_LABEL}":"{GROUP}","{SIGNING_MEMBERS_LABEL}":[{signing}],"{ROTATION_MEMBERS_LABEL}":[{rotation}]}},"e":{{"d":"EEMB","{INCEPTION_SLOT}":{event}}}}}"#,
        signing = quoted(signing),
        rotation = quoted(rotation)
    );
    format!(r#"[{{"exn":{exn},"paths":{{}},"groupName":"multisig","memberName":"member1","sender":"{LOCAL}"}}]"#)
}

/// Classifies one listing document, as a joining member does before it rebuilds anything.
fn classify(document: &str) -> Result<ClassifiedExchange, Box<dyn Error>> {
    let listing: Vec<MultisigExchangeResource> = serde_json::from_str(document)?;
    let entry = listing.first().ok_or("empty listing")?;
    Ok(ClassifiedExchange::try_from(entry)?)
}

/// The `bt` field of the inception a classified proposal embeds, exactly as it arrived.
fn embedded_threshold(classified: &ClassifiedExchange) -> Result<String, TestCaseError> {
    let multisig = classified
        .as_multisig()
        .ok_or_else(|| TestCaseError::fail("not a multisig proposal"))?;
    let ExchangeEmbed::Inception(embed) = &multisig.proposed.message else {
        return Err(TestCaseError::fail("not an inception embed"));
    };
    match &embed.icp {
        KeyEvent::Inception(record) => Ok(record.witness_threshold.clone()),
        _ => Err(TestCaseError::fail("not a plain inception")),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// A proposal never reaches its own sender, and reaches every other participant once, in order.
    ///
    /// The reference filters the local member when accepting and not when proposing, so upstream an
    /// initiator delivers to itself and — through Roadmap 7.7's loop — addresses the message to
    /// itself as well. Both halves filter here.
    #[test]
    fn a_proposal_is_delivered_to_every_peer_exactly_once(
        participants in members(),
        index in 0_usize..4,
    ) {
        let prefixes = as_prefixes(&participants)?;
        let local = prefixes
            .get(index % prefixes.len())
            .ok_or_else(|| TestCaseError::fail("an empty participant list"))?
            .clone();

        let peers = delivery_list(&local, &prefixes)
            .map_err(|error| TestCaseError::fail(error.to_string()));
        if prefixes.len() == 1 {
            // A group of one has nobody to tell, which is where the reference sends to itself.
            prop_assert!(peers.is_err());
            return Ok(());
        }
        let peers = peers?;

        prop_assert!(!peers.contains(&local), "a proposal was delivered back to its sender");
        prop_assert_eq!(peers.len(), prefixes.len() - 1);
        // Order is the participants' own, which matters: the first peer is the addressee.
        let expected: Vec<IdentifierPrefix> = prefixes
            .iter()
            .filter(|participant| *participant != &local)
            .cloned()
            .collect();
        prop_assert_eq!(&peers, &expected);
        // And the addressee is a peer rather than the sender.
        prop_assert!(peers.first().is_some_and(|addressee| addressee != &local));
    }

    /// A member that is not a participant cannot propose the group at all.
    ///
    /// The reference reads `participants[0]` as the addressee and never checks, so a member there
    /// can propose a group it is not in — and then wait for a signature it will never be asked for.
    #[test]
    fn a_member_outside_the_group_is_refused(
        participants in members(),
        outsider in prop::sample::select(MEMBERS.to_vec()),
    ) {
        let prefixes = as_prefixes(&participants)?;
        let local = IdentifierPrefix::from_qb64(outsider)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let inside = prefixes.contains(&local);
        match delivery_list(&local, &prefixes) {
            Ok(peers) => {
                prop_assert!(inside, "an outsider was allowed to propose");
                prop_assert!(!peers.is_empty());
            }
            Err(error) => {
                let refused = !inside || prefixes.len() == 1;
                prop_assert!(refused, "a participant was refused: {}", error);
                prop_assert!(!error.to_string().is_empty());
            }
        }
    }

    /// The rotation set a proposal names is the rotation set a member reads back.
    ///
    /// The reference reads `rmids`, derives the group's next keys from it, and then relays `smids`
    /// in its place — so a third member joining from that message is told the wrong set. Nothing
    /// substitutes one for the other here, which this states at every pair of sets.
    #[test]
    fn the_rotation_set_is_never_the_signing_set_in_disguise(
        signing in members(),
        rotation in members(),
    ) {
        let document = proposal(&signing, &rotation, "0", &[]);
        let classified = classify(&document)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let multisig = classified.as_multisig()
            .ok_or_else(|| TestCaseError::fail("an inception proposal did not classify as one"))?;

        prop_assert_eq!(multisig.route, MultisigRoute::Inception);
        let read_signing: Vec<String> = multisig.attributes.signing_members.clone().unwrap_or_default()
            .iter().filter_map(|member| member.qb64().ok()).collect();
        let read_rotation: Vec<String> = multisig.attributes.rotation_members.clone().unwrap_or_default()
            .iter().filter_map(|member| member.qb64().ok()).collect();

        prop_assert_eq!(&read_signing, &signing);
        prop_assert_eq!(&read_rotation, &rotation);
        // Which says the two are conflated only when they were written that way.
        prop_assert_eq!(read_signing == read_rotation, signing == rotation);
    }

    /// A witness threshold survives as the hexadecimal the protocol writes it in.
    ///
    /// `toad: parseInt(icp.bt)` reads that field in base ten. Below ten the two bases agree; at ten
    /// and above they do not, and the joining member derives a different group with nothing said.
    /// Nothing re-parses the field here, so this states the divergence at every value rather than
    /// at the two the fixture drove.
    #[test]
    fn a_witness_threshold_is_the_hexadecimal_it_was_written_as(threshold in 0_u32..=4096) {
        let written = format!("{threshold:x}");
        let document = proposal(&[LOCAL.to_owned()], &[LOCAL.to_owned()], &written, &[]);
        let classified = classify(&document)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        // What arrived is what was written: nothing along the way normalises or re-parses it.
        prop_assert_eq!(embedded_threshold(&classified)?, written.clone());
        prop_assert_eq!(u32::from_str_radix(&written, 16).ok(), Some(threshold));

        // And this is what the reference's base-ten read makes of the same field.
        let base_ten = written.parse::<u32>().ok();
        if threshold < 10 {
            prop_assert_eq!(base_ten, Some(threshold), "the two bases disagree below ten");
        } else {
            prop_assert_ne!(
                base_ten,
                Some(threshold),
                "a threshold of {} read the same in both bases",
                threshold
            );
            // Either it fails loudly, as `"a"` does, or it silently means something else.
            prop_assert!(base_ten.is_none() || base_ten < Some(threshold));
        }
    }

    /// An inception proposal carrying anything but an inception is refused.
    ///
    /// A joining member rebuilds whatever it is handed, so the slot and the route agreeing is what
    /// stands between it and signing a message it did not read.
    #[test]
    fn a_proposal_that_does_not_embed_an_inception_is_refused(
        slot in prop::sample::select(vec!["rot", "ixn", "vcp", "rpy", "exn"]),
    ) {
        let event = match slot {
            "rot" => r#"{"v":"KERI10JSON000_","t":"rot","d":"EROT","i":"EGRP","s":"1","p":"EICP","kt":"2","k":["DAA"],"nt":"2","n":["EAA"],"bt":"0","br":[],"ba":[],"a":[]}"#,
            "ixn" => r#"{"v":"KERI10JSON000_","t":"ixn","d":"EIXN","i":"EGRP","s":"1","p":"EICP","a":[]}"#,
            _ => r#"{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"EMEM","rp":"EPEER","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"/multisig/icp","q":{},"a":{},"e":{}}"#,
        };
        let exn = format!(
            r#"{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{INCEPTION_ROUTE}","q":{{}},"a":{{"{GROUP_LABEL}":"{GROUP}","{SIGNING_MEMBERS_LABEL}":["{LOCAL}"],"{ROTATION_MEMBERS_LABEL}":["{LOCAL}"]}},"e":{{"d":"EEMB","{slot}":{event}}}}}"#
        );
        let document = format!(
            r#"[{{"exn":{exn},"paths":{{}},"groupName":"multisig","memberName":"member1","sender":"{LOCAL}"}}]"#
        );
        let refused = classify(&document).is_err();
        prop_assert!(refused, "an inception proposal embedding a {} was accepted", slot);
    }

    /// Arbitrary bytes never panic: a proposal either classifies or is refused with a reason.
    ///
    /// This is the trust boundary of the joining half — the message came from another member.
    #[test]
    fn arbitrary_bytes_classify_or_are_refused(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        match core::str::from_utf8(&bytes) {
            Ok(text) => match classify(text) {
                Ok(classified) => {
                    let _ = classified.as_multisig().is_some();
                }
                Err(error) => prop_assert!(!error.to_string().is_empty()),
            },
            Err(error) => prop_assert!(!error.to_string().is_empty()),
        }
    }
}

/// Regression: the group the pinned scenario derives, and the values that decide it.
#[test]
fn the_pinned_scenario_reproduces() -> Result<(), Box<dyn Error>> {
    let participants = [prefix(LOCAL)?, prefix(PEER)?];
    assert_eq!(delivery_list(&prefix(LOCAL)?, &participants)?, [prefix(PEER)?]);
    assert_eq!(delivery_list(&prefix(PEER)?, &participants)?, [prefix(LOCAL)?]);
    Ok(())
}

/// Regression: a group of one is refused rather than addressed to itself.
#[test]
fn a_group_of_one_has_nobody_to_tell() -> Result<(), Box<dyn Error>> {
    let refused = matches!(
        delivery_list(&prefix(LOCAL)?, &[prefix(LOCAL)?]),
        Err(ClientError::LonelyGroup)
    );
    assert!(refused, "a group of one was allowed to propose");
    Ok(())
}

/// Regression: the two values the fixture drove, stated as this port reads them.
#[test]
fn the_two_driven_thresholds_read_as_the_protocol_writes_them() {
    // `"a"` is ten, which `parseInt` makes `NaN` — a loud failure upstream.
    assert_eq!(u32::from_str_radix("a", 16).ok(), Some(10));
    assert!("a".parse::<u32>().is_err());
    // `"10"` is sixteen, which `parseInt` makes ten — a silent one.
    assert_eq!(u32::from_str_radix("10", 16).ok(), Some(16));
    assert_eq!("10".parse::<u32>().ok(), Some(10));
}
