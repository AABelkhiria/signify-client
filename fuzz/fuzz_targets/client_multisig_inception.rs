#![no_main]

//! Fuzzes multisig group inception over hostile member lists, thresholds, and proposals.
//!
//! What is at stake here is not a request shape. A group identifier is a digest over an inception
//! event that **every member builds independently**, from a message another member composed; two
//! members that disagree about one field of it derive different groups, sign different events, and
//! wait for each other forever. The reference does exactly that when a witness threshold reaches
//! ten. So the invariants are about agreement.
//!
//! Three inputs. A **member list** decides who a proposal reaches and, through its first entry, who
//! it names — the target asserts the sender is never in it, that no participant is dropped, and
//! that a member outside the group and a group of one are both refused rather than addressed. A
//! **witness threshold** is a hexadecimal field the reference re-reads in base ten — the target
//! asserts a round trip through the wire form is the identity in the base the protocol writes it
//! in, and that the two bases part company at exactly ten. A **proposal document** is a message a
//! peer wrote, asking this member to sign something it did not compose — the target asserts it
//! decodes whole and classifies, or is refused, and that the sets it names survive unswapped.
//!
//! Nothing panics, no member list loses or gains a member, and no threshold ever reads as a
//! different number than it was written as.

use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::exchanges::{ClassifiedExchange, MultisigRoute};
use signify_client::error::ClientError;
use signify_client::multisig::{INCEPTION_ROUTE, INCEPTION_SLOT, delivery_list};
use signify_keri::prefix::IdentifierPrefix;
use keria_types::api::{ExchangeEmbed, KeyEvent, MultisigExchangeResource};

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const THIRD: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const FOURTH: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";

/// The four members a fuzzed list is drawn from.
const MEMBERS: [&str; 4] = [LOCAL, PEER, THIRD, FOURTH];

/// Renders a member list as the JSON array a proposal carries.
fn quoted(members: &[&str]) -> String {
    members
        .iter()
        .map(|member| format!("\"{member}\""))
        .collect::<Vec<String>>()
        .join(",")
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let selection = parts.next().unwrap_or_default();
    let threshold_bytes = parts.next().unwrap_or_default();
    let document = parts.next().unwrap_or_default();

    // -----------------------------------------------------------------------
    // The delivery list: who a proposal names and who it reaches.
    // -----------------------------------------------------------------------
    let chosen: Vec<&str> = selection
        .iter()
        .map(|byte| MEMBERS[usize::from(*byte) % MEMBERS.len()])
        .fold(Vec::new(), |mut unique, member| {
            if !unique.contains(&member) {
                unique.push(member);
            }
            unique
        });
    let participants: Vec<IdentifierPrefix> = chosen
        .iter()
        .filter_map(|member| IdentifierPrefix::from_qb64(member).ok())
        .collect();

    for candidate in MEMBERS {
        let Ok(local) = IdentifierPrefix::from_qb64(candidate) else {
            continue;
        };
        let inside = participants.contains(&local);
        match delivery_list(&local, &participants) {
            Ok(peers) => {
                assert!(inside, "a member outside the group was allowed to propose to it");
                assert!(participants.len() > 1, "a group of one produced a delivery list");
                // The sender never receives its own proposal, which is what the reference does.
                assert!(!peers.contains(&local), "a proposal was delivered back to its sender");
                // Nobody else is dropped, and nobody is added.
                assert_eq!(peers.len(), participants.len() - 1);
                for participant in &participants {
                    assert_eq!(
                        participant == &local,
                        !peers.contains(participant),
                        "the delivery list disagrees with the participant list"
                    );
                }
                // The addressee is the first peer, and it is never the sender.
                assert!(peers.first().is_some_and(|addressee| addressee != &local));
            }
            Err(error) => {
                let refused = !inside || participants.len() <= 1;
                assert!(refused, "a participant of a real group was refused: {error}");
                assert!(matches!(
                    error,
                    ClientError::LocalMemberNotAParticipant { .. } | ClientError::LonelyGroup
                ));
            }
        }
    }

    // -----------------------------------------------------------------------
    // The witness threshold: the field the reference reads in the wrong base.
    // -----------------------------------------------------------------------
    let threshold = threshold_bytes
        .iter()
        .take(4)
        .fold(0_u32, |value, byte| value.wrapping_shl(8) | u32::from(*byte));
    let written = format!("{threshold:x}");
    // A round trip through the wire form is the identity in the base the protocol writes it in.
    assert_eq!(
        u32::from_str_radix(&written, 16).ok(),
        Some(threshold),
        "a witness threshold did not survive its own encoding"
    );
    // And the two bases part company at exactly ten: below it they agree, at or above it the
    // base-ten read either fails or means a smaller number, silently.
    let base_ten = written.parse::<u32>().ok();
    if threshold < 10 {
        assert_eq!(base_ten, Some(threshold));
    } else {
        assert_ne!(base_ten, Some(threshold), "a threshold read the same in both bases");
        assert!(base_ten.is_none() || base_ten < Some(threshold));
    }

    // -----------------------------------------------------------------------
    // A proposal a peer wrote: it classifies whole, or it is refused.
    // -----------------------------------------------------------------------
    if !chosen.is_empty() {
        let rotation: Vec<&str> = chosen.iter().rev().copied().collect();
        let event = format!(
            r#"{{"v":"KERI10JSON000_","t":"icp","d":"{GROUP}","i":"{GROUP}","s":"0","kt":"2","k":["DAA"],"nt":"2","n":["EAA"],"bt":"{written}","b":[],"c":[],"a":[]}}"#
        );
        let exn = format!(
            r#"{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{INCEPTION_ROUTE}","q":{{}},"a":{{"gid":"{GROUP}","smids":[{signing}],"rmids":[{relayed}]}},"e":{{"d":"EEMB","{INCEPTION_SLOT}":{event}}}}}"#,
            signing = quoted(&chosen),
            relayed = quoted(&rotation)
        );
        let listing =
            format!(r#"[{{"exn":{exn},"paths":{{}},"groupName":"multisig","memberName":"member1","sender":"{LOCAL}"}}]"#);

        if let Ok(decoded) = serde_json::from_str::<Vec<MultisigExchangeResource>>(&listing)
            && let Some(entry) = decoded.first()
            && let Ok(classified) = ClassifiedExchange::try_from(entry)
            && let Some(proposal) = classified.as_multisig()
        {
            assert_eq!(proposal.route, MultisigRoute::Inception);

            // The sets survive unswapped, which is what the reference loses on the way out.
            let read = |members: Option<&Vec<IdentifierPrefix>>| -> Vec<String> {
                members
                    .map(|list| list.iter().filter_map(|member| member.qb64().ok()).collect())
                    .unwrap_or_default()
            };
            let signing = read(proposal.attributes.signing_members.as_ref());
            let relayed = read(proposal.attributes.rotation_members.as_ref());
            assert_eq!(signing, chosen, "the signing set was rewritten");
            assert_eq!(relayed, rotation, "the rotation set was rewritten");
            assert_eq!(signing == relayed, chosen == rotation);

            // And the threshold reaches the embedded event as the text it was written as, so
            // nothing between the wire and the rebuild re-reads it.
            if let ExchangeEmbed::Inception(embed) = &proposal.proposed.message
                && let KeyEvent::Inception(record) = &embed.icp
            {
                assert_eq!(record.witness_threshold, written, "a threshold was rewritten in transit");
            }
        }
    }

    // -----------------------------------------------------------------------
    // And an arbitrary answer: whatever decodes is something the classifier answers about.
    // -----------------------------------------------------------------------
    if let Ok(listing) = serde_json::from_slice::<Vec<MultisigExchangeResource>>(document) {
        for entry in &listing {
            let _ = ClassifiedExchange::try_from(entry).is_ok();
        }
    }
});
