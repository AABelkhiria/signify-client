#![no_main]

//! Fuzzes a group's delegation approval over hostile seal lists.
//!
//! This round is the one place in the port where **a list is the payload**, and each element of it
//! is an identifier waiting to exist: a delegated inception is pending until its delegator anchors
//! a seal of it, so dropping a seal means an identifier that never comes into being and a group
//! that never converges. The reference drops all but the first — it reads `ixn.a[0]` where its own
//! plain interaction round reads `ixn.a` whole — and its one check fires after the approval is
//! already posted, comparing the first seal of what it built against the whole anchor it was given.
//!
//! So the target asserts the list survives. Every seal a proposal names is read back, in order, at
//! any length; a proposal naming a different list is a different event, which is what makes the
//! joining half's digest comparison a check rather than a formality; and a seal names one
//! identifier three ways that cannot disagree.
//!
//! Nothing panics, no seal is dropped, and no seal list is ever read as a shorter one.

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use signify_client::endpoint::delegations::InceptionSeal;
use signify_client::endpoint::exchanges::{ClassifiedExchange, MultisigRoute};
use signify_client::multisig::{INTERACTION_ROUTE, INTERACTION_SLOT};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_types::api::{ExchangeEmbed, KeyEvent, MultisigExchangeResource};

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";

/// The delegatee prefixes a fuzzed seal list is drawn from.
const DELEGATEES: [&str; 4] = [
    "EDNA2EUYd0HbW_4NU1kMv01LK2zqAWK6o7VkIQsK_LyR",
    "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1",
    PEER,
];

/// One delegated inception's seal, as this port writes it.
fn seal(delegatee: &str) -> Option<String> {
    let built = InceptionSeal::new(
        IdentifierPrefix::from_qb64(delegatee).ok()?,
        delegatee.parse::<Said>().ok()?,
    );
    String::from_utf8(built.to_sad().ok()?.to_json_bytes().ok()?).ok()
}

/// One delegation-approval proposal anchoring `seals`.
fn proposal(seals: &[String], digest: &str) -> String {
    let event = format!(
        r#"{{"v":"KERI10JSON000_","t":"ixn","d":"{digest}","i":"{GROUP}","s":"1","p":"{GROUP}","a":[{seals}]}}"#,
        seals = seals.join(",")
    );
    let exn = format!(
        r#"{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{INTERACTION_ROUTE}","q":{{}},"a":{{"gid":"{GROUP}","smids":["{LOCAL}","{PEER}"],"rmids":["{LOCAL}","{PEER}"]}},"e":{{"d":"EEMB","{INTERACTION_SLOT}":{event}}}}}"#
    );
    format!(r#"[{{"exn":{exn},"paths":{{}},"groupName":"delegators","memberName":"delegator1","sender":"{LOCAL}"}}]"#)
}

/// The seals an embedded interaction anchors, as a joining member reads them.
fn anchored(document: &str) -> Option<(Vec<Value>, String)> {
    let decoded = serde_json::from_str::<Vec<MultisigExchangeResource>>(document).ok()?;
    let entry = decoded.first()?;
    let classified = ClassifiedExchange::try_from(entry).ok()?;
    let multisig = classified.as_multisig()?;
    assert_eq!(multisig.route, MultisigRoute::Interaction, "the route was rewritten");
    let ExchangeEmbed::Interaction(embed) = &multisig.proposed.message else {
        return None;
    };
    match &embed.ixn {
        KeyEvent::Interaction(record) => {
            let seals = match &record.anchors {
                Value::Array(seals) => seals.clone(),
                single => vec![single.clone()],
            };
            Some((seals, record.digest.clone()))
        }
        _ => None,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let selection = parts.next().unwrap_or_default();
    let document = parts.next().unwrap_or_default();

    // -----------------------------------------------------------------------
    // The seal list: every seal survives, in order, at any length.
    // -----------------------------------------------------------------------
    let chosen: Vec<&str> = selection
        .iter()
        .take(64)
        .filter_map(|byte| DELEGATEES.get(usize::from(*byte) % DELEGATEES.len()).copied())
        .collect();
    let seals: Vec<String> = chosen.iter().filter_map(|delegatee| seal(delegatee)).collect();
    assert_eq!(seals.len(), chosen.len(), "a seal could not be written");

    if let Some((read, _)) = anchored(&proposal(&seals, "EIXNDIGEST")) {
        assert_eq!(read.len(), chosen.len(), "a seal was dropped");
        for (position, delegatee) in chosen.iter().enumerate() {
            let found = read.get(position);
            assert_eq!(
                found.and_then(|seal| seal.get("i")).and_then(Value::as_str),
                Some(*delegatee),
                "seal {position} names the wrong identifier"
            );
            // A delegated inception is its own digest, and the sequence number is not a caller's.
            assert_eq!(
                found.and_then(|seal| seal.get("d")).and_then(Value::as_str),
                Some(*delegatee)
            );
            assert_eq!(
                found.and_then(|seal| seal.get("s")).and_then(Value::as_str),
                Some("0")
            );
        }
        // Reading only the first would be a shorter list whenever there is more than one.
        assert_eq!(read.len() == 1, chosen.len() == 1);
    }

    // -----------------------------------------------------------------------
    // A shorter list is a different event, which is what the joining half checks.
    // -----------------------------------------------------------------------
    if chosen.len() > 1 {
        let truncated: Vec<String> = seals.iter().take(1).cloned().collect();
        let whole = anchored(&proposal(&seals, "EWHOLE"));
        let first = anchored(&proposal(&truncated, "EFIRST"));
        if let (Some((whole_seals, whole_digest)), Some((first_seals, first_digest))) = (whole, first) {
            assert_ne!(whole_seals.len(), first_seals.len());
            assert_ne!(
                whole_digest, first_digest,
                "two different seal lists carried the same digest"
            );
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
