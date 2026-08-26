#![no_main]

//! Fuzzes a multisig group's rotation and interaction rounds over hostile proposals.
//!
//! Roadmap 8.3's target was about a group *forming*: agreement on an identifier nobody had yet.
//! This one is about a group that already exists, and the thing at stake is different. A member
//! reading a proposal here is being asked to sign a change to **who controls an identifier that
//! already holds credentials** — so the question is not only whether the two members agree, but
//! whether what the message *says* it is matches what it *carries*.
//!
//! That is exactly where the reference fails: both joining members of a rotation announce it on
//! the interaction route, embedding a `rot` under `/multisig/ixn` while their peers wait on
//! `/multisig/rot`. The target asserts the pairing cannot come apart — every route admits its own
//! embed and refuses every other, at every combination.
//!
//! Two more inputs. A **witness threshold** whose JSON type the reference chooses by value: a bare
//! number when non-zero, hexadecimal text at zero. The target asserts both decode to the same
//! value, because a reader that takes only one of them silently drops half the rotations upstream
//! emits. And a **proposal document**, which is a message another member wrote: it classifies
//! whole or is refused, and what it names survives unchanged.
//!
//! Nothing panics, no route ever admits an embed it does not name, and no threshold ever means a
//! different number for having been written as a number.

use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::exchanges::{ClassifiedExchange, MultisigRoute};
use signify_client::multisig::{
    INCEPTION_ROUTE, INCEPTION_SLOT, INTERACTION_ROUTE, INTERACTION_SLOT, ROTATION_ROUTE, ROTATION_SLOT,
};
use signify_types::api::{ExchangeEmbed, KeyEvent, MultisigExchangeResource, RotationRecord};

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";
const DIGEST: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

/// The three rounds, each with the slot its route names.
const ROUNDS: [(&str, &str); 3] = [
    (INCEPTION_ROUTE, INCEPTION_SLOT),
    (ROTATION_ROUTE, ROTATION_SLOT),
    (INTERACTION_ROUTE, INTERACTION_SLOT),
];

/// One embedded event of each kind.
fn event(slot: &str, threshold: &str) -> String {
    match slot {
        "icp" => format!(
            r#"{{"v":"KERI10JSON000_","t":"icp","d":"{GROUP}","i":"{GROUP}","s":"0","kt":"2","k":["DAA"],"nt":"2","n":["EAA"],"bt":{threshold},"b":[],"c":[],"a":[]}}"#
        ),
        "rot" => format!(
            r#"{{"v":"KERI10JSON000_","t":"rot","d":"{DIGEST}","i":"{GROUP}","s":"1","p":"{GROUP}","kt":"2","k":["DAA"],"nt":"2","n":["EAA"],"bt":{threshold},"br":[],"ba":[],"a":[]}}"#
        ),
        _ => format!(
            r#"{{"v":"KERI10JSON000_","t":"ixn","d":"{DIGEST}","i":"{GROUP}","s":"1","p":"{GROUP}","a":[]}}"#
        ),
    }
}

/// One group request listing announcing `slot`'s event on `route`.
fn listing(route: &str, slot: &str, threshold: &str) -> String {
    let exn = format!(
        r#"{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{{"gid":"{GROUP}","smids":["{LOCAL}","{PEER}"],"rmids":["{LOCAL}","{PEER}"]}},"e":{{"d":"EEMB","{slot}":{event}}}}}"#,
        event = event(slot, threshold)
    );
    format!(r#"[{{"exn":{exn},"paths":{{}},"groupName":"multisig","memberName":"member1","sender":"{LOCAL}"}}]"#)
}

fn classify(document: &str) -> Option<ClassifiedExchange> {
    let decoded = serde_json::from_str::<Vec<MultisigExchangeResource>>(document).ok()?;
    let entry = decoded.first()?;
    ClassifiedExchange::try_from(entry).ok()
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let selection = parts.next().unwrap_or_default();
    let threshold_bytes = parts.next().unwrap_or_default();
    let document = parts.next().unwrap_or_default();

    let pick = |index: usize| {
        let choice = selection
            .get(index)
            .map_or(0, |byte| usize::from(*byte) % ROUNDS.len());
        ROUNDS.get(choice).copied().unwrap_or(ROUNDS[0])
    };
    let (route, _) = pick(0);
    let (_, slot) = pick(1);
    let threshold = threshold_bytes
        .iter()
        .take(4)
        .fold(0_u32, |value, byte| value.wrapping_shl(8) | u32::from(*byte));

    // -----------------------------------------------------------------------
    // The route and the embed: every pairing but the matching one is refused.
    // -----------------------------------------------------------------------
    let matching = ROUNDS
        .iter()
        .any(|(named, expected)| *named == route && *expected == slot);
    let classified = classify(&listing(route, slot, &threshold.to_string()));
    if matching {
        // A matching pair may still be refused for something else in the document, but when it
        // classifies it must classify as the route it names.
        if let Some(proposal) = classified {
            let multisig = proposal.as_multisig();
            assert!(multisig.is_some(), "a multisig route did not classify as one");
            if let Some(multisig) = multisig {
                assert_eq!(multisig.route.as_str(), route, "the route was rewritten");
                // The three rounds are distinct: no two share a slot.
                assert!(matches!(
                    multisig.route,
                    MultisigRoute::Inception | MultisigRoute::Rotation | MultisigRoute::Interaction
                ));
            }
        }
    } else {
        assert!(
            classified.is_none(),
            "the route {route} admitted a {slot} embed it does not name"
        );
    }

    // -----------------------------------------------------------------------
    // The witness threshold: two wire types, one value.
    // -----------------------------------------------------------------------
    let as_number = classify(&listing(ROTATION_ROUTE, ROTATION_SLOT, &threshold.to_string()));
    let as_text = classify(&listing(
        ROTATION_ROUTE,
        ROTATION_SLOT,
        &format!("\"{threshold}\""),
    ));
    let read = |proposal: Option<ClassifiedExchange>| -> Option<String> {
        let multisig = proposal?.as_multisig()?.clone();
        let ExchangeEmbed::Rotation(embed) = multisig.proposed.message else {
            return None;
        };
        match embed.rot {
            KeyEvent::Rotation(record) => Some(record.witness_threshold),
            _ => None,
        }
    };
    let from_number = read(as_number);
    let from_text = read(as_text);
    assert_eq!(
        from_number, from_text,
        "a threshold meant different things depending on how it was written"
    );
    assert_eq!(
        from_number,
        Some(threshold.to_string()),
        "a threshold did not survive its own encoding"
    );

    // -----------------------------------------------------------------------
    // And an arbitrary answer: whatever decodes is something the classifier answers about.
    // -----------------------------------------------------------------------
    if let Ok(listing) = serde_json::from_slice::<Vec<MultisigExchangeResource>>(document) {
        for entry in &listing {
            let _ = ClassifiedExchange::try_from(entry).is_ok();
        }
    }
    if let Ok(record) = serde_json::from_slice::<RotationRecord>(document) {
        // A rotation that decoded re-encodes and decodes again to the same threshold, whichever
        // type it arrived as.
        if let Ok(encoded) = serde_json::to_vec(&record)
            && let Ok(again) = serde_json::from_slice::<RotationRecord>(&encoded)
        {
            assert_eq!(again.witness_threshold, record.witness_threshold);
            assert_eq!(again.digest, record.digest);
        }
    }
});
