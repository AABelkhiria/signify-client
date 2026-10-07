#![no_main]

//! Fuzzes reading one step of a disclosure conversation over hostile input.
//!
//! A disclosure conversation is a chain, and everything downstream of it trusts two things: that
//! the step in hand is the step it claims to be, and that the SAID it names as its predecessor is
//! the one it actually carries. Both come off the wire.
//!
//! Upstream neither is checked. `waitAndMarkNotification` ends `?.a.d ?? ''`, so a notification
//! carrying no message yields the empty string, and `admitMultisig` builds an admit chained to it —
//! driven and recorded in this item's fixture, with no error. And every submitter takes a bare
//! string, so any step can be handed to any answer.
//!
//! The target asserts that nothing panics, that only the five named routes are steps, that a step's
//! own SAID and prior survive the round trip unchanged, that an empty prior reads as *answers
//! nothing* rather than as a SAID, and that an apply's schema and every requested attribute reach
//! the credential filter with the same values.

use keria_types::api::ExchangeResource;
use libfuzzer_sys::fuzz_target;
use signify_acdc::ipex::IpexRoute;
use signify_client::presentation::{ATTRIBUTE_FILTER_PREFIX, ReceivedStep, SCHEMA_FILTER, requested_credentials};

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const SAID: &str = "EDgvqnAQWAks1nXM1WD8kXRAan4ZkdoGAhP9_UtkGfFg";
const PRIOR: &str = "EM_FKO3crm8s4dpQ0aBl8pO2tz0B35hAWmuPBy0mns9v";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const CREDENTIAL: &str = "EGdeVjXib7lVynr1NAddi1YTO2BCU5oi_I5DT69n9zJd";

/// Whether a fuzzed string can appear inside a JSON string literal unescaped.
fn plain(text: &str) -> bool {
    !text.is_empty()
        && text.len() < 64
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-' || character == '_')
}

/// The embed block each route carries.
fn embeds(route: IpexRoute) -> String {
    match route {
        IpexRoute::Offer => format!(
            r#"{{"d":"EEMB","acdc":{{"v":"ACDC10JSON000100_","d":"{CREDENTIAL}","i":"{LOCAL}","s":"{SCHEMA}","a":{{"LEI":"5493001KJTIIGC8Y1R17"}}}}}}"#
        ),
        IpexRoute::Grant => format!(
            r#"{{"d":"EEMB","acdc":{{"v":"ACDC10JSON000100_","d":"{CREDENTIAL}","i":"{LOCAL}","s":"{SCHEMA}","a":{{"LEI":"5493001KJTIIGC8Y1R17"}}}},"iss":{{"v":"KERI10JSON000100_","t":"iss","d":"EISS","i":"{CREDENTIAL}","s":"0","ri":"EJBglnT4bORqW6oF87S050gj5i1qBQSHwTj3bLPyMpbX","dt":"2023-11-14T22:13:20.123000+00:00"}},"anc":{{"v":"KERI10JSON000100_","t":"ixn","d":"EANC","i":"{LOCAL}","s":"1","p":"{LOCAL}","a":[]}}}}"#
        ),
        IpexRoute::Apply | IpexRoute::Agree | IpexRoute::Admit => "{}".to_owned(),
    }
}

fn document(route: &str, prior: &str, attributes: &str, embeds: &str) -> String {
    format!(
        r#"{{"exn":{{"v":"KERI10JSON000100_","t":"exn","d":"{SAID}","i":"{LOCAL}","rp":"{PEER}","p":"{prior}","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{attributes},"e":{embeds}}},"pathed":{{}}}}"#
    )
}

fn read(text: &str) -> Option<ReceivedStep> {
    let resource: ExchangeResource = serde_json::from_str(text).ok()?;
    ReceivedStep::of("0AAnote", &resource).ok()
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let selection = parts.next().unwrap_or_default();
    let route = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let label = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let value = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let arbitrary = parts.next().unwrap_or_default();

    let known = IpexRoute::ALL
        .get(
            selection
                .first()
                .map_or(0, |byte| usize::from(*byte) % IpexRoute::ALL.len()),
        )
        .copied()
        .unwrap_or(IpexRoute::Apply);
    let answered = selection.get(1).is_some_and(|byte| byte % 2 == 0);
    let prior = if answered { PRIOR } else { "" };

    // -----------------------------------------------------------------------
    // Only the five named routes are steps, and a step reads its own identity back.
    // -----------------------------------------------------------------------
    let attributes = if known == IpexRoute::Apply {
        format!(r#"{{"m":"","s":"{SCHEMA}","a":{{}}}}"#)
    } else {
        r#"{"m":""}"#.to_owned()
    };
    if let Some(step) = read(&document(known.as_str(), prior, &attributes, &embeds(known))) {
        assert_eq!(step.route(), known, "a step's route was rewritten");
        assert_eq!(
            step.said().ok().and_then(|said| said.qb64().ok()),
            Some(SAID.to_owned())
        );
        assert_eq!(
            step.sender().ok().and_then(|prefix| prefix.qb64().ok()),
            Some(LOCAL.to_owned())
        );

        // An empty prior is "answers nothing", never a SAID — which is exactly the value the
        // reference's own waiter produces and passes on as though it were one.
        let named = step.answers().ok().flatten();
        if answered {
            assert_eq!(named.and_then(|said| said.qb64().ok()), Some(PRIOR.to_owned()));
        } else {
            assert!(named.is_none(), "an empty prior was read as a SAID");
        }

        // And only an apply is a request for credentials.
        assert_eq!(
            requested_credentials(&step).is_ok(),
            known == IpexRoute::Apply,
            "the wrong step answered a request for credentials"
        );
    }

    // A route the table does not name is never a step.
    if plain(&route) && !IpexRoute::ALL.iter().any(|named| named.as_str() == route) {
        let named = format!("/{route}");
        if !IpexRoute::ALL.iter().any(|known| known.as_str() == named) {
            assert!(
                read(&document(&named, "", r#"{"m":""}"#, "{}")).is_none(),
                "{named} classified as a disclosure step"
            );
        }
    }

    // -----------------------------------------------------------------------
    // What an apply asks for reaches the filter unchanged.
    // -----------------------------------------------------------------------
    if plain(&label) && plain(&value) && label != "m" && label != "s" && label != "a" {
        let block = format!(r#"{{"m":"","s":"{SCHEMA}","a":{{"{label}":"{value}"}}}}"#);
        if let Some(step) = read(&document(IpexRoute::Apply.as_str(), "", &block, "{}"))
            && let Ok(filter) = requested_credentials(&step)
            && let Ok(bytes) = filter.to_json_bytes()
            && let Ok(written) = String::from_utf8(bytes)
        {
            assert!(
                written.contains(&format!(r#""{SCHEMA_FILTER}":"{SCHEMA}""#)),
                "the schema did not reach the filter"
            );
            assert!(
                written.contains(&format!(r#""{ATTRIBUTE_FILTER_PREFIX}{label}":"{value}""#)),
                "a requested attribute did not reach the filter"
            );
        }
    }

    // -----------------------------------------------------------------------
    // And an arbitrary answer: whatever decodes is something the reader answers about.
    // -----------------------------------------------------------------------
    if let Ok(resource) = serde_json::from_slice::<ExchangeResource>(arbitrary) {
        if let Ok(step) = ReceivedStep::of("", &resource) {
            let _ = step.answers().is_ok();
            let _ = requested_credentials(&step).is_ok();
        }
    }
});
