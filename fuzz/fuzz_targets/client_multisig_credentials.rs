#![no_main]

//! Fuzzes a group's registry, issuance, and revocation rounds over hostile proposals.
//!
//! These three rounds decide what a group *asserts about other people*: a registry is where its
//! credentials live, an issuance is a signed statement about a subject, and a revocation withdraws
//! one. They are also where the reference stops reading its proposals altogether — both helpers
//! wait for a notification, discard the SAID, and build from their own arguments — so nothing
//! upstream ever compares what a member built with what it was asked to build.
//!
//! The target asserts the two things that make comparing possible. A **nonce** decides a registry
//! identifier and must reach a reader unchanged; a **credential's fields** decide its SAID and must
//! do the same. And it asserts the slot discipline these rounds are the exception to: an issuance
//! is named for its transaction event and discriminated by its credential, and a revocation sent
//! under the issuance label — which is what `multisigRevoke` sends — is refused by every route.
//!
//! Nothing panics, no route admits an embed it does not name, and no value that decides an
//! identifier is rewritten in transit.

use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::exchanges::{ClassifiedExchange, GROUP_LABEL, MultisigRoute};
use signify_client::multisig::{
    ANCHOR_SLOT, ISSUANCE_ROUTE, ISSUANCE_SLOT, REGISTRY_ROUTE, REGISTRY_SLOT, REVOCATION_ROUTE, REVOCATION_SLOT,
    TRANSACTION_SLOT,
};
use signify_types::api::{ExchangeEmbed, MultisigExchangeResource};

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";
const REGISTRY: &str = "EJBglnT4bORqW6oF87S050gj5i1qBQSHwTj3bLPyMpbX";
const CREDENTIAL: &str = "ECk3MhIQkFtytQZCiAKKEAA94Y9oL8OtDTINpzsI8JSg";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const ANCHOR: &str = r#"{"v":"KERI10JSON000_","t":"ixn","d":"EANC","i":"EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk","s":"1","p":"EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk","a":[]}"#;

/// The three rounds, each with the slot its embed is discriminated by.
const ROUNDS: [(&str, &str); 3] = [
    (REGISTRY_ROUTE, REGISTRY_SLOT),
    (ISSUANCE_ROUTE, ISSUANCE_SLOT),
    (REVOCATION_ROUTE, REVOCATION_SLOT),
];

/// Whether a fuzzed string can appear inside a JSON string literal unescaped.
fn plain(text: &str) -> bool {
    !text.is_empty()
        && text.len() < 128
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-' || character == '_')
}

fn embeds(slot: &str, nonce: &str, lei: &str) -> String {
    match slot {
        "vcp" => format!(
            r#""{REGISTRY_SLOT}":{{"v":"KERI10JSON000_","t":"vcp","d":"{REGISTRY}","i":"{REGISTRY}","ii":"{GROUP}","s":"0","c":[],"bt":"0","b":[],"n":"{nonce}"}},"{ANCHOR_SLOT}":{ANCHOR}"#
        ),
        "acdc" => format!(
            r#""{ISSUANCE_SLOT}":{{"v":"ACDC10JSON000_","d":"{CREDENTIAL}","i":"{GROUP}","ri":"{REGISTRY}","s":"{SCHEMA}","a":{{"i":"{PEER}","LEI":"{lei}","dt":"2023-11-14T22:13:20.123000+00:00"}}}},"{TRANSACTION_SLOT}":{{"v":"KERI10JSON000_","t":"iss","d":"EISS","i":"{CREDENTIAL}","s":"0","ri":"{REGISTRY}","dt":"2023-11-14T22:13:20.123000+00:00"}},"{ANCHOR_SLOT}":{ANCHOR}"#
        ),
        _ => format!(
            r#""{REVOCATION_SLOT}":{{"v":"KERI10JSON000_","t":"rev","d":"EREV","i":"{CREDENTIAL}","s":"1","ri":"{REGISTRY}","p":"EISS","dt":"2023-11-14T22:13:20.123000+00:00"}},"{ANCHOR_SLOT}":{ANCHOR}"#
        ),
    }
}

fn proposal(route: &str, slot: &str, nonce: &str, lei: &str) -> String {
    let exn = format!(
        r#"{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{{"{GROUP_LABEL}":"{GROUP}"}},"e":{{"d":"EEMB",{embeds}}}}}"#,
        embeds = embeds(slot, nonce, lei)
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
    let nonce = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let lei = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let document = parts.next().unwrap_or_default();

    let pick = |index: usize| {
        let choice = selection
            .get(index)
            .map_or(0, |byte| usize::from(*byte) % ROUNDS.len());
        ROUNDS.get(choice).copied().unwrap_or(ROUNDS[0])
    };
    let (route, _) = pick(0);
    let (_, slot) = pick(1);

    // -----------------------------------------------------------------------
    // The route and the embed: every pairing but the matching one is refused.
    // -----------------------------------------------------------------------
    let safe_nonce = if plain(&nonce) { nonce.clone() } else { "AHSND".to_owned() };
    let safe_lei = if plain(&lei) { lei.clone() } else { "5493001KJTIIGC8Y1R17".to_owned() };

    let matching = ROUNDS
        .iter()
        .any(|(named, expected)| *named == route && *expected == slot);
    let classified = classify(&proposal(route, slot, &safe_nonce, &safe_lei));
    if matching {
        if let Some(proposal) = classified {
            let multisig = proposal.as_multisig();
            assert!(multisig.is_some(), "a multisig route did not classify as one");
            if let Some(multisig) = multisig {
                assert_eq!(multisig.route.as_str(), route, "the route was rewritten");
                assert!(matches!(
                    multisig.route,
                    MultisigRoute::RegistryInception | MultisigRoute::Issuance | MultisigRoute::Revocation
                ));
                // A transaction proposal names only the group.
                assert_eq!(multisig.attributes.group.qb64().ok(), Some(GROUP.to_owned()));
                assert!(multisig.attributes.signing_members.is_none());
            }
        }
    } else {
        assert!(
            classified.is_none(),
            "the route {route} admitted a {slot} embed it does not name"
        );
    }

    // -----------------------------------------------------------------------
    // The values that decide an identifier reach a reader unchanged.
    // -----------------------------------------------------------------------
    if let Some(proposal) = classify(&proposal(REGISTRY_ROUTE, REGISTRY_SLOT, &safe_nonce, &safe_lei))
        && let Some(multisig) = proposal.as_multisig()
        && let ExchangeEmbed::RegistryInception(embed) = &multisig.proposed.message
    {
        assert_eq!(embed.vcp.nonce, safe_nonce, "a registry nonce was rewritten");
        assert_eq!(embed.vcp.registry, REGISTRY);
        assert_eq!(embed.vcp.issuer, GROUP);
    }

    if let Some(proposal) = classify(&proposal(ISSUANCE_ROUTE, ISSUANCE_SLOT, &safe_nonce, &safe_lei))
        && let Some(multisig) = proposal.as_multisig()
        && let ExchangeEmbed::Issuance(embed) = &multisig.proposed.message
    {
        assert_eq!(embed.acdc.digest, CREDENTIAL);
        assert_eq!(embed.acdc.schema, SCHEMA);
        if let Ok(attributes) = serde_json::to_value(&embed.acdc.attributes) {
            assert_eq!(
                attributes.get("LEI").and_then(serde_json::Value::as_str),
                Some(safe_lei.as_str()),
                "a credential attribute was rewritten"
            );
        }
    }

    // -----------------------------------------------------------------------
    // And the pairing the reference sends: a revocation under the issuance label.
    // -----------------------------------------------------------------------
    for named in [REVOCATION_ROUTE, ISSUANCE_ROUTE] {
        let misfiled = format!(
            r#"[{{"exn":{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{named}","q":{{}},"a":{{"{GROUP_LABEL}":"{GROUP}"}},"e":{{"d":"EEMB","{TRANSACTION_SLOT}":{{"v":"KERI10JSON000_","t":"rev","d":"EREV","i":"{CREDENTIAL}","s":"1","ri":"{REGISTRY}","p":"EISS","dt":"2023-11-14T22:13:20.123000+00:00"}},"{ANCHOR_SLOT}":{ANCHOR}}}}},"paths":{{}},"groupName":"multisig","memberName":"member1","sender":"{LOCAL}"}}]"#
        );
        assert!(
            classify(&misfiled).is_none(),
            "{named} accepted a revocation labelled as an issuance"
        );
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
