#![no_main]

//! Fuzzes the group endpoint over hostile SAIDs, aliases, and agent answers.
//!
//! A group request listing is a set of proposals **other members wrote**, each asking this member
//! to sign something — an inception that fixes who controls the group, a rotation that changes it,
//! an issuance that puts a credential in force. Nothing here verifies any of them; that is the
//! keeper's job, next. So the job of this family is narrow: address the right resource, and hand
//! back exactly what arrived or nothing.
//!
//! Three inputs come from outside. A **SAID** and an **alias** are path components the reference
//! concatenates raw — its own integration helper falls back to the empty string for the first,
//! which addresses the whole collection — and the request signature covers `@path`. An **answer**
//! is a listing the reference casts to `ExnMultisig[]` without looking.
//!
//! The target asserts that a read is always three segments and a write always four, that the two
//! writes differ only in their last, that a listing decodes whole or not at all, and that anything
//! that decodes is something the exchange route classifiers either classify or refuse — never
//! something either panics on.

use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::exchanges::ClassifiedExchange;
use signify_client::endpoint::groups::{JOIN_SEGMENT, MULTISIG_SEGMENT, REQUEST_SEGMENT};
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_client::protocol::said::Said;
use signify_client::types::api::MultisigExchangeResource;
use signify_http::request::{ResourcePath, encode_path_component};

/// Every character that would give a path component a meaning it did not have.
const PATH_DELIMITERS: [char; 3] = ['/', '?', '#'];

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let said_text = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let alias = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let document = parts.next().unwrap_or_default();

    // -----------------------------------------------------------------------
    // The read address: a SAID is validated, or it is nothing.
    // -----------------------------------------------------------------------
    if let Ok(said) = said_text.parse::<Said>() {
        let encoded = said.qb64();
        assert!(encoded.is_ok(), "a parsed SAID failed to re-encode: {said_text:?}");
        let text = encoded.unwrap_or_default();
        for delimiter in PATH_DELIMITERS {
            assert!(!text.contains(delimiter), "a parsed SAID carries {delimiter:?}");
        }
        if let Ok(path) = ResourcePath::builder()
            .segment(MULTISIG_SEGMENT)
            .segment(REQUEST_SEGMENT)
            .segment(&text)
            .build()
        {
            let segments: Vec<&str> = path.path().split('/').skip(1).collect();
            assert_eq!(segments.len(), 3, "a SAID became {} segments", segments.len());
            assert_eq!(segments.first().copied(), Some(MULTISIG_SEGMENT));
            assert_eq!(segments.get(1).copied(), Some(REQUEST_SEGMENT));
            assert_eq!(segments.get(2).copied(), Some(text.as_str()));
            assert_eq!(path.query(), None, "a SAID introduced a query");
        }
    }

    // -----------------------------------------------------------------------
    // The two write addresses: four segments, differing only in the last.
    // -----------------------------------------------------------------------
    let write = |action: &str| {
        ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(&alias)
            .segment(MULTISIG_SEGMENT)
            .segment(action)
            .build()
    };
    if let (Ok(request), Ok(join)) = (write(REQUEST_SEGMENT), write(JOIN_SEGMENT)) {
        for (path, action) in [(&request, REQUEST_SEGMENT), (&join, JOIN_SEGMENT)] {
            let segments: Vec<&str> = path.path().split('/').skip(1).collect();
            assert_eq!(
                segments.len(),
                4,
                "the alias {alias:?} became {} segments",
                segments.len()
            );
            assert_eq!(segments.first().copied(), Some(IDENTIFIERS_SEGMENT));
            assert_eq!(segments.get(1).copied(), Some(encode_path_component(&alias).as_str()));
            assert_eq!(segments.get(2).copied(), Some(MULTISIG_SEGMENT));
            assert_eq!(segments.get(3).copied(), Some(action));
            assert_eq!(path.query(), None, "the alias {alias:?} introduced a query");
            // The request signature covers the path, so what is signed is what is sent.
            assert_eq!(path.path(), path.as_str());
        }
        // The same resource asked to do two things: everything but the action agrees.
        let strip = |path: &ResourcePath| path.path().rsplit_once('/').map(|(head, _)| head.to_owned());
        assert_eq!(
            strip(&request),
            strip(&join),
            "the two writes addressed different resources"
        );
        assert_ne!(request.as_str(), join.as_str());
    }

    // -----------------------------------------------------------------------
    // The answer: a set of proposals other members wrote.
    // -----------------------------------------------------------------------
    if let Ok(listing) = serde_json::from_slice::<Vec<MultisigExchangeResource>>(document) {
        for entry in &listing {
            // The wrapper's three local labels are optional and independent of the message.
            let _ = entry.group_name.as_deref();
            let _ = entry.member_name.as_deref();
            let _ = entry.sender.as_deref();
            let _ = entry.paths.len();

            // Whatever arrived, classification decides or refuses — never panics.
            if let Ok(classified) = ClassifiedExchange::try_from(entry) {
                match classified.route() {
                    Some(route) => assert_eq!(route.as_str(), entry.exn.route, "a classification changed the route"),
                    None => assert!(
                        classified.as_multisig().is_none() && classified.as_ipex().is_none(),
                        "an unnamed route claimed a shape"
                    ),
                }
            }
        }

        // A listing survives a round trip whole.
        let encoded = serde_json::to_vec(&listing);
        assert!(encoded.is_ok(), "a decoded listing failed to re-encode");
        let again = serde_json::from_slice::<Vec<MultisigExchangeResource>>(&encoded.unwrap_or_default());
        assert_eq!(
            again.map(|entries| entries.len()).ok(),
            Some(listing.len()),
            "a listing did not survive a round trip"
        );
    }
});
