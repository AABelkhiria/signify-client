#![no_main]

//! Fuzzes the delegation endpoint over hostile aliases and seals.
//!
//! What this one call does is decide whether an identifier exists. A delegated inception is
//! pending until its delegator anchors a seal of it, and the seal is the only thing the delegate
//! is watching for — so a seal naming the wrong event approves the wrong identifier, and one that
//! never arrives leaves a delegate waiting forever. Both failures are silent.
//!
//! Two inputs. An **alias** is a path component, and an unusual one: `approve` visits *two*
//! addresses with it, reading the identifier before writing to it. Upstream encodes the first and
//! concatenates the second, so one alias gets two treatments inside a single method. The target
//! asserts both stay one segment and that the two paths agree about it.
//!
//! A **seal** is the payload. The target asserts it always writes exactly three fields, in the
//! reference's order, holding the two values it was built from and a sequence number that is not
//! one of them — because the reference hand-assembles those three from separately-obtained values
//! and its own unit test omits the block entirely, sending `"a": [null]`.
//!
//! Nothing panics, no alias escapes its segment, and no seal is ever written empty or partial.

use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::delegations::{
    DELEGATION_SEGMENT, InceptionSeal, SEAL_DIGEST_LABEL, SEAL_IDENTIFIER_LABEL, SEAL_SEQUENCE_LABEL,
};
use signify_client::endpoint::identifiers::{EVENTS_SEGMENT, IDENTIFIERS_SEGMENT};
use signify_http::request::{ResourcePath, encode_path_component};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;

/// Every character that would give a path component a meaning it did not have.
const PATH_DELIMITERS: [char; 3] = ['/', '?', '#'];

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let alias = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let delegate = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let digest = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();

    // -----------------------------------------------------------------------
    // The two addresses one approval visits.
    // -----------------------------------------------------------------------
    let read = ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(&alias)
        .build();
    let write = ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(&alias)
        .segment(DELEGATION_SEGMENT)
        .build();

    if let (Ok(read), Ok(write)) = (read, write) {
        let segments: Vec<&str> = write.path().split('/').skip(1).collect();
        assert_eq!(segments.len(), 3, "the alias {alias:?} became {} segments", segments.len());
        assert_eq!(segments.first().copied(), Some(IDENTIFIERS_SEGMENT));
        assert_eq!(segments.last().copied(), Some(DELEGATION_SEGMENT));
        let encoded = encode_path_component(&alias);
        assert_eq!(segments.get(1).copied(), Some(encoded.as_str()));
        assert_eq!(write.query(), None, "the alias {alias:?} introduced a query");
        // Roadmap 3.10 signs the path, so what is signed is exactly what is sent.
        assert_eq!(write.path(), write.as_str());

        // The read and the write agree about the alias, which upstream they do not.
        assert!(
            write.as_str().starts_with(read.as_str()),
            "the read and the write disagree about {alias:?}"
        );
        assert_eq!(write.as_str(), format!("{}/{DELEGATION_SEGMENT}", read.as_str()));

        // And an approval differs from an interaction in one segment and nothing else.
        if let Ok(interaction) = ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(&alias)
            .segment(EVENTS_SEGMENT)
            .build()
        {
            assert_eq!(
                write.as_str().trim_end_matches(DELEGATION_SEGMENT),
                interaction.as_str().trim_end_matches(EVENTS_SEGMENT),
                "the two addresses differ by more than their action"
            );
        }
    }

    // -----------------------------------------------------------------------
    // The seal: three fields, in order, holding what it was built from.
    // -----------------------------------------------------------------------
    let built = (
        IdentifierPrefix::from_qb64(&delegate),
        digest.parse::<Said>(),
    );
    if let (Ok(prefix), Ok(said)) = built {
        let seal = InceptionSeal::new(prefix, said);
        let Ok(written) = seal.to_sad() else {
            return;
        };

        // The two values survive, and neither is transcribed from the other.
        let Ok(delegate_text) = seal.delegate().qb64() else {
            return;
        };
        let Ok(digest_text) = seal.digest().qb64() else {
            return;
        };
        assert_eq!(written.get_text(SEAL_IDENTIFIER_LABEL), Some(delegate_text.as_str()));
        assert_eq!(written.get_text(SEAL_DIGEST_LABEL), Some(digest_text.as_str()));
        // The sequence number is an inception's and is never a caller's value.
        assert_eq!(written.get_text(SEAL_SEQUENCE_LABEL), Some("0"));

        // Neither qualified value can carry a delimiter, so a seal never reshapes a path it is
        // quoted into — which is what makes the encoding above sufficient.
        for delimiter in PATH_DELIMITERS {
            assert!(!delegate_text.contains(delimiter), "a parsed prefix carries {delimiter:?}");
            assert!(!digest_text.contains(delimiter), "a parsed digest carries {delimiter:?}");
        }

        // Three fields and no more, written in the reference's own order.
        if let Ok(bytes) = written.to_json_bytes()
            && let Ok(text) = String::from_utf8(bytes)
        {
            assert_eq!(
                text,
                format!(r#"{{"i":"{delegate_text}","s":"0","d":"{digest_text}"}}"#),
                "a seal was written in an order the reference does not use"
            );
            // Never empty, never a bare null — which is the body the pinned test publishes.
            assert!(!text.contains("null"), "a seal was written holding a null");
        }

        for absent in ["a", "v", "t", "n", "bt", "kt"] {
            assert!(written.get_text(absent).is_none(), "a seal carries an unexpected {absent}");
        }
    }
});
