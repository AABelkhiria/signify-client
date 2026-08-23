#![no_main]

//! Fuzzes ACDC credential construction over hostile attributes, edges, and rules.
//!
//! The untrusted-input path here is real rather than hypothetical: the pinned reference's own
//! multisig suite feeds a credential body received over an exchange message straight back into
//! `issue` (`issExn2.e.acdc as CredentialData`), so a peer chooses the attribute, edge, and rule
//! blocks a member commits its key to. Two of the three inputs this target drives are therefore
//! attacker-controlled in a real workflow, and the third — the identifiers — is what a caller
//! might paste in.
//!
//! The target asserts that nothing panics or exhausts the stack, that every rejection is a typed
//! [`CredentialError`] with a non-empty description, and that anything accepted is exactly what
//! the two languages agree on: no label JavaScript would reorder, every bound respected, the
//! container's field order fixed, and both identifiers verifying against the data that carries
//! them, byte for byte after a reparse.

use libfuzzer_sys::fuzz_target;
use signify_acdc::credential::{
    ATTRIBUTES_LABEL, CredentialAttributes, CredentialBuilder, EDGES_LABEL, MAX_BLOCK_DEPTH, MAX_BLOCK_FIELDS,
    MAX_LABEL_BYTES, MAX_NONCE_BYTES, NONCE_LABEL, RULES_LABEL, RegistryIdentifier, SCHEMA_LABEL,
};
use signify_keri::event::timestamp::Timestamp;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::{DEFAULT_SAID_LABEL, Said, SaidVerification};
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};

const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const HOLDER: &str = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";
const REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";

/// The complete set of labels JavaScript reorders: canonical `0..=4294967294`.
fn is_array_index(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 10
        && label.bytes().all(|byte| byte.is_ascii_digit())
        && (label.len() == 1 || !label.starts_with('0'))
        && label.parse::<u32>().is_ok_and(|value| value != u32::MAX)
}

/// Walks a block, returning its deepest nesting, its total field count, and whether any label
/// would be reordered or is oversized.
fn survey(sad: &Sad, depth: usize) -> (usize, usize, bool) {
    let mut deepest = depth;
    let mut fields = 0_usize;
    let mut suspect = false;
    for (label, value) in sad.entries() {
        fields = fields.saturating_add(1);
        if is_array_index(label) || label.len() > MAX_LABEL_BYTES {
            suspect = true;
        }
        let (child_depth, child_fields, child_suspect) = survey_value(value, depth);
        deepest = deepest.max(child_depth);
        fields = fields.saturating_add(child_fields);
        suspect |= child_suspect;
    }
    (deepest, fields, suspect)
}

fn survey_value(value: &SadValue, depth: usize) -> (usize, usize, bool) {
    match value {
        SadValue::Map(nested) => survey(nested, depth.saturating_add(1)),
        SadValue::Array(items) => {
            let mut deepest = depth.saturating_add(1);
            let mut fields = 0_usize;
            let mut suspect = false;
            for item in items {
                fields = fields.saturating_add(1);
                let (child_depth, child_fields, child_suspect) = survey_value(item, depth.saturating_add(1));
                deepest = deepest.max(child_depth);
                fields = fields.saturating_add(child_fields);
                suspect |= child_suspect;
            }
            (deepest, fields, suspect)
        }
        _ => (depth, 0, false),
    }
}

/// Builds one block from the fuzzer's bytes: a chain of maps or arrays whose depth, breadth, and
/// labels all come from the input, so the recursive validator and serializer are driven together.
fn block(bytes: &[u8]) -> Sad {
    let mut sad = Sad::new();
    let [shape, rest @ ..] = bytes else {
        return sad;
    };
    let depth = usize::from(shape & 0x3f);
    let mut labels = rest.split(|&byte| byte == 0);

    let mut value = SadValue::text(String::from_utf8_lossy(labels.next().unwrap_or_default()));
    for index in 0..depth {
        value = if shape & 0x40 == 0 {
            let mut wrapper = Sad::new();
            let label = labels
                .next()
                .map_or_else(|| format!("n{index}"), |raw| String::from_utf8_lossy(raw).into_owned());
            // A duplicate simply loses the field, which is what the caller asked for.
            let _ = wrapper.insert(label, value);
            SadValue::Map(wrapper)
        } else {
            SadValue::Array(vec![value])
        };
    }

    let label = labels
        .next()
        .map_or_else(|| "block".to_owned(), |raw| String::from_utf8_lossy(raw).into_owned());
    let _ = sad.insert(label, value);
    if shape & 0x80 != 0 {
        let _ = sad.insert(DEFAULT_SAID_LABEL, SadValue::text(""));
    }
    sad
}

fuzz_target!(|data: &[u8]| {
    let [control, sections @ ..] = data else {
        return;
    };
    let (Ok(stamp), Ok(issuer), Ok(holder), Ok(registry), Ok(schema)) = (
        STAMP.parse::<Timestamp>(),
        IdentifierPrefix::from_qb64(ISSUER),
        IdentifierPrefix::from_qb64(HOLDER),
        RegistryIdentifier::from_qb64(REGISTRY),
        Said::from_qb64(SCHEMA),
    ) else {
        return;
    };

    // The input splits into four sections on a sentinel: attributes, salt, edges, and rules.
    let mut parts = sections.split(|&byte| byte == 0xff);
    let attribute_bytes = parts.next().unwrap_or_default();
    let nonce_bytes = parts.next().unwrap_or_default();
    let edge_bytes = parts.next().unwrap_or_default();
    let rule_bytes = parts.next().unwrap_or_default();

    // The attribute block, assembled through the public methods a caller would use.
    let mut attributes = CredentialAttributes::new(stamp);
    if control & 0x01 != 0 {
        let Ok(next) = attributes.issuee(&holder) else {
            return;
        };
        attributes = next;
    }
    if control & 0x02 != 0 {
        let Ok(next) = attributes.timestamp() else {
            return;
        };
        attributes = next;
    }
    let mut accepted_labels: Vec<String> = Vec::new();
    for field in attribute_bytes.split(|&byte| byte == 0).take(8) {
        let label = String::from_utf8_lossy(field).into_owned();
        match attributes.clone().text(label.clone(), "v") {
            Ok(next) => {
                // Only a label both languages order alike is ever accepted.
                assert!(!is_array_index(&label), "an array-index label was accepted: {label:?}");
                assert!(label.len() <= MAX_LABEL_BYTES);
                assert!(!matches!(label.as_str(), "d" | "v" | "i" | "u" | "dt"));
                accepted_labels.push(label);
                attributes = next;
            }
            Err(error) => assert!(!error.to_string().is_empty()),
        }
    }

    let mut builder = CredentialBuilder::new(issuer, registry, schema, attributes);

    let nonce = String::from_utf8_lossy(nonce_bytes).into_owned();
    let carries_nonce = control & 0x04 != 0;
    if carries_nonce {
        match builder.clone().nonce(nonce.clone()) {
            Ok(next) => {
                assert!(!nonce.is_empty() && nonce.len() <= MAX_NONCE_BYTES);
                builder = next;
            }
            Err(error) => {
                assert!(!error.to_string().is_empty());
                assert!(nonce.is_empty() || nonce.len() > MAX_NONCE_BYTES);
            }
        }
    }

    let mut carries_edges = false;
    if control & 0x08 != 0 {
        let edges = block(edge_bytes);
        let (depth, fields, suspect) = survey(&edges, 1);
        match builder.clone().edges(edges) {
            Ok(next) => {
                assert!(!suspect, "a reorderable or oversized edge label was accepted");
                assert!(depth <= MAX_BLOCK_DEPTH, "an over-deep edge block was accepted");
                assert!(fields <= MAX_BLOCK_FIELDS);
                carries_edges = true;
                builder = next;
            }
            Err(error) => assert!(!error.to_string().is_empty()),
        }
    }

    let mut carries_rules = false;
    if control & 0x10 != 0 {
        let rules = block(rule_bytes);
        let (depth, fields, suspect) = survey(&rules, 1);
        match builder.clone().rules(rules) {
            Ok(next) => {
                assert!(!suspect, "a reorderable or oversized rule label was accepted");
                assert!(depth <= MAX_BLOCK_DEPTH, "an over-deep rule block was accepted");
                assert!(fields <= MAX_BLOCK_FIELDS);
                carries_rules = true;
                builder = next;
            }
            Err(error) => assert!(!error.to_string().is_empty()),
        }
    }

    let Ok(credential) = builder.build() else {
        return;
    };

    // The container's field order never varies with the input.
    let labels: Vec<&str> = credential.sad().entries().map(|(label, _)| label).collect();
    let mut expected = vec!["v", DEFAULT_SAID_LABEL];
    if carries_nonce && !nonce.is_empty() && nonce.len() <= MAX_NONCE_BYTES {
        expected.push(NONCE_LABEL);
    }
    expected.extend(["i", "ri", SCHEMA_LABEL, ATTRIBUTES_LABEL]);
    if carries_edges {
        expected.push(EDGES_LABEL);
    }
    if carries_rules {
        expected.push(RULES_LABEL);
    }
    assert_eq!(labels, expected, "the container field order changed");

    // The attribute block always opens with its identifier and always carries its timestamp.
    let attributes = credential.attributes().expect("an accepted credential has attributes");
    assert_eq!(attributes.first_label(), Some(DEFAULT_SAID_LABEL));
    assert_eq!(attributes.get_text("dt"), Some(STAMP));
    for label in &accepted_labels {
        assert!(attributes.contains(label), "an accepted label was dropped: {label:?}");
    }

    // The two properties that make the module worth having: each identifier is the digest of the
    // data carrying it, and the serialization round-trips byte for byte.
    credential
        .said()
        .verify(credential.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())
        .expect("a credential must carry its own identifier");
    credential
        .attributes_said()
        .verify(attributes, DEFAULT_SAID_LABEL, SaidVerification::strict())
        .expect("an attribute block must carry its own identifier");

    assert_eq!(credential.serialized().size(), credential.raw().len());
    let reparsed = SerializedEvent::parse(credential.raw()).expect("an accepted credential must reparse");
    assert_eq!(reparsed.sad(), credential.sad());
});
