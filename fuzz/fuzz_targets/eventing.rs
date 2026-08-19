#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_crypto::digest::Digest;
use signify_crypto::verifier::VerificationKey;
use signify_keri::event::inception::InceptionBuilder;
use signify_keri::event::interaction::InteractionBuilder;
use signify_keri::event::rotation::{RotationBuilder, RotationKind};
use signify_keri::event::witness::{AmpleMode, ample};
use signify_keri::event::{ConfigurationTrait, KeyEvent, ThresholdEncoding};
use signify_keri::prefix::{IdentifierPrefix, PrefixDerivation, PrefixVerification};
use signify_keri::said::{DEFAULT_SAID_LABEL, Said, SaidVerification};
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};
use signify_keri::threshold::SigningThreshold;

const KEYS: [&str; 4] = [
    "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH",
    "DB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ",
    "DB3MBHRA6bpPwxY-QpywXUwNR-7WCEO5PmUZV3xYBkk2",
    "DIUghlVOUiV8eFLs5cP-w6hWMJosH6TLaX9BqOSI68WX",
];
const NON_TRANSFERABLE: &str = "BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH";
const WITNESSES: [&str; 4] = [
    "BB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ",
    "BB3MBHRA6bpPwxY-QpywXUwNR-7WCEO5PmUZV3xYBkk2",
    "BIUghlVOUiV8eFLs5cP-w6hWMJosH6TLaX9BqOSI68WX",
    "BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH",
];
const DIGESTS: [&str; 3] = [
    "EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W",
    "EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj",
    "EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg",
];

/// Reads one byte from the fuzz input, cycling when it runs out.
fn byte(data: &[u8], index: usize) -> u8 {
    if data.is_empty() {
        0
    } else {
        data.get(index % data.len()).copied().unwrap_or(0)
    }
}

/// Every event a builder accepts must satisfy the invariants a peer relies on.
fn check(event: &KeyEvent) {
    // The declared size, the byte count, and the reparsed content all agree.
    assert_eq!(event.serialized().size(), event.raw().len(), "size disagrees with bytes");
    match SerializedEvent::parse(event.raw()) {
        Ok(reparsed) => assert_eq!(reparsed.sad(), event.sad(), "an event did not survive reparsing"),
        Err(error) => panic!("a built event failed to parse: {error}"),
    }

    // The reported identifier and SAID are the ones the event actually carries.
    if let (Ok(identifier), Ok(said)) = (event.identifier().qb64(), event.said().qb64()) {
        assert_eq!(event.sad().get_text("i"), Some(identifier.as_str()));
        assert_eq!(event.sad().get_text("d"), Some(said.as_str()));
    }
    assert_eq!(event.sad().get_text("t"), Some(event.kind().as_str()));

    // A self-addressing inception commits to itself through the prefix derivation, which dummies
    // both identifier fields; every other event carries an ordinary SAID.
    if event.identifier().is_digestive() && event.kind().as_str() == "icp" {
        assert!(
            event.identifier().verify(event.sad(), PrefixVerification::Strict).is_ok(),
            "a self-addressing inception did not verify against itself",
        );
    } else {
        assert!(
            event
                .said()
                .verify(event.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())
                .is_ok(),
            "an event's SAID did not verify against itself",
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let key_count = usize::from(byte(data, 0) % 5);
    let digest_count = usize::from(byte(data, 1) % 4);
    let witness_count = usize::from(byte(data, 2) % 5);
    let signing = u128::from(byte(data, 3) % 6);
    let next = u128::from(byte(data, 4) % 6);
    let witness_threshold = u32::from(byte(data, 5) % 6);
    let flags = byte(data, 6);
    let sequence_number = u128::from(byte(data, 7));

    let keys: Vec<VerificationKey> = KEYS
        .iter()
        .take(key_count)
        .filter_map(|entry| VerificationKey::from_qb64(entry).ok())
        .collect();
    let digests: Vec<Digest> = DIGESTS
        .iter()
        .take(digest_count)
        .filter_map(|entry| Digest::from_qb64(entry).ok())
        .collect();
    let witnesses: Vec<IdentifierPrefix> = WITNESSES
        .iter()
        .take(witness_count)
        .filter_map(|entry| IdentifierPrefix::from_qb64(entry).ok())
        .collect();

    let encoding = if flags & 1 == 0 {
        ThresholdEncoding::Text
    } else {
        ThresholdEncoding::Integer
    };

    // Hostile parameter combinations must either build a valid event or fail with a typed error.
    let mut inception = InceptionBuilder::new(keys.clone())
        .next_key_digests(digests.clone())
        .witnesses(witnesses.clone())
        .threshold_encoding(encoding);
    if flags & 2 != 0 {
        inception = inception.signing_threshold(SigningThreshold::numeric(signing));
    }
    if flags & 4 != 0 {
        inception = inception.next_threshold(SigningThreshold::numeric(next));
    }
    if flags & 8 != 0 {
        inception = inception.witness_threshold(witness_threshold);
    }
    if flags & 16 != 0 {
        inception = inception.prefix_derivation(PrefixDerivation::Blake3_256);
    }
    if flags & 32 != 0 {
        inception = inception.configuration(vec![ConfigurationTrait::EstablishmentOnly]);
    }

    let Ok(root) = inception.build() else { return };
    check(&root);
    // Inception is always sequence number zero, whatever was asked for.
    assert_eq!(root.sequence_number(), 0);

    // Building the same event twice is deterministic.
    let repeat = InceptionBuilder::new(keys.clone())
        .next_key_digests(digests.clone())
        .witnesses(witnesses.clone())
        .threshold_encoding(encoding);
    if let Ok(again) = repeat.build() {
        if flags & 62 == 0 {
            assert_eq!(again.raw(), root.raw(), "inception is not deterministic");
        }
    }

    // A non-transferable single-key identifier can never commit to a future.
    if let Ok(key) = VerificationKey::from_qb64(NON_TRANSFERABLE) {
        let abandoned = InceptionBuilder::new(vec![key]).next_key_digests(digests.clone()).build();
        assert_eq!(
            abandoned.is_ok(),
            digests.is_empty(),
            "a non-transferable identifier accepted next keys",
        );
    }

    // Rotations and interactions chain off the identifier just built.
    if sequence_number > 0 {
        let rotation = RotationBuilder::new(root.identifier().clone(), root.said(), sequence_number, keys)
            .next_key_digests(digests)
            .witness_adds(witnesses)
            .kind(if flags & 64 == 0 {
                RotationKind::Rotation
            } else {
                RotationKind::Delegated
            })
            .threshold_encoding(encoding)
            .build();
        if let Ok(rotation) = rotation {
            check(&rotation);
            assert_eq!(rotation.sequence_number(), sequence_number);
            assert_eq!(rotation.identifier(), root.identifier());
            assert_ne!(rotation.said(), root.said(), "a rotation collided with its own prior");
        }

        let mut seal = Sad::new();
        if seal.insert("i", SadValue::text(DIGESTS[0])).is_ok() {
            if let Ok(interaction) =
                InteractionBuilder::new(root.identifier().clone(), root.said(), sequence_number)
                    .anchors(vec![seal])
                    .build()
            {
                check(&interaction);
            }
        }
    } else {
        assert!(
            InteractionBuilder::new(root.identifier().clone(), root.said(), 0)
                .build()
                .is_err(),
            "an interaction accepted sequence number zero",
        );
    }

    // The witness threshold never exceeds its set, whatever count is asked for.
    if let Ok(threshold) = ample(u32::from(byte(data, 8)), None, AmpleMode::Weak) {
        assert!(threshold <= u32::from(byte(data, 8)));
    }
    let _ = Said::from_qb64(DIGESTS[0]);
});
