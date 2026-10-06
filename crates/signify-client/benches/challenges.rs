//! Microbenchmark for the challenges endpoint family.
//!
//! Nothing here is expensive, and that is worth recording rather than guessing at, because a
//! challenge *looks* cryptographic. It is not: the entropy is the agent's, the mnemonic is the
//! agent's, and the signing that proves control belongs to Roadmap 7.7's exchange submission. What
//! this family does is validate a strength, write two small bodies, and decode two small answers.
//!
//! Inputs: all five entropy sizes; word lists of 12 and 24 words, which is what those sizes
//! produce; a 44-character prefix and SAID.
//!
//! As everywhere in this crate, all of it is negligible beside one signed request, whose signature
//! alone Roadmap 6.4 measured at ~25 µs.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keria_types::api::{Challenge, ChallengeOperation};
use signify_client::endpoint::challenges::{
    CHALLENGES_SEGMENT, CHALLENGES_VERIFY_SEGMENT, ChallengeStrength, STRENGTH_PARAMETER,
};
use signify_http::request::ResourcePath;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue};

const SOURCE: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const SAID: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

/// The twelve words the pinned unit test uses.
const WORDS: [&str; 12] = [
    "shell", "gloom", "mimic", "cereal", "stool", "furnace", "nominee", "nation", "sauce", "sausage", "rather", "venue",
];

/// A word list of `count` words, cycling the pinned twelve.
fn words(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| WORDS.get(index % WORDS.len()).copied().unwrap_or("shell").to_owned())
        .collect()
}

/// The body `verify` sends.
fn words_body(list: &[String]) -> Sad {
    let mut body = Sad::new();
    let _ = body.insert(
        "words",
        SadValue::Array(list.iter().map(|word| SadValue::text(word.clone())).collect()),
    );
    body
}

/// A generated challenge of `count` words, as KERIA answers.
fn challenge_answer(count: usize) -> String {
    let list: Vec<String> = words(count).into_iter().map(|word| format!("\"{word}\"")).collect();
    format!(r#"{{"words":[{}]}}"#, list.join(","))
}

/// A pending challenge operation, as `verify` answers.
fn operation_answer(count: usize) -> String {
    let list: Vec<String> = words(count).into_iter().map(|word| format!("\"{word}\"")).collect();
    format!(
        r#"{{"name":"challenge.{SOURCE}","metadata":{{"words":[{}]}},"done":false}}"#,
        list.join(",")
    )
}

fn benchmark_challenges(criterion: &mut Criterion) {
    let Ok(source) = IdentifierPrefix::from_qb64(SOURCE) else {
        return;
    };
    let Ok(source_text) = source.qb64() else { return };
    let Ok(said) = Said::from_qb64(SAID) else { return };
    let Ok(said_text) = said.qb64() else { return };

    // Validating a strength, which is the one check this family performs on a caller's argument.
    criterion.bench_function("challenges_strength_accepted", |bencher| {
        bencher.iter(|| ChallengeStrength::new(black_box(128)).is_ok());
    });
    criterion.bench_function("challenges_strength_refused", |bencher| {
        bencher.iter(|| ChallengeStrength::new(black_box(129)).is_err());
    });
    criterion.bench_function("challenges_strength_word_count", |bencher| {
        bencher.iter(|| black_box(ChallengeStrength::BITS_256).word_count());
    });

    // Addressing: the generation query, and the address both verification calls share.
    criterion.bench_function("challenges_generate_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(CHALLENGES_SEGMENT)
                .parameter(STRENGTH_PARAMETER, black_box("128"))
                .build()
                .is_ok()
        });
    });
    criterion.bench_function("challenges_verify_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(CHALLENGES_VERIFY_SEGMENT)
                .segment(black_box(&source_text))
                .build()
                .is_ok()
        });
    });

    // The two bodies, at both word counts the reference generates.
    for count in [12_usize, 24] {
        let list = words(count);
        let body = words_body(&list);
        criterion.bench_function(&format!("challenges_verify_body_{count}_words"), |bencher| {
            bencher.iter(|| black_box(&body).to_json_bytes().is_ok());
        });
    }
    let mut acceptance = Sad::new();
    let _ = acceptance.insert("said", said_text);
    criterion.bench_function("challenges_responded_body", |bencher| {
        bencher.iter(|| black_box(&acceptance).to_json_bytes().is_ok());
    });

    // The two answers.
    for count in [12_usize, 24] {
        let document = challenge_answer(count);
        criterion.bench_function(&format!("challenges_decode_challenge_{count}_words"), |bencher| {
            bencher.iter(|| serde_json::from_str::<Challenge>(black_box(&document)).is_ok());
        });
    }
    let operation = operation_answer(12);
    criterion.bench_function("challenges_decode_operation", |bencher| {
        bencher.iter(|| serde_json::from_str::<ChallengeOperation>(black_box(&operation)).is_ok());
    });
}

criterion_group!(benches, benchmark_challenges);
criterion_main!(benches);
