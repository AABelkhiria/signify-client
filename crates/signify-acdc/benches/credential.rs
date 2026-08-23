//! Microbenchmark for ACDC credential construction.
//!
//! Building a credential is two BLAKE3-256 derivations over four serializations: the attribute
//! block is sized and hashed, then the container is sized and hashed with the block inside it. The
//! cost is therefore driven by how big the caller's blocks are, not by any cryptographic key
//! operation — there is none here — so the interesting axes are the attribute count, whether an
//! edge and a rule block are carried, and how large those blocks are.
//!
//! The inputs are the pinned reference's own: the QVI credential of its single-signature vLEI
//! suite, and the LE credential that adds an edge block and the two rule disclaimers, whose
//! combined rule text is about a kilobyte.

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use signify_acdc::credential::{CredentialAttributes, CredentialBuilder, RegistryIdentifier};
use signify_keri::event::timestamp::Timestamp;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::{DEFAULT_SAID_LABEL, Said};
use signify_keri::serialization::{Sad, SadValue};

const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const HOLDER: &str = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";
const REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";

const USAGE_DISCLAIMER: &str = "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.";
const ISSUANCE_DISCLAIMER: &str = "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.";

/// The QVI credential's attribute block: an issuee, a timestamp, and one attribute.
fn qvi_attributes(stamp: &Timestamp) -> Option<CredentialAttributes> {
    let holder = IdentifierPrefix::from_qb64(HOLDER).ok()?;
    CredentialAttributes::new(stamp.clone())
        .issuee(&holder)
        .ok()?
        .timestamp()
        .ok()?
        .text("LEI", "254900OPPU84GM83MG36")
        .ok()
}

/// An attribute block carrying `count` caller-defined fields.
fn wide_attributes(stamp: &Timestamp, count: usize) -> Option<CredentialAttributes> {
    let holder = IdentifierPrefix::from_qb64(HOLDER).ok()?;
    let mut attributes = CredentialAttributes::new(stamp.clone())
        .issuee(&holder)
        .ok()?
        .timestamp()
        .ok()?;
    for index in 0..count {
        attributes = attributes.text(format!("field{index}"), "254900OPPU84GM83MG36").ok()?;
    }
    Some(attributes)
}

/// The reference's own two-disclaimer rule block, saidified as its callers saidify it.
fn le_rules() -> Option<Sad> {
    let mut usage = Sad::new();
    usage.insert("l", SadValue::text(USAGE_DISCLAIMER)).ok()?;
    let mut issuance = Sad::new();
    issuance.insert("l", SadValue::text(ISSUANCE_DISCLAIMER)).ok()?;

    let mut rules = Sad::new();
    rules.insert(DEFAULT_SAID_LABEL, SadValue::text("")).ok()?;
    rules.insert("usageDisclaimer", SadValue::Map(usage)).ok()?;
    rules.insert("issuanceDisclaimer", SadValue::Map(issuance)).ok()?;
    Some(
        Said::compute(&rules, signify_acdc::credential::DIGEST_ALGORITHM, DEFAULT_SAID_LABEL)
            .ok()?
            .into_parts()
            .1,
    )
}

/// A one-edge chain to another credential.
fn le_edges() -> Option<Sad> {
    let mut qvi = Sad::new();
    qvi.insert("n", SadValue::text("EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo"))
        .ok()?;
    qvi.insert("s", SadValue::text(SCHEMA)).ok()?;

    let mut edges = Sad::new();
    edges.insert(DEFAULT_SAID_LABEL, SadValue::text("")).ok()?;
    edges.insert("qvi", SadValue::Map(qvi)).ok()?;
    Some(
        Said::compute(&edges, signify_acdc::credential::DIGEST_ALGORITHM, DEFAULT_SAID_LABEL)
            .ok()?
            .into_parts()
            .1,
    )
}

fn benchmark_credential(criterion: &mut Criterion) {
    let (Ok(stamp), Ok(issuer), Ok(registry), Ok(schema)) = (
        STAMP.parse::<Timestamp>(),
        IdentifierPrefix::from_qb64(ISSUER),
        RegistryIdentifier::from_qb64(REGISTRY),
        Said::from_qb64(SCHEMA),
    ) else {
        return;
    };
    let (Some(attributes), Some(edges), Some(rules)) = (qvi_attributes(&stamp), le_edges(), le_rules()) else {
        return;
    };

    // `build` consumes its builder, so the builder is assembled in the batched setup phase and
    // only the derivation itself is timed. Timing the clone too would measure this benchmark's
    // scaffolding rather than the cost a caller pays.
    let plain = || CredentialBuilder::new(issuer.clone(), registry.clone(), schema, attributes.clone());

    // The plainest credential the reference issues: 407 bytes, three attribute fields.
    criterion.bench_function("credential_qvi", |bencher| {
        bencher.iter_batched(
            plain,
            |builder| black_box(builder).build().is_ok(),
            BatchSize::SmallInput,
        );
    });

    // The chained one: the same block plus an edge block and about a kilobyte of rule text, which
    // is the largest credential in the pinned tree at 1,480 bytes.
    let Ok(chained) = plain().edges(edges).and_then(|builder| builder.rules(rules.clone())) else {
        return;
    };
    criterion.bench_function("credential_le_with_edges_and_rules", |bencher| {
        bencher.iter_batched(
            || chained.clone(),
            |builder| black_box(builder).build().is_ok(),
            BatchSize::SmallInput,
        );
    });

    // How the cost grows with the attribute count, which is the one axis a caller controls
    // without bound. Each field adds about 32 bytes to both hashed serializations.
    for count in [1_usize, 16, 128] {
        let Some(wide) = wide_attributes(&stamp, count) else {
            return;
        };
        let builder = CredentialBuilder::new(issuer.clone(), registry.clone(), schema, wide);
        criterion.bench_function(&format!("credential_{count}_attributes"), |bencher| {
            bencher.iter_batched(
                || builder.clone(),
                |builder| black_box(builder).build().is_ok(),
                BatchSize::SmallInput,
            );
        });
    }

    // Validating a caller-supplied block is a separate cost from building, and it is the one paid
    // on data that may have arrived from a peer — so it is worth knowing it is cheap enough to
    // run before anything is hashed.
    criterion.bench_function("credential_validate_rules_block", |bencher| {
        bencher.iter_batched(
            || (plain(), rules.clone()),
            |(builder, rules)| black_box(builder).rules(black_box(rules)).is_ok(),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, benchmark_credential);
criterion_main!(benches);
