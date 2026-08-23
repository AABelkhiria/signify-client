# ACDC credential reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-23
- Sources: `src/keri/app/credentialing.ts`, `test/app/credentialing.test.ts`,
  `test/app/test-utils.ts`, `test-integration/singlesig-vlei-issuance.test.ts`,
  `test-integration/multisig-vlei-issuance.test.ts`
- Binary fields: none. Identifiers and schema SAIDs are qualified Base64; credentials and attribute
  blocks are exact serialized text.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/acdc_credential.mjs --write   # regenerate
node tools/reference-vectors/acdc_credential.mjs --check   # verify determinism
```

## Determinism

`Saider.saidify` reads no clock and derives no keys, so every recorded value is exact and the
generator runs instantly. The single non-deterministic input in the ported code is the attribute
timestamp, which the reference defaults to `new Date()`; it is supplied here as the pinned mock
credential's own `2023-08-23T15:16:07.553000+00:00`, and its default expression is recorded by
text and shape in `reference_quirks.timestamp_default_reads_the_clock`.

## What the evidence is

Roadmap 6.1 ports two expressions — the `Saider.saidify(...)` calls inside `Credentials.issue`
that build the attribute block and the credential container. Everything else in that method (the
TEL issuance event, the anchoring interaction, the keeper signatures, the `POST`) is Roadmap 6.2
and 6.11 and is deliberately not driven.

Because the ported unit is an expression rather than an exported function, the fixture carries two
independent kinds of evidence:

1. **`declarations`** holds the two expressions themselves, read out of the reference's own syntax
   tree by its own pinned TypeScript 5.9.2, alongside the member lists of `CredentialSubject`,
   `CredentialData`, `CredentialFilter`, and `CredentialTypes`. The generator therefore
   demonstrably re-expresses production code rather than a paraphrase of it, and a Rust test
   asserts the container's nine fields appear in the expression in the order this port writes
   them. The third `saidify` call — the issuance event — is recorded too, so a reader can see the
   whole method was read and what was left for 6.2.
2. **`credentials`** holds thirteen complete credentials produced by the reference's own compiled
   `Saider` and `versify`, each with its exact bytes, both identifiers, its size, its serialized
   field order, and the reference's own `Saider.verify` verdict on it.

`pinned_artifact` anchors the whole set against something the reference asserts against rather
than against this generator: `mockCredential.sad` in `test/app/test-utils.ts` is read from source,
verified by the reference's own `Saider`, and shown byte-identical to the credential the generator
rebuilds from its inputs. Rust rebuilds the same bytes and reproduces both published SAIDs.

## Contents

- `credentials` pins thirteen credentials: the mock credential above; the exact arguments the
  pinned `credentialing.test.ts` passes to `issue`; the QVI, LE, and ECR credentials of the pinned
  vLEI suites, covering an edge block, two and three rule disclaimers, and a privacy salt at both
  levels; an untargeted credential whose attribute block is `d` and `dt` alone; both timestamp
  placements; edges without rules and rules without edges; one credential carrying every
  representable JSON shape; and one carrying non-ASCII text, whose version string counts bytes
  rather than characters.
- `supporting` pins the three blocks those credentials embed — two rule blocks and one edge block —
  with the identifiers the reference derived for them, so this port's derivation is checked against
  the reference's on data it did not build.
- `reference_quirks` pins thirteen behaviours, each with what the reference does and what this port
  does instead.

## Reference behavior recorded as deliberate divergences

- **JavaScript hoists array-index-like keys.** An attribute named `0` is serialized ahead of every
  other field, including the `d` the reference writes first — the fixture records the order
  `["0", "10", "d", "b", "01", "dt"]` — and both identifiers commit to it. ADR `0008` settled that
  `Sad` is insertion-ordered, so the hoist cannot be spelled here; such a label is refused in the
  attribute, edge, and rule blocks rather than deriving a different identifier from the same
  inputs. `01` has a leading zero, is not an array index, and is accepted on both sides.
- **An attribute named `v` is resized as if the block were a message.** `Saider._derive` checks
  `'v' in sad` and runs `sizeify`, so a caller's `ACDC10JSON000000_` comes back rewritten to the
  attribute block's own length. `v` is reserved here, as is `d`, which the reference silently
  replaces with its derivation placeholder.
- **`CredentialData.v` and `.d` are declared and read by nothing.** Supplying either changes no
  byte; neither is a builder input here.
- **The attribute block is not really required.** TypeScript marks `a` required, but the type is
  erased at run time and `{...undefined}` is legal, so a credential built without it still carries
  a block of `d` and `dt` — byte-identical to the empty block spelled out. A non-object block is
  worse: spreading a string yields one array-index key per character.
- **Numbers are doubles.** A fractional attribute is committed as `1.5`, and an integer above
  2^53 is rounded before it is ever serialized — the fixture records `9007199254740995` committed
  as `9007199254740996`. `SadValue` accepts only exact safe integers.
- **The issuer, registry, schema, and issuee are unchecked text**, and an empty `ri` or `s` is
  accepted as readily as an absent one. All four are typed here, and the registry and schema are
  required.
- **The timestamp defaults to the system clock** with three zero digits standing in for microseconds
  it never had — the same fake precision Roadmap 5.5 recorded on `Signify-Timestamp`. A protocol
  crate reads no clock, so it is a required validated `Timestamp`.
- **`CredentialTypes` has no consumer.** A scan of all 117 `.ts` files in the pinned source and test
  trees finds the needle exactly once, in its own declaration, so it is recorded `N/A` on the same
  evidence as `core/httping.ts`'s `Unqualified`.
- **`CredentialFilter` is request shaping**, named only in `credentialing.ts` and consumed only by
  `Credentials.list`, so it goes to Roadmap 6.11 with the endpoint that sends it.

Rust tests consume the checked-in fixture and require neither Node nor network access.
