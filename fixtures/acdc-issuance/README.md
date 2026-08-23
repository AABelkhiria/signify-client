# ACDC issuance and revocation reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-23
- Sources: `src/keri/app/credentialing.ts`, `src/keri/core/utils.ts`,
  `test/app/credentialing.test.ts`, `test/core/utils.test.ts`
- Binary fields: none. Identifiers are qualified Base64; events are exact serialized text and
  attachments are exact CESR text.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/acdc_issuance.mjs --write   # regenerate
node tools/reference-vectors/acdc_issuance.mjs --check   # verify determinism
```

## Determinism

None of these builders derives a key, so every recorded value is exact and the generator is
instant. The one clock reading in the ported code is the revocation timestamp, which is supplied
instead; its default expression is recorded by text in
`reference_quirks.revocation_timestamp_defaults_to_the_clock`. The issuance event has no clock
reading at all — it takes the credential's own attribute timestamp.

## What the evidence is

Roadmap 6.2 ports what `Credentials.issue` and `Credentials.revoke` construct before anything is
sent: the `iss` transaction event, the `rev` transaction event, the interaction event anchoring
either in the issuer's key event log, and the two CESR attachments of `src/keri/core/utils.ts`. The
keeper signatures' place in a request body, the path, and the `POST`/`DELETE` are Roadmap 6.11;
embedding the result in an IPEX grant is Roadmap 6.3.

As in Roadmap 6.1, the ported unit is a set of expressions rather than an exported function, so the
fixture carries two independent kinds of evidence:

1. **`declarations`** holds the `iss` construction, the `_rev` literal, both `interact(...)` calls,
   the `ri`/`rd` fallback, and both attachment serializer bodies, read out of the reference's own
   syntax tree by its own pinned TypeScript. A Rust test asserts each event's fields appear there in
   the order this port writes them, that both anchors use `sn: sn + 1`, and that only the couple
   serializer pipelines.
2. **`issuances`** and **`revocations`** hold five and three complete cases produced by the
   reference's own compiled `Saider`, `interact`, and serializers — each with the transaction
   event's exact bytes and SAID, the anchor's exact bytes and SAID, the seal the anchor carries,
   both attachments where applicable, and the reference's own `Saider.verify` verdict.

Two blocks anchor the set against values the reference's own test suite asserts against rather than
against this generator:

- **`pinned_artifacts`** rebuilds the `iss` event and the `ixn` that
  `test/app/credentialing.test.ts` constructs inside its IPEX grant assertion. The rebuilt `iss`
  SAID equals the `ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW` that test publishes, and both
  attachment strings appear verbatim inside the grant attachment it publishes. Note that this
  test's anchor deliberately seals `[{}]` rather than the transaction event — it is testing the
  grant, not the issuance — which the fixture records as `anchor_seals_empty_object`.
- **`pinned_serializers`** holds the two vectors `test/core/utils.test.ts` asserts directly, with
  their inputs, and records that both reproduce.

## Contents

- `issuances` pins five: the issuance of the pinned mock credential at the issuer's first
  interaction; one anchored well into the key event log; one whose anchor position needs
  hexadecimal digits; one past 32 bits; and one at a different instant, which changes the
  transaction event alone.
- `revocations` pins three, covering the same anchor positions.
- `reference_quirks` pins nine behaviours, each with what the reference does and what this port
  does instead.

## Reference behavior recorded as deliberate divergences

- **A revocation's sequence number is the literal `'1'`.** The reference can only revoke a
  credential whose transaction log holds exactly one prior event; a credential in a backed registry,
  whose log carries backer rotations, would get an event claiming a position it does not occupy.
  Here it is an input defaulting to one.
- **A revocation's prior digest comes from the server.** `p` is read from `cred.status.d`, so the
  reference cannot build a revocation without fetching the credential first. Here it is an input,
  so revocation artifacts are constructible offline.
- **The revocation timestamp defaults to a clock reading**, with three zero digits standing in for
  microseconds it never had — the same fake precision Roadmap 5.5 recorded on `Signify-Timestamp`.
  A protocol crate reads no clock.
- **The issuance timestamp is the credential's own** — `dt: subject.dt` rather than a second clock
  reading. That is reproduced and made structural: `IssuanceEvent::for_credential` takes no
  timestamp.
- **`serializeACDCAttachment` names its parameter `anc`** but every call site passes the
  *issuance* event, so the triple it builds is (credential SAID, 0, iss SAID). Here it is a method
  on the issuance event, so there is no argument to get wrong.
- **A transaction event with no `s` field reads as position zero.** `Serder.sn` builds a
  `CesrNumber` from `sad['s']`, and the pinned `utils.test.ts` vector has no such field. A sequence
  number is a `u128` on a typed event here and is never read back out of an untyped map.
- **The `rd` registry spelling is accepted**, and the reference throws when neither `ri` nor `rd` is
  present. Roadmap 6.1 always writes `ri`, and `PORTING.md` §5.12 already records CESR 2 as out of
  scope, so the `rd` branch is unreachable from a credential this port built.
- **An establishment-only issuer throws.** Both `issue` and `revoke` raise
  `Establishment only not implemented` — two occurrences across all 117 pinned `.ts` files — because
  anchoring in such a log needs a rotation event neither builds. Here it is a typed refusal naming
  the trait, checked before anything is built.
- **`bis` and `brv` have no builder.** The backed spellings of issuance and revocation are declared
  in the ilk table and constructed nowhere — both scans return zero across all 117 files — so they
  are recorded `N/A` on the same evidence as Roadmap 3.6's receipt and query messages.

Both serializer inputs in `pinned_serializers` are also events this port would refuse *as messages*:
each writes its version string after another field, which Roadmap 3.2's `SerializedEvent` rejects
and the reference's `Serder` does not. They are read as ordered data instead, which is all the
serializers use.

Rust tests consume the checked-in fixture and require neither Node nor network access.
