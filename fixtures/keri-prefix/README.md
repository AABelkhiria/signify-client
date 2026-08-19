# KERI identifier-prefix reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-19
- Sources: `src/keri/core/prefixer.ts`, `test/core/prefixer.test.ts`, `test/core/serder.test.ts`
- Binary fields: `preimage_hex` is the lowercase hexadecimal UTF-8 encoding of the exact bytes the
  reference hashes for a self-addressing prefix; `preimage` is the same bytes as text and the two
  are cross-checked on load. Basic derivations hash nothing, so their preimage fields are `null`.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/keri_prefix.mjs --write   # regenerate
node tools/reference-vectors/keri_prefix.mjs --check   # verify determinism
```

## Contents

`cases` records eight derivations. The reference mutates the inception data it is handed, so the
object left behind after a self-addressing derivation *is* the placeholder-bearing intermediate it
hashed; `dummied_sad_json` and `preimage` capture it. Recording the preimage separately from the
prefix isolates the placeholder-and-sizing step from BLAKE3, so a future mismatch points at
serialization rather than at the digest.

- `pinned_prefixer_test_self_addressing` — the inception data from the pinned unit test, whose
  prefix `ELEjyRTtmfyp4VpTBTkv_b6KONMS1V8-EW-aGJ5P_QMo` that test asserts. This event carries an
  identifier field but **no SAID field**, so the reference appends one at the end of the event
  before hashing; reproducing that placement is what makes the expected prefix derivable.
- `pinned_prefixer_test_basic_transferable` — the same data under the transferable basic
  derivation, whose prefix is the controller's key itself.
- `pinned_serder_test_self_addressing` — the inception data from the `Prefixer` assertions in
  `test/core/serder.test.ts`, with both identifier fields in their normal positions. Its prefix
  `ECHOi6qRaswNpvytpCtpvEh2cB2aLAwVHBLFinno3YVW` is also pinned by `fixtures/keri-serder/v1.json`,
  where Roadmap 3.2 recorded it without implementing derivation.
- `pinned_serder_test_basic_transferable` — the basic prefix that test also asserts.
- `basic_non_transferable` — the non-transferable form, whose inception data must carry no next
  keys, backers, or anchors.
- `delegated_inception` and `registry_inception` — the other two event kinds that may originate an
  identifier.
- `both_identifier_fields_absent` — neither identifier nor SAID field present; the reference
  appends both, in that order.

`parsed_prefixes` pins the code, transferability, and digestiveness the reference recovers from a
finished prefix — the `Matter` accessors `eventing.ts` and `keeping.ts` branch on.

`rejected_cases` pins the reference's error class and message for fourteen malformed inputs: wrong
key counts, an absent or unparsable key field, a key whose code contradicts the requested
derivation, a non-transferable identifier carrying rotatable content, a non-incepting or absent
event kind, an absent version string, an unsupported derivation code, a P-256 key, and non-prefix
qualified material.

## Reference quirks recorded as safe Rust divergences

- **The public `derive` and `verify` gate on the wrong field.** Both compare `sad['i']`, the
  identifier field, against the `icp` ilk instead of `sad['t']`. Every real event therefore throws
  `Non-incepting ilk`, and the fixture records the consequence: the only events that reach the
  comparison are ones whose identifier field holds the literal text `icp`, which is exactly what
  `prefixed=true` then rejects. `verify(sad, true)` can never return `true`, so the reference has
  no working way to check that an event claims its own prefix. Rust gates self-addressing
  derivation on the event-kind field and makes `PrefixVerification::Strict` — the check `prefixed`
  intends — the default.
- **The transferable key-code check is a no-op.** It is written
  `verfer.code in [MtrDex.Ed25519]`, which tests array *property keys* and is never true. The
  fixture records that passing a non-transferable `B` key to the transferable `D` derivation
  silently yields a `B` prefix whose `transferable` is `false` — a caller who asked for a rotatable
  identifier gets one that can never rotate. Rust returns `KeyCodeMismatch`.
- **Non-transferable verification skips backers and anchors.** `_verify_ed25519N` checks only the
  next-key field, so the fixture records it accepting events with backers and with anchors that its
  own `_derive_ed25519N` rejects. Rust verifies by re-deriving, so derivation and verification
  cannot disagree.
- **Verification mutates the caller's event.** Self-addressing verification calls the same
  `_derive_blake3_256` that overwrites the identifier and SAID fields with placeholder characters
  and restamps the version string. The fixture records the event before and after. Rust borrows the
  data and clones internally.
- **The constructor calls `super()` twice.** When no code is passed and the identifier field is
  already populated, `new Prefixer({}, ked)` throws
  `ReferenceError: Super constructor may only be called once`, so the natural "recover the
  derivation of a received event" path is unusable. Callers must construct from qb64 and call
  `verify()` instead. Rust exposes no constructor overload with this hazard.

Rust tests consume the checked-in fixture and require neither Node nor network access.
