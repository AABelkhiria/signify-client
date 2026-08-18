# KERI self-addressing-identifier reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-18
- Sources: `src/keri/core/saider.ts`, `test/core/saider.test.ts`
- Binary fields: `preimage_hex` is the lowercase hexadecimal UTF-8 encoding of the exact bytes the
  reference hashes; `preimage` is the same bytes as text and the two are cross-checked on load.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/keri_said.mjs --write   # regenerate
node tools/reference-vectors/keri_said.mjs --check   # verify determinism
```

## Contents

`cases` records the complete derivation of three SADs, including the intermediate that is actually
hashed. Recording the preimage separately from the identifier isolates the placeholder-and-sizing
step from BLAKE3, so a future mismatch points at serialization rather than at the digest:

- `pinned_rep_message` — the `rep` message whose SAID
  `ELzewBpZHSENRP-sL_G_2Ji4YDdNkns9AzFzufleJqdw` the pinned unit test asserts.
- `version_less_block` — a SAD with no version string, the shape ACDC nests inside a credential.
- `custom_label` — derivation against an identifier field named `id` rather than `d`.

Each case pins the placeholder (44 `#` characters, exactly the width of the identifier that
replaces it), the preimage bytes, the resulting identifier, and the completed data with its
identifier filled in and version string sized.

`verification` records the reference's outcome for the completed message under each combination of
its `prefixed` and `versioned` flags, plus tampered content and a restamped version string.

`rejected_cases` pins the reference's error classes for `saidify` with an absent label and for an
unsupported digest code.

## Reference quirks recorded as safe Rust divergences

- **Default verification ignores the identifier field.** Derivation replaces that field with a
  placeholder before hashing, so its actual content is never checked unless the caller passes
  `prefixed=true`. The fixture records that `verify(sad)` returns `true` for a message whose `d` is
  empty *and* for one holding an entirely unrelated SAID. A caller who writes `verify(sad)` has not
  verified what the message claims about itself. Rust's default policy,
  `SaidVerification::strict`, requires the field to match; the reference behavior remains available
  only under the explicitly named `SaidVerification::digest_only`.
- **The public `derive` appends an absent label.** Rather than rejecting a SAD with no identifier
  field, it inserts one at the end of the field order and sizes the version string around it,
  silently changing the bytes being committed to. Only `saidify` checks first. Rust always requires
  the field to exist.
- **The constructor calls `super()` twice.** When the identifier field is already populated and no
  code is passed, `new Saider({}, sad)` throws
  `ReferenceError: Super constructor may only be called once`, so the natural "parse a received
  message and check its SAID" path is unusable. Callers must construct from qb64 and call
  `verify()` instead. Rust exposes no constructor overload with this hazard.

Rust tests consume the checked-in fixture and require neither Node nor network access.
