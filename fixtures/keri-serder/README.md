# KERI deterministic serialization reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-18
- Sources: `src/keri/core/serder.ts`, `test/core/serder.test.ts`
- Binary fields: `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the reference's exact
  serialization; `raw` is the same bytes as text and the two are cross-checked on load. All other
  values are text or decimal integers exactly as the reference emits them.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/keri_serder.mjs --write   # regenerate
node tools/reference-vectors/keri_serder.mjs --check   # verify determinism
```

## Contents

`cases` holds the three messages the pinned unit test exercises, each with the reference's exact
serialized bytes, byte size, `size` accessor value, and derived version string:

- `pinned_inception` — the 211-byte inception event whose raw bytes the unit test asserts verbatim.
- `pinned_non_ascii_anchor` — the 313-byte `Lenksjö` case. The unit test reaches it only after two
  `Prefixer` derivations have rewritten `i` and `d` in place, so the generator reproduces that
  mutation sequence and records the resulting data verbatim. `blake3_prefix` pins the prefix the
  unit test asserts, which proves the sequence was reproduced exactly; Rust consumes the recorded
  values and does not implement prefix derivation until Roadmap 3.4.
- `pinned_interaction` — the 315-byte interaction event used for sequence-number and parse
  coverage.

`encoding_cases` holds two `dumps` matrices used as direct byte expectations: every C0 control
character plus `"`, `\`, `/`, DEL, U+2028, U+2029, Latin-1, CJK, and an astral scalar; and a
value-shape matrix covering empty containers, nesting, `null`, booleans, and the safe-integer
extremes.

`rejected_cases` pins the reference's error classes for a missing version field, a malformed
version string, and an unsupported serialization kind.

## Reference quirks recorded as safe Rust divergences

- **Numeric key hoisting** — JavaScript objects order array-index-like keys (`"0"`, `"1"`)
  numerically ahead of the rest, so `JSON.stringify` reorders them. keripy, the protocol's
  reference implementation, uses insertion-ordered dicts, so this is a JavaScript artifact rather
  than protocol order and Rust preserves insertion order.
- **Duplicate field labels** — `JSON.parse` keeps the last value at the first position; Rust
  rejects the ambiguity rather than silently discarding a value.
- **Number renormalization** — parse/stringify re-spells numbers through IEEE-754 (`1.50` to
  `1.5`, `1e2` to `100`, `9007199254740993` to `9007199254740992`), which would change any SAID
  computed over them. Rust rejects fractional, exponent, and unsafe-magnitude numbers instead.
- **Version field not first** — the reference sizes and emits a message whose `v` is not the first
  field, which no stream parser can sniff. Rust rejects it.
- **Embedded version string** — the reference's unanchored version regex accepts a padded value,
  computes the size while the longer value is still present, then substitutes a 17-byte one. The
  recorded message declares 39 bytes but is 35. Rust rejects both the input and the output.
- **UTF-16 size accessor** — `Serder.size` reports a JavaScript string length, so it reports 312
  for the 313-byte non-ASCII message. The version string itself correctly counts UTF-8 bytes.

Rationale for every divergence is recorded in
`docs/adr/0008-deterministic-json-serialization.md`. Rust tests consume the checked-in fixture and
require neither Node nor network access.
