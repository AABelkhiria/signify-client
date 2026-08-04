# Exact CESR number reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-04
- Sources: `src/keri/core/{number,matter,utils}.ts`, `test/core/number.test.ts`
- Binary fields: lowercase hexadecimal; qualified text is canonical unpadded URL-safe Base64.

Generate from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/cesr_number.mjs
```

`cases` includes every upstream unit-test form plus each code transition that JavaScript can
represent exactly and a deterministic huge power of two. `exact_material_cases` qualifies the
minimum and maximum raw value for all four `NumDex` codes through the pinned `Matter` engine; this
provides exact 64-bit and 128-bit qualification evidence without passing those bytes through an
imprecise JavaScript `number`. `qb2_hex` is derived from reference-produced `qb64` with the pinned
Base64 decoder because `CesrNumber` rejects all encoded-input constructor paths before delegating
to `Matter`.

The fixture records deliberate safety differences. Rust uses `u128`, rejects negative and
fractional values by type, and parses complete bounded hexadecimal text instead of JavaScript
`parseInt` prefixes. The reference also rounds its `2^64 - 1` and `2^128 - 1` selection thresholds;
as a result, input `2 ** 64` is truncated into an eight-byte zero and `2 ** 128` into a sixteen-byte
zero. Rust instead encodes every value through `u128::MAX` exactly and rejects anything larger.
