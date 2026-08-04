# CESR sequence-number reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-04
- Sources: `src/keri/core/{seqner,matter,utils}.ts`, `test/core/seqner.test.ts`
- Binary fields: lowercase hexadecimal; qualified text is canonical unpadded URL-safe Base64.

Generate from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/cesr_sequence.mjs
```

`cases` covers every upstream unit-test value plus `Number.MAX_SAFE_INTEGER`, and verifies that the
pinned `Seqner` accepts its own qb64 output. `exact_raw_cases` qualifies fixed 16-byte values through
the reference, including a value above JavaScript's exact integer range and `u128::MAX`. The raw
bytes and qb64 remain authoritative when the reference's `sn`/`snh` accessors lose precision.

`qb2_hex` is decoded from reference-produced qb64 with the pinned Base64 helper because the
reference `Matter._bexfil` path is unimplemented. The fixture also records deliberate Rust safety
differences: unsigned exact types exclude negative, fractional, and infinite values; hexadecimal
parsing consumes the whole bounded input; and strict raw construction rejects excess bytes instead
of silently truncating them.
