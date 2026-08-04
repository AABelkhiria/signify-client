# CESR Base64-text reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-04
- Sources: `src/keri/core/{bexter,matter,base64}.ts`, `test/core/{bexter,pather}.test.ts`
- Binary fields: lowercase hexadecimal; qualified text is canonical unpadded URL-safe Base64.

Generate from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/cesr_bexter.mjs
```

`cases` covers every upstream `bexter.test.ts` example and a path-shaped dependent example.
`boundary_cases` records the exact final small-code and first large-code artifacts; their inputs are
deterministic repetitions described by `input_pattern` and `input_length`. The fixture intentionally
records complete raw, qb64, and qb2 bytes even for those boundary cases.

`qb2_hex` is decoded from reference-produced qb64 with the pinned Base64 helper because the
reference `Matter._bexfil` path is unimplemented. `parsed_canonical_text` proves that the pinned
`Bexter` accepts its own qb64 output. Inputs `AAAA` and `ABBB` record the reference's documented
leading-`A` ambiguity rather than silently treating constructor text as canonical. `stream_case`
records the reference parser's accidental inclusion of trailing text; Rust exposes prefix parsing
explicitly and makes its whole-input constructor reject the suffix. The reference also accepts a
truncated variable encoding into an object that cannot be re-encoded; Rust rejects it before value
construction.
