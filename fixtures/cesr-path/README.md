# CESR SAD-path reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-04
- Sources: `src/keri/core/{pather,bexter,matter,base64}.ts`,
  `src/keri/app/exchanging.ts`, `test/core/pather.test.ts`
- Binary fields: lowercase hexadecimal; qualified text is canonical unpadded URL-safe Base64.

Generate from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/cesr_path.mjs
```

`cases` covers every upstream unit example, the documented mixed string/integer example, and the
path used to frame exchange embed attachments. `boundary_cases` records complete exact artifacts
for the final small-code and first large-code path. Deterministic repeated components are described
by `component_pattern` and `component_length`.

`qb2_hex` is decoded from reference-produced qb64 with the pinned Base64 helper because the
reference `Matter._bexfil` path is unimplemented. `parsed_components` proves that the pinned
`Pather` accepts its own qb64 output. `stream_case` records the reference parser's accidental
inclusion of trailing material; Rust exposes prefix consumption explicitly and rejects suffixes in
strict constructors.

The pinned TypeScript source explicitly leaves `root`, `strip`, `startswith`, `tail`, and `resolve`
as TODO. Those Rust operations are unit/property tested against component-boundary semantics and
are not presented as TypeScript cross-language evidence. The fixture records three component edge
cases. An internal empty component round-trips and is modeled by Rust as an identity traversal
step. A leading empty component and a component containing `-` lose their original boundaries in
the reference; Rust rejects those ambiguous forms. Text without a leading `-` can construct a
reference object but fails when its path is read; Rust rejects it at construction.
