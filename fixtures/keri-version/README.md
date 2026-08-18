# KERI protocol/serialization/version-string reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-18
- Sources: `src/keri/core/core.ts`, `test/core/serder.test.ts`
- Binary fields: none; every value is UTF-8 text, a decimal integer, or a lowercase hexadecimal
  string exactly as emitted by the reference. `major`/`minor` in deversify cases are recorded as
  strings so JavaScript `NaN` observations survive JSON.

Generate from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/keri_version.mjs
```

The successful cases cover the exact `deversify` vector asserted by the pinned
`test/core/serder.test.ts`, both protocols, default and explicit `versify` arguments, the empty and
maximum six-digit sizes, both wire-representable version-digit extremes, and an unsupported-but-
parseable protocol version. Rejected cases pin the reference's error classes for empty, truncated,
mis-terminated, unknown-protocol, unsupported-kind, lowercase-kind, uppercase-digit, and
non-hexadecimal inputs. Rust tests consume the checked-in fixture and require neither Node nor
network access.

Reference quirks recorded as safe Rust divergences:

- `deversify` scans with an unanchored regular expression and accepts arbitrary surrounding text;
  Rust parses exactly seventeen anchored bytes.
- `deversify` coerces hexadecimal version digits with decimal semantics, so `a`–`f` become `NaN`;
  Rust parses them as 10–15, matching `versify`'s own hexadecimal emission.
- Every `deversify` result aliases one module-global mutable `Version` singleton, which is also
  `versify`'s default; a parse therefore silently changes later defaults. Rust returns immutable
  values.
- `versify` emits out-of-range sizes, negative sizes, and version components above 15 as overlong
  or non-hexadecimal invalid strings; Rust makes these states unrepresentable at construction.

The generator orders its calls so default-`versify` outputs are captured before the first
`deversify` mutation, and it records singleton observations eagerly before the next parse
overwrites them.
