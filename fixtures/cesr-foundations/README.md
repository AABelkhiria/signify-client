# CESR foundation vectors (schema version 1)

These fixtures cover Base64, six-bit integer, and big-endian byte/integer behavior.

- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-03
- Sources: `src/keri/core/base64.ts`, `core.ts`, and `utils.ts`
- Tests used as evidence: `test/core/base64.test.ts` and the Roadmap 1.1 cases in
  `test/core/coring.test.ts`
- Binary encoding in `v1.json`: JSON arrays of unsigned decimal bytes
- Integer encoding in `v1.json`: decimal strings, avoiding JSON number-width ambiguity

Generate from the workspace root:

```bash
npm --prefix reference/signify-ts ci --ignore-scripts
npm --prefix reference/signify-ts run build
node tools/reference-vectors/cesr_foundations.mjs
```

The generator executes the compiled output of the pinned TypeScript checkout. `base64_cases` records
canonical upstream encodings and every padded/unpadded spelling checked by the generator.
`rejected_cases` records a reference-rejected input. `strict_rejections` records unsafe reference
acceptance that Rust deliberately rejects: standard-alphabet bytes, incomplete quanta, partial
padding, and non-zero unused bits. No normalization is applied.
