# CESR indexed-material reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-04
- Sources: `src/keri/core/indexer.ts`, `test/core/indexer.test.ts`
- Binary fields: lowercase hexadecimal; qualified text is canonical unpadded URL-safe Base64.

Generate from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/cesr_indexer.mjs
```

Inputs are deterministic arithmetic byte sequences; no randomness or secret material is involved.
Every fixed indexed-signature code is constructed and parsed by the reference. Rejected cases record
the TypeScript error category and the stable Rust category. `qb2_hex` is derived by applying the
pinned reference Base64 decoder to reference-produced `qb64`, because `Indexer._bexfil` explicitly
throws for every input at this revision.

The fixture also records two observable reference defects. `Indexer._rawSize('A')` reports 86 even
though construction requires 64 bytes, due to misplaced parentheses. More importantly,
`IndexedBothSigCodex` omits both-list secp256r1 codes `E` and `2E`; omitting `ondex` for `2E` thus
encodes zero rather than the current index. Rust uses the declared both-list semantics and records
the resulting intentional byte divergence in `reference_quirks`.
