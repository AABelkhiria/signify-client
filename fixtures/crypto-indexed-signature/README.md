# Indexed-signature (`Siger`) reference fixture

This fixture records exact indexed-signature behavior from
`WebOfTrust/signify-ts` commit `ae92eceb8e776ad57669707bff7f84db9390b711`
(`0.4.0-16-gae92ece`, package `0.4.0`). Schema version 1 was generated on 2026-08-12.

Upstream evidence:

- `src/keri/core/siger.ts`
- `src/keri/core/indexer.ts`
- `src/keri/core/signer.ts`
- `test/core/signer.test.ts`
- `test/core/eventing.test.ts`
- `test/end/ending.test.ts`

Generate from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/crypto_indexed_signature.mjs
```

The generator uses deterministic public signature bytes and public verification keys. Binary fields
ending in `_hex` are lowercase hexadecimal. `qb64` is unpadded URL-safe Base64 with its CESR hard
and soft fields. `qb2_hex` is obtained by applying the pinned reference Base64 decoder to its own
`qb64`, because `Indexer._bexfil` is unfinished. Successful cases cover all 16 fixed indexed
signature codes; rejected cases record the reference error class/message and the corresponding Rust
error category.

The fixture also pins observable reference quirks: excess raw bytes are truncated, verifier
association is mutable and does not validate algorithms, and omitted prior indices on both-list
P-256 codes are mishandled because those codes are absent from `IndexedBothSigCodex`. Rust rejects
or safely normalizes those states as documented in `PORTING.md`.
