# Private signer reference vectors

- Schema: `v1.json`, schema version 1.
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`.
- Exact commit: `ae92eceb8e776ad57669707bff7f84db9390b711`.
- Generated: 2026-08-12.
- Generator: `node tools/reference-vectors/crypto_signer.mjs` from the repository root after
  `npm --prefix reference/signify-ts run build`.
- Upstream sources: `src/keri/core/{signer,matter,verfer,cigar,siger,indexer}.ts` and
  `test/core/signer.test.ts`.

The deterministic input seed is the 32-byte sequence `00 01 ... 1f`; it is public test material
and must never be used as a production secret. The serialization is UTF-8
`abcdefghijklmnopqrstuvwxyz0123456789`. Raw seed, verifier, serialization, and signature fields are
lowercase hexadecimal. `qb64` fields are canonical unpadded URL-safe Base64 with their CESR code;
`qb64_bytes_hex` is its UTF-8 byte encoding. `qb2_hex` is obtained by decoding reference-produced
`qb64`, because the pinned TypeScript qualified-binary constructors are unfinished.

Successful cases pin transferable/non-transferable verifier derivation, unindexed signing, and all
Ed25519 small/big current-only/both-list code-selection branches. Rejected cases record the exact
TypeScript error category/message and the corresponding stable Rust error category. The quirks
section records reference truncation of excess seed bytes, ignored `ondex` in current-only mode,
and the intentional Rust secret-exposure hardening.
