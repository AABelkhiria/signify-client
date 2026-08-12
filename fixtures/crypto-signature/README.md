# Unindexed signature reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-12
- Sources: `src/keri/core/{cigar,matter}.ts`, `test/core/signer.test.ts`, and
  `test/end/ending.test.ts`
- Binary fields: lowercase hexadecimal; qualified text is canonical unpadded URL-safe Base64.

Generate from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/crypto_signature.mjs
```

`cases` covers all three unindexed-signature codes in the pinned `MatterCodex`: Ed25519, ECDSA
secp256k1, and ECDSA secp256r1. The Ed25519 and P-256 cases use public signature/key vectors already
generated for Roadmap 2.2; the secp256k1 case is deterministic opaque material because the pinned
reference has no secp256k1 verifier. Each case records exact raw bytes, qb64, qualified UTF-8 bytes,
qb64-derived qb2, reverse qb64 construction, and optional verifier association.

The pinned `Matter._bexfil` path is unimplemented, so `qb2_hex` is decoded from reference-produced
qb64 with the pinned Base64 helper. Rust safely completes strict qb2 parsing.

`rejected_cases` records the pinned short/empty-material failures and unfinished qb2 construction.
`reference_quirks` records safe Rust divergences: exact raw construction rejects suffixes; semantic
signature construction rejects non-signature codes; and optional verifier association rejects
algorithm mismatches. Rust also replaces the reference's mutable verifier setter with consuming,
immutable association methods.
