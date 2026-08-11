# Public verification key reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-11
- Sources: `src/keri/core/{verfer,matter}.ts`, `test/core/verfer.test.ts`
- Algorithms: pinned `libsodium-wrappers-sumo` 0.8.4 Ed25519 and `@noble/curves` 1.9.7 P-256/SHA-256
- Binary fields: lowercase hexadecimal; qualified text is canonical unpadded URL-safe Base64.

Generate from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/crypto_verifier.mjs
```

`cases` covers transferable and non-transferable CESR codes for both reference-supported
algorithms. Each case records exact raw key bytes, qb64, qualified UTF-8 bytes, qb64-derived qb2,
serialization, compact signature, reverse qb64 construction, and positive/changed-message results.
The fixed Ed25519 seed and P-256 private scalar are generator inputs only; neither secret is written
to the fixture.

The pinned `Matter._bexfil` path is unimplemented, so `qb2_hex` is decoded from reference-produced
qb64 with the pinned Base64 helper. Rust safely completes strict qb2 parsing.

`rejected_cases` covers the upstream secp256k1 rejection, short material, a non-verification code,
and unfinished qb2 construction. `verification_edges` records malformed-signature behavior and the
reference's intentional acceptance of both high-S and low-S P-256 signatures. `reference_quirks`
records stricter Rust behavior: exact raw construction rejects suffixes, and public keys are
cryptographically validated at construction rather than deferred until verification.

`safe_p256_divergence` is the maintainer-approved resolution of an unsafe pinned behavior. The
pinned `Verfer` passes serialization bytes to Noble's prehash API and therefore authenticates only
the leftmost 32 bytes of longer inputs. Rust instead uses standard P-256 ECDSA with SHA-256 over the
complete serialization. The fixture records the exact signature produced and accepted by the same
pinned Noble primitive with `prehash: true`; it also proves that this safe signature and the pinned
`Verfer` signature are intentionally not interchangeable.
