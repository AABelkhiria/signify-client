# Cryptographic digest reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-11
- Sources: `src/keri/core/{diger,matter}.ts`, `test/core/diger.test.ts`
- Algorithm implementation: pinned `@noble/hashes` 1.8.0 BLAKE3, 32-byte output
- Binary fields: lowercase hexadecimal; qualified text is canonical unpadded URL-safe Base64.

Generate from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/crypto_digest.mjs
```

`cases` includes the upstream unit serialization, empty input, and every possible byte value. Each
case records exact serialization, raw digest, qb64, qualified UTF-8 bytes, qb64-derived qb2, reverse
qb64 construction, and positive/negative verification results. `rejected_cases` covers missing and
truncated material, unsupported SHA3-256 selection through raw input, unfinished qb2 construction,
and missing comparison input.

The pinned `Matter._bexfil` path is unimplemented, so `qb2_hex` is decoded from reference-produced
qb64 with the pinned Base64 helper. Rust safely completes strict qb2 parsing.

`reference_quirks` records three deliberate Rust API/behavior differences. The reference truncates
excess raw input; Rust separates exact construction from explicit prefix parsing. Its overloaded
constructor silently replaces malformed raw input with a digest of `ser`; Rust uses separate raw and
derivation methods so conflicting sources are unrepresentable. Finally, the reference's `compare`
fast paths compare `Uint8Array` values through object identity or string coercion and return false
even for the same digest. Rust accepts a typed digest and implements the method's documented equality
semantics. The reference also dispatches qb64 input using the constructor argument's default `E`
instead of the parsed material code, so it accepts `H` and even non-digest `D` material while
verifying it with BLAKE3. Rust validates the parsed code before algorithm selection.
