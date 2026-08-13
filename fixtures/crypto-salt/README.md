# Salt and deterministic-derivation reference vectors

- Schema: `v1.json`, schema version 1.
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`.
- Exact commit: `ae92eceb8e776ad57669707bff7f84db9390b711`.
- Generated: 2026-08-13.
- Generator: `node tools/reference-vectors/crypto_salt.mjs` from the repository root after
  `npm --prefix reference/signify-ts run build`.
- Upstream sources: `src/keri/core/{salter,signer,matter}.ts` and
  `test/core/salter.test.ts`.

The salt is UTF-8 `0123456789abcdef`; it and every derived seed are deterministic public test
material and must never be used as a production secret. Derivation paths are UTF-8, and binary
fields are lowercase hexadecimal. `qb64` fields are canonical unpadded URL-safe Base64 with their
CESR code. `salt_qb64_bytes_hex` is the UTF-8 encoding of qb64. `salt_qb2_hex` is decoded from
reference-produced qb64 because the pinned TypeScript qualified-binary constructor is unfinished.

Successful cases cover empty, ASCII, and non-ASCII paths; transferable and non-transferable keys;
the temporary profile; and the pinned low profile, including the upstream unit vector. Each case
records the derived seed, verifier, detached signature, and successful TypeScript round trips.
The profile table records all exact libsodium Argon2id v1.3 cost parameters without executing the
256 MiB and 1 GiB profiles during normal fixture generation.

Rejected cases preserve TypeScript error categories/messages and their stable Rust mapping. The
quirks section records excess-raw truncation, nullable tiers, public secret extraction, and Rust's
explicit 4,096-byte path ceiling.
