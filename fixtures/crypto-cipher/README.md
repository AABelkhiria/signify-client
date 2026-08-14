# Cipher material reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-14
- Sources: `src/keri/core/{cipher,matter}.ts` and
  `test/core/{encrypter,decrypter}.test.ts`
- Binary fields: lowercase hexadecimal; qualified text is canonical unpadded URL-safe Base64.

Generate from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/crypto_cipher.mjs
```

`cases` records both deterministic stored ciphertexts from the upstream decrypter test: the `P`
ciphertext wrapping 44-character qualified seed material and the `1AAH` ciphertext wrapping
24-character qualified salt material. Each case records exact raw bytes, qb64, qualified UTF-8
bytes, qb64-derived qb2, and successful pinned `Cipher` reconstruction from qb64 and explicit raw
material.

The pinned `Matter._bexfil` path is unimplemented, so `qb2_hex` is decoded from reference-produced
qb64 with the pinned Base64 helper. Rust safely completes strict qb2 parsing.

`rejected_cases` records empty, short, non-cipher-code, and unfinished qb2 behavior.
`reference_quirks` records strict Rust divergences: exact construction rejects excess raw bytes;
and raw-length inference correctly treats 92 bytes as seed ciphertext instead of reproducing the
pinned `Cipher` defect that assigns the salt code and silently truncates 20 bytes. Ciphertext is
public transport material and may be cloned or persisted, but Rust debug formatting omits its bytes
because it normally carries encrypted secrets.
