# X25519 decrypter reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-18
- Sources: `src/keri/core/{decrypter,cipher,signer,salter}.ts`, `test/core/decrypter.test.ts`
- Binary fields: lowercase hexadecimal (`*_hex`); all other material is qualified Base64 text
  exactly as emitted by the reference.
- Secret policy: every seed, salt, and private key here is deterministic public test material from
  the pinned unit test and must never be used as a production secret.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/crypto_decrypter.mjs --write   # regenerate
node tools/reference-vectors/crypto_decrypter.mjs --check   # verify determinism
```

The successful cases pin, from the pinned unit test: the exact libsodium
`crypto_sign_ed25519_sk_to_curve25519` conversion of the test seed (raw bytes and qualified `O`
material), equality of the raw-key and seed-parameter construction paths, and decryption of the two
stored fully qualified ciphertexts to the exact wrapped seed (both verifier transferability codes)
and salt. The reverse direction is proven by the pinned reference `Decrypter` class opening the two
deterministic Rust ciphertexts already pinned by `fixtures/crypto-encrypter/v1.json`.

Rejected cases pin the reference's error classes for empty material, a non-decrypter derivation
code, salt material passed as the seed parameter, a call with neither input (unrepresentable in the
Rust signatures), and a tampered ciphertext.

Reference quirks recorded as safe Rust divergences:

- The `Matter` base class silently truncates excess raw private-key bytes; Rust rejects trailing
  material.
- `decrypt` selects its return type from the ciphertext code, so callers cannot state the expected
  secret kind; Rust's typed `decrypt_seed`/`decrypt_salt` reject a mismatched kind before opening.
- The reference throws distinguishable errors for tampered ciphertexts (libsodium) versus
  authenticated boxes wrapping unexpected plaintext (`Signer` construction); Rust returns one
  detail-free `DecryptionFailed` for both so failures cannot act as a decryption oracle.
