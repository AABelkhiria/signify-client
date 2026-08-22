# KERI Controller and Agent reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-22
- Sources: `src/keri/app/controller.ts`, `test/app/controller.test.ts`
- Binary fields: the agent seed is recorded as decimal bytes; keys, digests, events, and
  signatures are qualified Base64 or exact serialized text.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/keri_controller.mjs --write   # regenerate
node tools/reference-vectors/keri_controller.mjs --check   # verify determinism
```

## Determinism

A `Controller` hardcodes the production Argon2 profile, so every derived key here costs a real
64 MiB derivation and the generator takes several seconds. All key material derives from the two
passcodes and the agent seed the pinned unit test declares; no secret beyond those public test
constants is stored.

Sealed boxes draw a fresh ephemeral key per call, so ciphertexts cannot be pinned byte-for-byte.
The rotation section records the *plaintexts* instead: what the input records sealed
(`aid_salt_qb64`, `seed_qb64s`) and what every output ciphertext opens to through the reference's
own decrypter. The Rust test seals its own inputs to the same prior encryption key; the events and
signatures — which do not depend on any ciphertext — are compared byte for byte.

## Contents

- `controllers` pins both `controller.test.ts` prefixes with their complete inception events, a
  rotation-index-one controller, the pinned agent verifier, and the `event` getter's signature.
- `restore_cases` pins the constructor's state branch: a sequence-zero establishment event — under
  both the string and number spellings, because the comparison is loose equality — rebuilds the
  local inception, while a later event is adopted without any ownership check.
- `agent` pins one accepted delegated state (with a hexadecimal sequence number) and six
  rejections with the reference's own error text.
- `approval` pins two chained delegation approvals: the anchored interaction events, their
  sequence numbers, and their signatures.
- `rotation` pins the complete passcode-rotation payload: the exact rotation event and both
  signatures, what the sealed salt and every re-encrypted identifier key open to, the confirmation
  that the **new** passcode's key cannot open the payload, and three rejections.

## Reference behavior recorded as deliberate divergences

- **The rotation payload is sealed to the prior passcode's encryption key**, and the sealed salt
  is the *old* salt — `sxlt_opens_under_new_passcode` is `false` from the reference itself.
  Reproduced loudly (the workflow decision belongs to Roadmap 8.9); see ADR `0016`.
- **The rotation event always claims sequence one**, whatever the log's position, while its prior
  digest points at the current event.
- **A second rotation derives from the original salt**: `rotate` never updates the stored salter
  or bran, so every rotation commits the same "old" key and seals the same salt.
- **`ridx` mutation does not re-derive.** The client assigns the field after construction while
  the keys stay put; Rust fixes the index at construction.
- **`get verfers` always throws** (`this.signer.verfer is not a function`) and **`derive` is dead
  code** that reads a different state shape than the constructor and throws on `undefined`.
  Neither is ported.

Rust tests consume the checked-in fixture and require neither Node nor network access.
