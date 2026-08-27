# KERI key-manager reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-20
- Sources: `src/keri/core/manager.ts`, `test/core/manager.test.ts`, `test/app/controller.test.ts`
- Binary fields: none. Keys, signatures, and digests are qualified Base64; the one sealed value is
  recorded by what it opens to rather than by its bytes.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/keri_manager.mjs --write   # regenerate
node tools/reference-vectors/keri_manager.mjs --check   # verify determinism
```

## Determinism

The salt and the encryption seed are the pinned unit test's own public constants, and the temporary
Argon2 profile is selected wherever the reference's `temp` flag is set. Two values would otherwise
vary between runs and are handled explicitly:

- **A sealed box draws a fresh ephemeral key each call**, so the salt ciphertext is never the same
  twice. The fixture records its code, its length, and — the stronger statement — the salt it
  *opens to*, obtained by handing it back to the reference's own decrypter.
- **`PubLot.dt` is `new Date().toString()`** — a locale string, not an ISO-8601 timestamp. It is
  masked so the shape stays pinned while the value does not vary: digits become `#` and letters
  become `@`, and the parenthesised timezone name is dropped. Letters are masked because the
  weekday and month names change with the day, and the timezone name is dropped because it changes
  with the machine and with daylight saving. Masking only the digits — as this fixture originally
  did, following Roadmap 3.6's reply timestamp — left it stale the day after it was written.

Random keys cannot be pinned at all, so `randy_creator_shape` records the structure of a randy key
set — count, code, length, transferability, distinctness, and the absence of paths — rather than
any key.

## Contents

`salty_creator_cases` records thirteen `SaltyCreator.create` calls with every input, the derivation
paths the creator built, and the private and public keys it produced. The Rust test re-derives each
one and compares the paths and public keys; the private keys are recorded for completeness but are
never compared, because `Signer` exposes no seed by design (ADR `0004`).

`encrypted_manager` and `unencrypted_manager` each record a whole walk — inception, every signature
form, two rotations — with a complete snapshot of the key store after each step: the globals, the
per-identifier parameters, all three key sets with their rotation and key indices, every stored key
set under its rotation key, and every derivation path. The Rust test replays the walk and compares
the whole snapshot.

`rejected_cases` records ten calls the reference refuses, each with the error it raises.
`reference_quirks` records six behaviors with the reference's own output.

## Reference behavior recorded as deliberate divergences

- **An empty stem derives one key for every rotation.** The path is
  `stem == "" ? hex(pidx) : stem + hex(ridx) + hex(kidx)`, so an empty stem drops the rotation and
  key indices entirely. `empty_stem_reuses_the_key` records the consequence from the reference
  itself: an identifier's current and committed-to public keys are **identical**, so pre-rotation
  commits to the key already in use and protects nothing. This is reproduced exactly — diverging
  would derive different identifiers from the same inputs — and
  `DerivationPath::reuses_keys_across_rotations` reports the condition so a caller can refuse it.
- **A rotation forgets the derivation code.** `rotate` builds a `PubPath` and sets `path`, `tier`,
  and `temp` but never `code`, which therefore stays the class default of the empty string.
  `rotation_forgets_the_derivation_code` records the stored path and the error signing with it
  raises — `Cannot read properties of undefined (reading 'hs')` — so **an identifier held without
  encryption cannot sign with the keys a rotation gave it**. The pinned unit test never notices,
  because it reads back the path inception stored. There is no separate code to forget here: this
  port derives Ed25519 only, and a stored path carries the profile it was derived under.
- **An inception with no signing keys crashes.** The prefix is `verfers[0].qb64`, so an empty
  current set raises `Cannot read properties of undefined (reading 'qb64')`. Rust returns
  `ManagerError::NoCurrentKeys`.
- **`updateAeid` is unreachable.** It is private, called only from the constructor, and only when
  `this.aeid` is undefined and `_decrypter` has just been set to undefined — so its last-seed check
  and its entire re-encryption loop can never run. Not ported; re-keying is Roadmap 8.9.
- **`PubLot.dt` is written and never read.** Omitted, because a protocol crate does not read the
  clock.
- **`sign` has two entry points that do the same thing.** One takes qualified public keys and one
  takes verification keys; `two_signing_entry_points` records that both produce the same bytes, so
  there is one method here.
- **A randy creator answers the salt, stem, and tier accessors with empty strings**, casting one of
  them to the tier enum. Rust's randy creator has no such accessors, and a randy identifier records
  no salt and no tier.

Rust tests consume the checked-in fixture and require neither Node nor network access.
