# KERI identifier-keeper reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-20
- Sources: `src/keri/core/keeping.ts`, `test/core/keeping.test.ts`, `test/core/manager.test.ts`
- Binary fields: none. Keys, signatures, and digests are qualified Base64; the one sealed value is
  recorded by what it opens to.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/keri_keeping.mjs --write   # regenerate
node tools/reference-vectors/keri_keeping.mjs --check   # verify determinism
```

## Determinism, and what could not be pinned

A salty keeper hardcodes the **production** Argon2 profile, so every key in `salty_walk` and
`salty_variants` costs a real 64 MiB derivation. That is the point: those are the keys a deployed
client holds, and the generator takes a few seconds because of it.

Three things are not reproducible and are handled explicitly:

- **A randy keeper's keys are random.** `randy_shape` records the *shape* a randy keeper produces —
  counts, codes, the code its sealed keys carry, whether a rotation promotes the committed-to keys
  — rather than any key.
- **A sealed box draws a fresh ephemeral key each call.** The salty keeper's `sxlt` is recorded by
  the salt it *opens to*, obtained by handing it back to the reference's own decrypter.
- **The group cases delegate to a mocked member keeper.** The reference's own unit test does the
  same, so `member_keeper_called_with` records the exact arguments the group hands down — which is
  the observable behavior, since the group has no keys of its own.

## Contents

`salty_walk` is a complete walk: the stored parameters before and after inception, the key material
each step produces, all five signature forms, two rotations with the key index after each, and the
signature the rotated keys produce. `salty_variants` pins the path arithmetic across six
configurations — the default stem, an explicit stem, non-transferable keys, three keys, and each
index offset.

`group.cases` records the two cases the pinned `keeping.test.ts` asserts plus a third position, and
`group.params` records that the reference's `params()` returns three fields while its declared
interface names one. `factory` records how both entry points dispatch and four rejections.

## Reference behavior recorded as deliberate divergences

- **A rotation loses the derivation code** — recorded in the Roadmap 4.2 fixture, and the reason a
  keeper's stored path carries a cost profile rather than a code here.
- **A randy keeper discards the code lists it just defaulted.** The constructor computes `icodes`
  and `ncodes` from the counts and then overwrites both with the raw arguments. Counts are the
  input in Rust, so there is no list to discard.
- **`get` builds a randy keeper with no next codes at all**, so a keeper loaded from a record
  commits to nothing until a rotation supplies it. Rust takes the counts from the lengths of the
  stored sealed key lists.
- **A salty rotation keeps the inception count as its stride.** `rotate` sets `ncodes` but never
  `icodes`, so the key index advances by the inception count even when the rotation changes how
  many keys there are. Reproduced: the stride is what the stored key index means.
- **The key a salty keeper seals its salt to depends on the identifier's transferability**, so two
  identifiers under one passcode seal to different keys. Reproduced, and it round-trips because the
  transferability is stored alongside the sealed salt.
- **Every keeper publishes its private signers** as a public field, which `clienting.ts` reads to
  build an authenticator. Signing happens inside the keeper here; `expose_signers` names the one
  deliberate export.
- **Every method is `async` and none of them awaits anything.** No keeper performs I/O, and
  `ARCHITECTURE.md` §4.4 forbids this crate an async runtime, so the Rust trait is synchronous.
- **`Unknown algo` and `No algo specified` are unrepresentable here.** The request enum has four
  variants, and a Roadmap 4.1 identifier record names exactly one key manager or does not decode.

Rust tests consume the checked-in fixture and require neither Node nor network access.
