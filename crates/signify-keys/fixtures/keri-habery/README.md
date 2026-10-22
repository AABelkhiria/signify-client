# KERI Habery reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-21
- Sources: `src/keri/app/habery.ts`, `test/app/habery.test.ts`
- Binary fields: none. Keys, digests, and identifiers are qualified Base64; events are recorded as
  their exact serialized text.

Generate and verify from the repository root after installing the pinned references:

```bash
npm ci --prefix tools/reference-vectors
node tools/reference-vectors/keri_habery.mjs --write   # regenerate
node tools/reference-vectors/keri_habery.mjs --check   # verify determinism
```

## Determinism

`makeHab` hardcodes the **production** Argon2 profile (`temp: false`), so every key here costs a
real 64 MiB derivation and the generator takes several seconds. That is the point: these are the
keys and events a deployed client actually produces. All key material derives from the pinned unit
test's own public salt and passcode; no secret is stored. The three witness prefixes in
`provenance.witnesses` are *inputs only*, derived cheaply from the same salt.

A named salty Habery holds only one habitat per transferability — the salty derivation path drops
the prefix index under a non-empty stem — so every `habitat_cases` entry builds a fresh Habery.

## Contents

- `pinned_unit_tests` records both `habery.test.ts` cases byte-complete: the encryption identifier
  and full inception event for the salt-plus-passcode case, and the derived signer, verifier, and
  event for the passcode-as-salt case.
- `habitat_cases` pins thirteen complete inception events across the argument space: defaults,
  non-transferable, multi-key, explicit and propagated thresholds, witnesses with and without an
  explicit `toad`, configuration traits with anchored data, delegation, the empty registry name,
  and a second stem.
- `pidx_does_not_change_a_named_habitat` pins that a registry started at `pidx: 4` produces the
  same habitat as one started at zero, because the named salty path drops the prefix index.
- `mixed_transferability` pins the only reachable way one named salty registry holds two habitats:
  the same raw key under both transferability codes.
- `rejections` pins eight reference-refused inputs with their exact error messages.

## Reference behavior recorded as deliberate divergences

- **The `tier` argument is never read.** `HaberyArgs` declares it and the constructor never
  destructures it. Rust has no such argument — a salt already knows its tier.
- **A passcode alongside a seed is ignored without even its length check.** Rust makes the
  combination unrepresentable: a passcode and a seed are different build methods.
- **A duplicate name overwrites the map entry** while the manager keeps both identifiers, losing
  the first habitat's handle but not its keys. Reachable only through an empty-name registry, whose
  empty stem keeps the prefix index in the path. Rust refuses with `DuplicateHabitat`.
- **A transferable habitat with `ncount: 0` commits to an unsatisfiable threshold.** The default
  `nsith` formula `max(1, ceil(ncount / 2))` never yields zero, so the event carries `nt: "1"` over
  an empty next-key list, which no rotation can ever satisfy. Rust refuses; an explicit zero next
  threshold still abandons the identifier cleanly.
- **Randy habitats are unreachable.** `Manager.incept` reads `this.salt` unconditionally, and with
  a decrypter present the getter decrypts the stored global salt a randy manager never has, so
  every passcode-only Habery throws `Empty Material` before creating a single key — although the
  randy creator itself never uses the salt. Rust reads a salt only for the salty algorithm, so a
  randy registry produces valid habitats; their shape is asserted by Rust tests, since the
  reference cannot emit one to pin.

Rust tests consume the checked-in fixture and require neither Node nor network access.
