# KERI identifier-artifact reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-22
- Sources: `src/keri/app/aiding.ts`, `test/app/aiding.test.ts`
- Binary fields: none. Keys, digests, events, and signatures are qualified Base64 or exact
  serialized text; sealed salts are recorded by what they open to, and randy material by shape.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/keri_aiding.mjs --write   # regenerate
node tools/reference-vectors/keri_aiding.mjs --check   # verify determinism
```

## Determinism

The generator drives the reference's `Identifier` class exactly as the pinned `aiding.test.ts`
does — through a mock client whose fetch records each request body — with every keeper derived
from the pinned test's own passcodes at the production Argon2 profile, so events and signatures
are deterministic. Sealed salts (`sxlt`) draw a fresh ephemeral key per call and are recorded by
what they open to through the reference's own decrypter; the Rust test never compares them
byte-for-byte. Random (randy) keys cannot be pinned and are recorded by shape.

## Contents

- `creations` pins six complete inception request bodies — the pinned test's default,
  non-transferable, and multisig vectors byte-complete, plus witnessed, delegated-with-data, and
  weighted-threshold cases — each with its exact event text, signatures, and resolved keeper
  parameters.
- `group_creation` pins a deterministic three-member group: the event whose next digests come
  from the rotation states, the member-position signature with no prior index, and the `smids`/
  `rmids` lists.
- `interactions` pins the pinned test's seal-list and hexadecimal-sequence cases, and the
  `[null]` anchor a data-less interact commits to.
- `rotations` pins five rotations: the pinned default and hexadecimal-sequence vectors, a
  delegated state rotating with `drt`, witness cuts/adds with an explicit threshold, and an
  explicit next threshold over two keys.
- `replies` pins both authorization replies with fixed timestamps: `/end/role/add` with and
  without an endpoint, and `/loc/scheme` with explicit and defaulted arguments.
- `rejections` pins a witnessed creation without a threshold and an unregistered external module.

## Reference behavior recorded as deliberate divergences

- **The non-transferable rewrites are silent.** `create` forces `ncount = 0`, `nsith = 0`, and
  `dcode = Ed25519N` whatever was passed; the fixture proves the overridden arguments change
  nothing. Rust keeps the forced values as defaults and refuses explicit contradictions.
- **A data-less interact anchors `[null]`** — a seal that seals nothing, committed into the SAID.
  Unrepresentable in Rust, where an anchor is a field map; an anchor-less interaction writes
  `a: []`.
- **`create` wraps `data` unconditionally**, so a list argument nests a list inside the anchors.
  Unrepresentable: the anchor is one field map.
- **`pre`, `keys`, and `ndigs` are accepted and never read** by `create`; no equivalent exists.
- **The reply timestamp defaults to the system clock**; Rust requires it, as the reply event builder
  does.
- **A non-transferable identifier's stored `dcode` is `B`** — the basic prefix code written into
  the field that names the *digest* algorithm, because `create` reuses one variable for both. The
  digest list it would govern is empty either way; Rust records the digest it actually uses (`E`),
  and its factory refuses to reload a record whose `dcode` is not a digest code.

Rust tests consume the checked-in fixture and require neither Node nor network access.
