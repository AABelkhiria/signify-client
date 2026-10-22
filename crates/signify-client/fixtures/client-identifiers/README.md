# Identifier endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-24
- Sources: `src/keri/app/aiding.ts`, `src/keri/app/clienting.ts`, `test/app/aiding.test.ts`
- Binary fields: none. Paths, headers, and bodies are exact text; a body is the exact string
  `SignifyClient.fetch` would `JSON.stringify`, with each sealed salt masked (see below).

Generate and verify from the repository root after installing the pinned references:

```bash
npm ci --prefix tools/reference-vectors
node tools/reference-vectors/client_identifiers.mjs --write   # regenerate
node tools/reference-vectors/client_identifiers.mjs --check   # verify determinism
```

## Determinism

Two things are pinned to make this reproducible.

The **clock**, as the `http-auth` and `client-lifecycle` fixtures pinned it, so the signature
`createSignedRequest` produces is exact rather than masked.

**Sealed salts are masked.** A salty keeper seals its salt with a fresh ephemeral key on every
call, so its `sxlt` differs run to run. Every occurrence in a recorded body is replaced with
`<SXLT>` and the salt it opens to is recorded beside it in `sxlt_opens_to`. The Rust test does the
same to its own body before comparing, and asserts each sealed value opens to the recorded salt —
so the comparison is byte for byte everywhere except the ciphertext, which cannot be pinned by
construction. The `keri-controller` fixture established that convention.

**Randy material is recorded by shape.** Random keys cannot be pinned, so `randy_shape` and
`randy_reload_shape` record the field set, counts, and the transferability written back rather than
any value.

Key material derives at the reference's own production Argon2 profile, so the generator takes
several seconds.

## What the evidence is

This port covers the HTTP half of `aiding.ts` — everything `list`, `get`, `update`, `create`,
`interact`, `rotate`, `addEndRole`, `addLocScheme`, and `members` do around the artifacts
the `keri-aiding` fixture already verified — together with the `EventResult` class and
`SignifyClient.createSignedRequest`, which reaches an identifier's keeper.

As with the `client-operations` fixture, this one **drives the reference** rather than
re-expressing it. `Identifier` takes an `IdentifierDeps` — one `fetch` method, a `pidx`, and a
manager — so the generator hands the real class a recorder, exactly as the pinned `aiding.test.ts`
does, and every request it makes is captured.

`createSignedRequest` needs a whole connected client, so the second half of the generator replaces
`globalThis.fetch` and pins the agent's key as the `client-lifecycle` fixture did, and drives the
real `SignifyClient` through `connect` and then the signing call.

`declarations` holds the nine path expressions, the `Range` header, the two body literals, the
`pidx` increment, the `EventResult` members, and all three keeper `params()` literals, read out of
the reference's own syntax tree. `pinned_confirmations` closes the loop against the test suite:
every `/identifiers…` path `aiding.test.ts` asserts is produced here by the reference's own methods.

## Contents

- `calls` pins twenty-four requests: three listings, four reads, two updates, six creations, two
  interactions, two rotations, four authorization replies, and one member listing. Each carries the
  exact path, method, headers, and body.
- `group_creation` pins the three member records a group creation was built from, in the schema's
  own field order — which is what a KERIA response carries and what a group's request body embeds
  verbatim.
- `randy_shape` and `randy_reload_shape` pin what a randy body looks like on creation and on
  reload.
- `signed_request` pins both forms of `createSignedRequest`, with every header including the
  signature.
- `reference_quirks` pins thirteen behaviours, each with what the reference does and what this port
  does instead.

## Reference behavior recorded as deliberate divergences

- **Only two of seven paths encode their name.** `get` and `update` call `encodeURIComponent`;
  `interact`, `rotate`, `addEndRole`, `addLocScheme`, and `members` concatenate the alias raw, so
  `interact("a/b", …)` addresses `/identifiers/a/b/events` — a different resource, and, because
  request authentication signs `@path`, a different signed path. **Refused by construction**: the
  request builder's `ResourcePath` encodes every dynamic component exactly once and offers no way
  to skip it.
- **A listing's window is unvalidated.** `list(start, end)` interpolates both into
  `aids=${start}-${end}` with no checks at all. The request builder's `ItemRange` carries unsigned
  integers and validates `start ≤ end` at construction, so an unsatisfiable window is
  unrepresentable.
- **An absent `content-range` reads as `{0, 0, 0}`**, so a listing carrying entries reports a total
  of zero. **Not reproduced**: the window is an `Option`, which the request builder already decided.
- **`requireKeyState` is a boolean parameter with three overloads**, and throws
  `No key state for identifier <name>`. Two methods here instead: `get` returns an `AcceptedHab`
  and `get_any` returns the shared `Hab` type, whose pending variant has no key state to demand.
- **A body's optional fields are dropped rather than nulled.** The literal always names `proxy`,
  `smids`, and `rmids`, but `JSON.stringify` drops an `undefined` value. Reproduced exactly: a
  non-group creation without a proxy sends four fields and a group creation sends seven.
- **A rotation always writes both member lists** — empty for a single-signature identifier — where
  a creation omits them, because `rotate` defaults `states`/`rstates` to `[]` before mapping them.
  Reproduced: the asymmetry is what the agent receives.
- **A non-transferable record stores the prefix code as its digest code.** `create` reuses one
  `dcode` variable for the prefix derivation and for the stored digest code, so the record names
  `B` in the field that says which digest algorithm commits to the next keys. **Not reproduced**:
  the `keri-aiding` fixture recorded this and stores the digest actually used (`E`). This is the
  **only field in any recorded body that differs**, and the cross-language test asserts it is
  exactly one field.
- **A randy keeper writes a field the schema does not declare.** `params()` returns
  `{nxts, prxs, transferable}` while `RandyKeyState` declares only the first two; on reload the
  reference reads transferability from the identifier's *prefix* instead. Reproduced from the same
  source: the request's transferability when creating or rotating, the prefix when interacting.
- **`pidx` is shared mutable state on the client**, incremented after signing — so two concurrent
  creations read the same value and derive the same identifier's keys. **Not reproduced**: the
  index is an atomic counter reserved before any key derives. A creation that fails consumes its
  index, which the reference would have reused; that leaves a gap and nothing else.
- **`EventResult.op()` re-reads its response**, so a second call throws `Body has already been
  read`. Here the body is owned bytes and `operation()` can be called as often as a caller likes.
- **`createSignedRequest` mutates the caller's `RequestInit` in place.** The Rust method takes a
  built request and returns a new one.
- **`test-utils.ts`'s `createMockIdentifierState` names two key managers**, writing
  `extern: extern ?? {}` beside the algorithm's own field. The shared `Hab` type requires exactly
  one, so the reference's own test utility produces records this port refuses; the records here
  name one, as a KERIA response does.

Rust tests consume the checked-in fixture and require neither Node nor network access. They derive
real keys at the production Argon2 profile, which is why they are slow.
