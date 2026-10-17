# Registry endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-24
- Sources: `src/keri/app/credentialing.ts`, `test/app/registry.test.ts`,
  `test/app/clienting.test.ts`, `test/app/credentialing.test.ts`
- Binary fields: none. Paths and bodies are exact text, with each sealed salt masked (see below).

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_registries.mjs --write   # regenerate
node tools/reference-vectors/client_registries.mjs --check   # verify determinism
```

## Determinism

Three things are pinned. The **clock** and the **agent's key**, as the `client-lifecycle` fixture
pinned them. And the **nonce**: `vdr.incept` defaults it to `randomNonce()`, so without pinning it
the registry identifier — which is the inception's own SAID — could not be reproduced. One case
deliberately omits it and records the generated shape instead.

**Sealed salts are masked.** A salty keeper seals its salt with a fresh ephemeral key each time, so
every `sxlt` in a recorded body is replaced with `<SXLT>` and the salt it opens to is recorded
beside it. The Rust test does the same to its own body before comparing, so the comparison is byte
for byte everywhere except the ciphertext, which cannot be pinned by construction.

Key material derives at the reference's production Argon2 profile, so the generator takes several
seconds.

## What the evidence is

This port covers `Registries.{list,create,createFromEvents,rename}` and `RegistryResult`.

**The pinned unit tree does exercise this family**, in `test/app/registry.test.ts` — two cases that
publish an exact `vcp` and `ixn` pair, the establishment-only refusal, and the path
`/identifiers/a name/registries`, with a literal space in it.

**Those two event vectors are not reproducible here.** Their issuer prefix is the literal
`'hab prefix'`, which no qualified `IdentifierPrefix` can be, so they are recorded verbatim in
`pinned_confirmations` and the input is proven refused on the Rust side — the arrangement exchange
message construction established for exactly this situation. Their nonce, `''`, *is* representable,
so the issuer is the only obstacle and the test says so.

Byte parity therefore comes from the reference **driven directly**: `globalThis.fetch` is replaced
with a recorder that answers and signs as a KERIA agent would, the identifier lookup `create`
performs is answered with a deterministic record, and the real client is walked through boot,
connect, and every call. `credentialing.test.ts` has no registry case and `clienting.test.ts`
asserts only the accessor's type; the generator checks all three files and fails if that changes.

`create` is the only call in the crate that builds **two** events: the registry's own inception
and the interaction event anchoring it in the issuer's log.

## Contents

- `pinned_confirmations` pins the two events `test/app/registry.test.ts` publishes, its asserted
  path, its refusal message, and the two inputs that make the events unreproducible.
- `calls` pins six requests: two listings, two creations, and two renames — one of each with names
  the path does not encode.
- `identifier_records` pins the two identifier records `create` looks up, one of them
  establishment-only. Their sealed salts are masked like the bodies', and the Rust side seals the
  recorded salt again with the same controller key before reloading a keeper from the record.
- `generated_nonce_shape` records what a creation looks like when the nonce is drawn rather than
  supplied.
- `establishment_only` records the reference's refusal, and how much work it had already done.
- `reference_quirks` pins six behaviours, each with what the reference does and what this port does
  instead.

## Reference behavior recorded as deliberate divergences

- **No path encodes its names.** All three concatenate raw, and a rename carries *two* — so
  `rename('a/b','c/d',…)` addresses `/identifiers/a/b/registries/c/d`, four segments where two were
  meant. The pinned unit test **asserts the unencoded form itself**, with a literal space in
  `/identifiers/a name/registries`, so this is confirmed from the reference's own suite rather than
  argued from this port's side. **Refused by construction**, as the identifiers endpoint decided
  for the identifier family.
- **An establishment-only issuer is built and then thrown away.** `create` pushes the `EO` trait
  into the registry configuration, builds the whole registry inception from it, and *only then*
  throws `establishment only not implemented` — after the identifier lookup has already gone out.
  Here it is a typed refusal checked first, which is what credential issuance decided for an
  establishment-only issuer: no derivation, no second request.
- **`noBackers` defaults to true while `baks` and `toad` sit beside it.** A caller who names
  backers without also clearing the flag gets a registry declaring `NB` — configured to have no
  backers — with their backers written into it anyway. Here `RegistryBacking` makes naming backers
  *be* the choice, so the flag and the list cannot disagree.
- **`RegistryResult` holds the fetch promise, not its response.** `create` resolves before the
  `POST` does, so a rejected `POST` is an unhandled rejection unless the caller awaits `op()`. Here
  the submission is awaited and a failure is a failure at the call site; the artifacts are still
  available beside it, and the answer can be read as often as a caller likes.
- **The anchor seals the registry to itself.** The interaction event anchors
  `{i: regser.pre, s: '0', d: regser.pre}` — the registry identifier in both the identifier and the
  digest slot, because a registry inception's SAID *is* its prefix. Reproduced exactly.
- **`create` resolves its keeper twice.** It resolves once to sign the interaction event and again
  inside `createFromEvents` to write the key-manager parameters, so a salty identifier runs its
  Argon2 derivation twice per registry. Resolved once here, which changes no byte and halves the
  cost.

Rust tests consume the checked-in fixture and require neither Node nor network access. They derive
real keys at the production Argon2 profile, which is why they are slower than the reading families.
