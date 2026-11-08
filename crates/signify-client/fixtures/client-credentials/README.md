# Credentials endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-25
- Sources: `src/keri/app/credentialing.ts`, `src/types/keria-api-schema.ts`,
  `test/app/credentialing.test.ts`, `test/app/test-utils.ts`, `test/app/clienting.test.ts`
- Binary fields: none. Paths and bodies are exact text, with each sealed salt masked (see below).

Generate and verify from the repository root after installing the pinned references:

```bash
npm ci --prefix tools/reference-vectors
node tools/reference-vectors/client_credentials.mjs --write   # regenerate
node tools/reference-vectors/client_credentials.mjs --check   # verify determinism
```

## Determinism

Two things are pinned. The **clock**, because `issue` and `revoke` both default their timestamp to
`new Date().toISOString()`, so nothing either of them derives is reproducible without it — the
credential's SAID, the issuance event's SAID, and the anchoring interaction event all commit to it.
And the **agent's key**, as the `client-lifecycle` fixture pinned it, so every response
authenticates.

**Sealed salts are masked.** A salty keeper seals its salt with a fresh ephemeral key each time, so
every `sxlt` in a recorded body or record is replaced with `<SXLT>` and the salt it opens to is
recorded beside it. The Rust test seals that salt again with the same controller key before
reloading a keeper, and masks its own bodies before comparing — so the comparison is byte for byte
everywhere except the ciphertext, which cannot be pinned by construction.

`issue` and `revoke` sign with a real keeper at the reference's production Argon2 profile, so the
generator takes several seconds.

## What the evidence is

This ports `Credentials.{list,get,delete,state,issue,revoke}` together with the
`CredentialFilter` declaration `list` sends as a body.

**The pinned unit tree exercises this family properly**, which the registries' and schemas' did not:
the single `Credentials` case in `test/app/credentialing.test.ts` calls all six methods and asserts
each path, each method, and — for `issue` and `revoke` — the fields of each body. What it does not
assert is any exact *bytes*: both of those methods read the clock, so the test checks fields.

So the generator drives the reference through that test's own mocks. `mockGetAID` and
`mockCredential` are read out of `test/app/test-utils.ts` by the reference's own compiler and are
what every lookup answers with, which makes every identifier, registry, and credential value here
one the reference's own suite asserts against. `globalThis.fetch` is replaced by a recorder that
signs its answers as a KERIA agent would, and the real client is walked through boot, connect, and
every call.

`pinned_confirmations.unit_test_assertions` is the anchor: **every value the pinned test asserts,
recomputed from what the reference produced here**, with the generator failing if any of them stops
reproducing. That includes the revocation the test performs on `lastBody.acdc.i` — the credential's
*issuer*, which is the identifier's own prefix rather than a credential SAID — which is why one
driven call revokes exactly that.

**One field is added to the reference's own mock.** `mockGetAID` carries no `icp_dt`, which the
generated `HabState` declares required, so the record would not decode on the Rust side at all. The
generator adds one and records that it did; nothing derived reads the field, so no recorded byte
changes. The omission is itself pinned in `mock_records.shortfall`, beside the larger finding that
`mockCredential` is missing **seven of the eleven** fields the `Credential` schema declares, carries
two the schema does not, and is handed to a caller as a credential regardless.

## Contents

- `declarations` pins the six methods' paths and bodies, the four `list` defaults, the two
  `saidify` expressions inside `issue`, the registry lookup inside `revoke`, the
  `CredentialFilter`/`IssueCredentialResult`/`RevokeCredentialResult` interfaces, the class's own
  member list, and the generated `Credential` schema literal — each read from the reference's own
  syntax tree, so a drift fails a test rather than passing silently.
- `mock_records` pins the identifier and credential records every lookup answers with, a
  well-formed credential record beside the reference's own, one carrying no registry at all, and
  the schema shortfall of both mocks.
- `calls` pins sixteen requests: three listings, four reads, a delete, two state reads, three
  issuances, and three revocations — including one of each with names the path does not encode.
- `renamed_by_agent` records `issue` addressing the alias the **agent** answered with.
- `issue_establishment_only` and `revoke_without_registry` record the reference's two refusals and
  how much work each had already done.
- `pinned_confirmations` pins the unit test's file set, its published paths and identifiers, the
  accessor assertion, a 117-file usage scan, and the assertion map described above.
- `reference_quirks` pins ten behaviours, each with what the reference does and what this port does
  instead.

## Reference behavior recorded as deliberate divergences

- **No path encodes its names.** Five of the six methods interpolate raw — seven dynamic values in
  all — so `get('E/../identifiers?x=1#y')` addresses `/credentials/E/../identifiers?x=1#y`, three
  extra segments plus a query and a fragment; `state('a/b','c/d')` addresses `/registries/a/b/c/d`;
  and `revoke('a/b','c/d')` addresses `/identifiers/a/b/credentials/c/d`. Request authentication
  signs `@path`, so each also changes what the signature commits to. **Refused by construction**: a
  SAID and a registry identifier are validated types, and `ResourcePath` encodes an alias exactly
  once.
- **`issue` addresses the agent's own alias.** It posts to `/identifiers/${hab.name}/credentials`,
  where `hab` is the record the **agent** answered with — so a server answering under a different
  alias chooses both the resource the credential is written to and the path the request's signature
  covers. The fixture records exactly that happening. Here the caller's own alias addresses the
  resource.
- **`issue` never checks the issuer it was given.** The credential's issuer is `args.i ?? hab.prefix`
  and nothing compares a supplied one against the identifier whose keeper signs the anchor, so a
  credential can claim an issuer whose key event log contains no anchor for it — unresolvable by any
  verifier. The fixture records one built that way. Here the credential arrives already built, so
  its issuer is compared with the identifier anchoring it and a mismatch is a typed refusal before
  anything is signed.
- **`revoke` reads its registry from the server.** It fetches the credential back to learn both the
  registry the revocation commits to and the prior digest it supersedes, so a revocation cannot be
  built offline and both values are the agent's rather than the caller's. Its sequence number is the
  literal `'1'`, wrong in any registry whose log has moved on. Here the revocation event is an input
  built by the `revocation` module, where all three are ordinary values defaulting to the
  reference's, and the endpoint looks up nothing.
- **An unqualified SAID becomes a credential identifier.** `revoke('a/b','c/d')` writes
  `"i":"c/d"` into the revocation event itself, which is recorded here and is unrepresentable in
  Rust, because `Said` is validated before it is anything.
- **`get` returns two unrelated types.** One method, a boolean second parameter, four overload
  signatures, and either `res.json()` or `res.text()`. Here they are two methods, `get` and
  `get_cesr`, because the answers are different types and a boolean mode argument is not a shape
  this port's API conventions allow.
- **A CESR answer is repaired rather than refused.** `res.text()` decodes with replacement, so a
  stream carrying an invalid byte comes back with U+FFFD substituted into it and reads as a valid —
  but different — stream. Here a body that is not UTF-8 is a typed failure.
- **The answer is cast rather than decoded.** `get`, `list`, and `state` all return `res.json()`
  cast to a generated type. The reference's own `mockCredential` proves the gap and is shown refused
  here, with a well-formed record beside it shown accepted.
- **A listing writes every field it was not given.** All four are written whether or not the caller
  supplied them, so an unfiltered listing sends `{"filter":{},"sort":[],"skip":0,"limit":25}` — the
  limit is a silent default rather than an absent one. Reproduced exactly.
- **A delete sends no body.** `delete` calls `fetch` with three arguments, so `data` is `undefined`
  and `JSON.stringify(undefined)` is `undefined`. Reproduced.
- **An establishment-only issuer throws a string**, and `revoke` declares the same `estOnly` flag
  twice with `var` in one scope before doing the same. Here it is a typed
  `ClientError::EstablishmentOnlyIssuer` checked before anything derives.

Rust tests consume the checked-in fixture and require neither Node nor network access. They derive
real keys at the production Argon2 profile, which is why they are slower than the reading families.

One wire-shape note. The reference's mocks spell the anchoring sequence number of a credential
status (`status.a.s`, and `a.s` of a state answer) as text, which is what `keria-api-schema.ts`
declares; KERIA itself writes a number, and the record types follow KERIA. The tests convert that
one field before a scripted agent answers with a mock, so the fixture stays exactly what the
generator wrote.
