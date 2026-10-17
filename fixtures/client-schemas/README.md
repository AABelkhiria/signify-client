# Schema endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-24
- Sources: `src/keri/app/credentialing.ts`, `src/types/keria-api-schema.ts`,
  `test/app/clienting.test.ts`, `test-integration/credentials.test.ts`
- Binary fields: none. Paths are exact text; the answers are exact JSON.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_schemas.mjs --write   # regenerate
node tools/reference-vectors/client_schemas.mjs --check   # verify determinism
```

## Determinism

The clock and the agent's key are pinned, as the `client-lifecycle` fixture pinned them. Nothing
here derives an identifier key, so the generator is fast.

## What the evidence is

This port covers `Schemas.{get,list}` — two reads, one addressing a SAID and one a constant path.

A scan of every pinned `.ts` file finds this family in exactly four, and **no unit test exercises
either call**: `test/app/clienting.test.ts` asserts only that `client.schemas()` is a `Schemas`.
The real usage is `test-integration/credentials.test.ts`, which reads both vLEI schemas by SAID,
asserts each answer's `$id`, then lists and asserts a count of two. The generator records that file
set and fails if it changes.

So the vectors are the reference **driven directly** — `globalThis.fetch` replaced with a recorder
that answers and signs as a KERIA agent would — using the two SAIDs that integration test uses, so
the recorded paths are the ones a real deployment sees.

## Contents

- `calls` pins six requests: both schema reads, a SAID that would escape the path, a listing, an
  empty listing, and an answer of the wrong shape.
- `pinned_confirmations` pins the four files that name the family and what each of them checks.
- `reference_quirks` pins five behaviours, each with what the reference does and what this port does
  instead.

## Reference behavior recorded as deliberate divergences

- **The SAID is not encoded.** `get` interpolates it straight into the path, so
  `get("E/../schema?x=1#y")` addresses `/schema/E/../schema?x=1#y` — three extra segments, a query,
  and a fragment from one argument, and request authentication signs `@path`. **Refused twice
  over**: the argument is a validated `Said`, and the request builder would encode it exactly once
  even if it were not. A qualified digest's alphabet is URL-safe Base64, so every real SAID reaches
  the path byte-identical to what the reference sends.
- **The segment is singular.** Both addresses are `/schema` while the class, the accessor, and the
  module are plural. Reproduced exactly, and pinned as a named constant so the plural module
  name cannot drift into the path.
- **The answer is never validated.** `get` returns `res.json()` cast to `Schema`, so an object
  carrying only `$id` — missing all nine other required fields — is handed to the caller as a
  schema. **Decoded here**: such an answer is `ClientError::Api`, and the recorded one is proven
  refused.
- **A listing carries no input.** No filter, no range, no paging, so an agent holding many schemas
  returns all of them in one body. Reproduced; the response is bounded only by the transport's
  limit, which is recorded as a limitation rather than a filter this port invents.
- **Nothing checks the schema came back under the SAID asked for.** The reference's own integration
  test makes that check at the call site — `assert.equal(issuerQviSchema.$id, QVI_SCHEMA_SAID)` —
  but `Schemas.get` does not, so a misrouted or substituted answer is returned unchallenged.
  **Reproduced rather than fixed**, and a test demonstrates it: asking for one SAID and answering
  with another succeeds on both sides. Inventing the check would diverge from the reference for a
  guarantee only digest verification can actually give, which is `keri-protocol::said`'s job and not
  an endpoint's. The method's own documentation tells a caller to make it.

Rust tests consume the checked-in fixture and require neither Node nor network access.
