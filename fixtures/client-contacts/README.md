# Contact endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-25
- Sources: `src/keri/app/contacting.ts`, `src/types/keria-api-schema.ts`,
  `test/app/contacting.test.ts`, `test-integration/utils/test-util.ts`
- Binary fields: none. Paths and bodies are exact text; the answers are exact JSON.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_contacts.mjs --write   # regenerate
node tools/reference-vectors/client_contacts.mjs --check   # verify determinism
```

## Determinism

The clock and the agent's key are pinned, as the `client-lifecycle` fixture pinned them. Nothing
here derives an identifier key, so the generator is fast.

## What the evidence is

This ports `Contacts` from `src/keri/app/contacting.ts` — five methods over one resource, two of
which write an open bag of caller-chosen fields as the request body. The `Challenges` half of the
same file is ported separately.

The pinned `contacting.test.ts` has one `Contacts` case, and it is **unusually complete for this
port**: it asserts all five paths, all five HTTP methods, both write bodies field for field, and
that a delete carries no body at all. So the vectors are the reference **driven directly** —
`globalThis.fetch` replaced with a recorder that answers and signs as a KERIA agent would — through
exactly those calls, and `pinned_confirmations` recomputes every one of those assertions.

Outside that case the family is used three times in the whole pinned tree, all of them `list`: twice
with no arguments at all, and once through `getOrCreateContact`, whose filter value is a **regular
expression**. Both shapes are recorded.

## Contents

- `calls` pins sixteen requests: seven listings covering every argument combination including both
  halves of a dropped filter, a read, an escaping prefix, three writes, an update, a delete, and two
  answers of the wrong shape.
- `declarations` pins all five path expressions, both listing guards, the `undefined` a delete sends
  where the writes send `info`, the `ContactInfo` interface, and the `Contact` schema entry — all
  read from the reference's own syntax tree. The `Contacts` class's member list is asserted, so the
  split between this endpoint and the challenges endpoint is machine-checked.
- `pinned_confirmations` pins the four unit-test assertions, the two addresses and five methods it
  covers, the info it sends, and the integration helper's own call.
- `reference_quirks` pins eight behaviours, each with what the reference does and what this port does
  instead.

## Reference behavior recorded as deliberate divergences

- **An unfiltered listing addresses a bare question mark.** `path` is
  `'/contacts' + '?' + params.toString()`, concatenated unconditionally, so `list()` sends
  `/contacts?`. This port sends `/contacts`, on the operations endpoint's three grounds applied
  again — the **signed path is identical** because request authentication strips the query, an
  empty query is not a distinguishable resource, and the request builder cannot spell a bare `?`
  without a knob whose only users would be this call and `Operations.list`. The KERIA integration
  matrix owes it a live confirmation.
- **Half a filter is silently dropped.** The guard is
  `filterField !== undefined && filterValue !== undefined`, so naming one half without the other
  drops **both** — the caller asks for a filtered listing and is answered with an unfiltered one, a
  mistake that succeeds. **Unrepresentable** here: the two are one `ContactFilter`. The group stays
  independent, because it genuinely is.
- **The prefix is not encoded.** All four single-contact paths are `'/contacts/' + pre`, and the
  `http-request-response` fixture already recorded `contacts().delete("a/b")` reaching two segments.
  **Refused twice over**: the argument is the validated `IdentifierPrefix`, and the builder would
  encode it exactly once regardless.
- **The filter value *is* encoded.** The query is built with `URLSearchParams` rather than by
  interpolation, so a value holding `&` is encoded — one of the few dynamic values the reference
  encodes anywhere, and the opposite of what the `client-oobis` fixture found in `Oobis.get`.
  **Reproduced exactly**, so this is a place the two already agree.
- **A delete carries no body.** `delete` passes `undefined` where the writes pass `info`, and the
  pinned test asserts the request's body is `undefined` rather than an empty object. Reproduced.
- **The info is an open bag.** `ContactInfo` is `{[key: string]: unknown}` handed straight to
  `JSON.stringify`, so the field order is the caller's and any shape is accepted. Here it is an
  **ordered document** — `Sad`, which is what the identifier endpoint settled a request body is —
  so a caller controls the bytes exactly. One narrowing rides along and is recorded rather than
  worked around: `Sad`'s number space admits an exact integer and not a float.
- **The answers are cast rather than decoded.** All four reading methods return `res.json()` cast to
  `Contact` or `Contact[]`. **Decoded here**, and both recorded wrong-shaped answers are proven
  refused; `id` is the one field the schema requires, and every other field the agent sends survives
  a round trip through the shared API types' open map.
- **A listing has no paging.** No range, no limit, no cursor, where the identifier endpoint's
  listing at least accepts a `Range` header. Reproduced; the response is bounded only by the
  transport's limit, and the benchmark measures what that costs at 256 contacts.

Rust tests consume the checked-in fixture and require neither Node nor network access.
