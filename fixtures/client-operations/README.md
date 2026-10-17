# Operations endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-23
- Sources: `src/keri/app/coring.ts`, `test/app/coring.test.ts`
- Binary fields: none. Paths and messages are exact text; operation documents are exact JSON.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_operations.mjs --write   # regenerate
node tools/reference-vectors/client_operations.mjs --check   # verify determinism
```

## Determinism

Nothing here derives a key or reads a clock, so the generator is instant and every value is exact.

## What the evidence is

This port covers `Operations.get`, `.list`, and `.delete`, together with the failure surfacing
`throwIfFailed` performs. `wait` — the polling loop — is `client-operation-wait`'s; the `http-retry`
fixture already pinned its delay schedule by executing it.

As with the IPEX artifact and `client-lifecycle` fixtures, this one **drives the reference** rather
than re-expressing it. `Operations` takes an `OperationsDeps` — one `fetch` method — so the
generator hands it a recorder, exactly as the pinned `coring.test.ts` does, and every request the
real class makes is captured with its path, method, and body.

`declarations` holds the three path expressions, the query construction, the whole of
`throwIfFailed` and `hasDepends`, and the fourteen-member `Operation` union, read out of the
reference's own syntax tree. `pinned_confirmations` closes the loop against the test suite: the
three paths `coring.test.ts` asserts are all produced here by the reference's own methods.

`throwIfFailed` is private, so its two messages are reached through `wait` on an
already-completed operation — which returns immediately without polling, and is recorded doing so.

## Contents

- `calls` pins seven: a get answered with a pending operation and with a completed one, an
  unfiltered list, a filtered one, a filter needing encoding, a delete, and a name needing
  encoding.
- `failures` pins both failure messages — with and without structured details — and the fact that
  an already-completed operation is returned unchanged.
- `reference_quirks` pins six behaviours, each with what the reference does and what this port does
  instead.

## Reference behavior recorded as deliberate divergences

- **An unfiltered list addresses `/operations?`.** `list()` builds its query with
  `URLSearchParams` and interpolates `?${params.toString()}` unconditionally, so a list with no
  filter ends in a bare question mark; the pinned unit test asserts exactly that string. **Not
  reproduced**: the request builder emits a query only when there is one. An empty query is not a
  distinguishable resource, the *signed* path is `/operations` either way — request authentication
  strips the query before signing — and a KERIA agent parses the two identically.
- **An operation name is interpolated unencoded**, so `get("a/b?c=d")` addresses
  `/operations/a/b?c=d` — a different resource, and a different signed path. Refused by
  construction here, as the request builder decided for every family.
- **The type filter *is* encoded**, because `URLSearchParams` does it — one of only two encoded
  dynamic values in the whole reference. Reproduced exactly, down to `+` for a space.
- **A failed operation becomes one interpolated string** carrying the name, the code, the message,
  and the details as JSON. Typed here: `ClientError::OperationFailed` keeps all four apart, and the
  message is bounded because it is remote text.
- **`delete` discards its response.** Reproduced — the status check is what carries the outcome.
- **`get` returns a fourteen-way union** a caller narrows at run time; `hasDepends` is the
  reference's own example, a `'depends' in op.metadata`. The KERIA API types already replaced the
  union with `Operation<M, R>`, so narrowing here is a decode rather than a property test, and a
  narrowing that does not fit is refused.

One further difference is not a divergence but a consequence: the rendered detail block's keys are
sorted rather than kept in the order the agent sent them, because the map they decode into is
ordered. It is an error message, not wire bytes, and the port already declined to reproduce
JavaScript's insertion order where bytes *did* depend on it.

Rust tests consume the checked-in fixture and require neither Node nor network access. They derive
one controller at the ephemeral cost, which takes a few seconds.
