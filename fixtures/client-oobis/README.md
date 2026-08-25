# OOBI endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-25
- Sources: `src/keri/app/coring.ts`, `src/types/keria-api-schema.ts`,
  `test/app/coring.test.ts`, `test-integration/endroles-by-aid.test.ts`
- Binary fields: none. Paths and bodies are exact text; the answers are exact JSON.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_oobis.mjs --write   # regenerate
node tools/reference-vectors/client_oobis.mjs --check   # verify determinism
```

## Determinism

The clock and the agent's key are pinned, as Roadmap 6.4's fixture pinned them. Nothing here
derives an identifier key, so the generator is fast.

## What the evidence is

Roadmap 7.1 ports `Oobis.{get,resolve,endroles}` — two reads and one write. `get` publishes the
OOBIs a managed identifier advertises for a role, `resolve` asks the agent to fetch somebody else's,
and `endroles` reads the endpoint authorizations an identifier has granted.

Unlike Roadmap 6.9's and 6.10's families, this one has real pinned unit coverage: three cases in
`test/app/coring.test.ts` assert **four exact paths, both `resolve` body fields, and both HTTP
methods**. So the vectors are the reference **driven directly** — `globalThis.fetch` replaced with a
recorder that answers and signs as a KERIA agent would — through those calls and through every
integration call site besides, and `pinned_confirmations.unit_test_assertions` recomputes each of
the six assertions that test makes, with the generator failing if any stops reproducing.

`test-integration/endroles-by-aid.test.ts` supplies the rest, and
`pinned_confirmations.integration_expectations` pins its ten assertions: the role filter, the two
empty answers, and the line where a `get` answer's OOBI is split apart and resolved — which is why
an OOBI must reach the body byte for byte.

## Contents

- `calls` pins twenty-three requests: four publications including the defaulted role, an alias and
  a role that would reshape an address, eight resolutions including three the reference sends
  unchallenged and one with an empty alias, six end-role listings, and two answers of the wrong
  shape.
- `declarations` pins all three path expressions, the resolution body literal, the `undefined` test
  that keeps an absent alias apart from an empty one, both response types, and the nine roles the
  schema declares — all read from the reference's own syntax tree.
- `pinned_confirmations` pins the fifty-nine `get` call sites, the one that takes the default role,
  the thirty-four resolutions, and every assertion both pinned tests make.
- `reference_quirks` pins ten behaviours, each with what the reference does and what this port does
  instead.

## Reference behavior recorded as deliberate divergences

- **The alias is not encoded.** `get('a/b?c=d', 'agent')` addresses
  `/identifiers/a/b?c=d/oobis?role=agent` — one argument becoming two segments and a query, and a
  different `@path` for Roadmap 3.10 to sign. **Refused by construction**, which is the rule
  Roadmap 6.6 applied to the same alias in the same path.
- **The role is interpolated into the query.** The query is built by string interpolation rather
  than with `URLSearchParams`, so `get('aid', 'agent&extra=1')` sends `?role=agent&extra=1` — a
  second query parameter of the caller's choosing. **Refused by construction**: the role is written
  through Roadmap 5.3's `parameter`, which encodes the value exactly once.
- **The role defaults to `agent`.** `get(name, role = 'agent')` writes the default into the query,
  so an omitted role is still an observable request. Exactly one call site in the pinned tree takes
  it. The role is a **required argument** here and `DEFAULT_ROLE` names the reference's value, so
  what reaches the query is visible at the call site — Roadmap 6.7 made the same choice for
  `QuerySequence`, and Roadmap 3.6 for a reply's timestamp.
- **The OOBI is never validated.** `resolve` takes `oobi: string` and sends it unchallenged, so
  `''`, `'not a url at all'`, and a value carrying a newline all become `{"url":…}` and the agent is
  asked to fetch them. **Refused here**: the argument is `signify_http::transport::RequestUrl`, the
  same non-normalizing validator Roadmap 5.1 built — an absolute `http`/`https` URL of visible
  ASCII, no fragment, bounded at 2 KiB. It preserves its bytes exactly, which matters because the
  agent fetches what it is given and because the reference's own integration test splits a
  published OOBI apart before resolving it. Every OOBI the pinned tree resolves is accepted.
- **An empty alias is written.** The alias is dropped only when it is `undefined`; an explicitly
  empty one is written as `"oobialias":""`. **Reproduced**: `Option<&str>` tells the two apart
  exactly as `undefined` does.
- **The AID is not encoded.** `endroles('a/b?c=d')` addresses `/endroles/a/b?c=d`. **Refused twice
  over**: the argument is Roadmap 3.4's validated `IdentifierPrefix`, and the builder would encode
  it exactly once regardless.
- **The unknown AID the reference asks about is not a prefix.** `endroles-by-aid.test.ts` asks about
  `EXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`, which is **43 characters** where a qualified `E`
  prefix is 44 — so the value the reference's own integration test sends is not an identifier at
  all, and it reaches the path unchecked. **Recorded verbatim and proven refused**, as Roadmap 3.8
  and 6.9 did with the same situation; the case that test is making — an unknown AID answers with an
  empty list rather than a failure — is reproduced with `EAXXX…X`, one character longer and a valid
  prefix, whose recorded path is in the fixture beside it.
- **The role filter is a raw path segment.** `endroles(aid, '../identifiers')` addresses a resource
  two levels up. **Refused by construction.**
- **The answers are cast rather than decoded.** All three methods return `res.json()` cast to a
  declared type, so an answer of any shape reaches the caller as an `OOBI`, an `OOBIOperation`, or
  an `EndRole[]`. **Decoded here**, and both recorded wrong-shaped answers are proven refused.
- **Resolving does not wait.** `resolve` returns the operation the agent created and never polls it;
  all thirty-four callers hand it straight to `waitOperation`. **Reproduced exactly** — polling is
  Roadmap 7.2's item, and Roadmap 5.4 already built and pinned the schedule `Operations.wait` uses.

Rust tests consume the checked-in fixture and require neither Node nor network access.
