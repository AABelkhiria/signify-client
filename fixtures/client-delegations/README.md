# Delegation endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-26
- Sources: `src/keri/app/delegating.ts`, `src/keri/app/aiding.ts`,
  `test/app/delegating.test.ts`, `test-integration/delegation.test.ts`,
  `test/app/test-utils.ts`
- Binary fields: none. The paths and bodies are exact text; the answers are exact JSON.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_delegations.mjs --write   # regenerate
node tools/reference-vectors/client_delegations.mjs --check   # verify determinism
```

## Determinism

The clock and the agent's key are pinned, as the `client-lifecycle` fixture pinned them — a signed
request's `Signify-Timestamp` is a clock reading, and every recorded request here is signed. The
identifier is the reference's own `mockGetAID`, with one field supplied: `icp_dt`, which the
reference never reads and the typed identifier record requires. `PUBLIC TEST MATERIAL`: the passcode
and sealed salt are the pinned tests' own, and the salt is recorded as what it opens to rather than
as a blob only the reference's controller can open.

## What the evidence is

This fixture ports the whole of `delegating.ts`: one class, one method, thirty-three lines
including its documentation — the smallest application module in the port, three lines shorter
than `escrowing.ts`.

A delegated identifier cannot come into existence alone. Its inception names a delegator and stays
pending until that delegator **anchors a seal of it** in its own key event log. `approve` is that
anchoring.

`Delegations` takes a whole `SignifyClient`, so this fixture drives the real client the way
`client-escrows` did: `globalThis.fetch` is replaced with a recorder that answers and signs as a
KERIA agent would, and the client is walked through boot, connect, and each call.

`declarations` holds the method read from the reference's own syntax tree — its whole text, its
signature with each parameter's declared type and whether it is optional, its one `fetch` call, the
class's members — beside every `approve` call site in the pinned tree, the line in `createInteract`
that wraps an anchor, and consumer scans over all 117 pinned files.

The generator **refuses to write a fixture** if the class stops being a constructor and one method,
if `approve` stops performing exactly one `POST`, if that `POST` stops addressing `delegation`, or
if the anchor stops being optional.

## The finding: the only published body approves nothing

`approve` declares `data?: any`, and `createInteract` does:

```ts
data = Array.isArray(data) ? data : [data];
```

So calling it with no anchor makes `[undefined]`, which serializes as `[null]`. **The reference's
own unit test does exactly that**, and asserts the result byte for byte:

```json
{"ixn":{…,"a":[null]},"sigs":["AAC4StAw-0Ii…"],"salty":{…}}
```

An interaction event whose seal list holds a JSON null, whose SAID — `EBPt7hivibUQN-dlRyE9x_Y5…` —
is computed over that list, and whose signature covers it. It is the only body the pinned tree
publishes for this endpoint, and a delegate waiting on the seal it does not contain waits forever.

Reproduced here exactly. **Refused here**: the seals are a required argument and an empty list is a
typed error, so an approval of nothing cannot be spelled.

## The finding: the address is the whole difference

`approve` calls `createInteract` and posts the result to `/identifiers/{name}/delegation`;
`identifiers().interact` posts it to `/identifiers/{name}/events`. Driven both ways with the same
seal, the two bodies are **byte for byte identical** — event, SAID, signature, and key-manager
block — and only the last path segment differs.

**Reproduced**: one builder serves both here, as one serves both upstream.
`Identifiers::submit_interaction` takes the segment, and `Delegations::approve` is that call with
`delegation` in it.

## The finding: one alias, two treatments, one call

`approve` reads the identifier through `identifiers().get`, which **encodes** its path component,
and then writes to `'/identifiers/' + name + '/delegation'`, which **concatenates**. Recorded for
the alias `a/b?c=d`:

| request | path |
|---|---|
| read | `/identifiers/a%2Fb%3Fc%3Dd` |
| write | `/identifiers/a/b?c=d/delegation` |

One segment on the read, two segments and a query on the write — the reference disagreeing with
itself inside a single method. **Closed by `ResourcePathBuilder`**, which builds both the same
way; a property states that the two agree for any alias.

## Contents

- `calls` pins seven: the pinned test's own anchorless call; a real approval; the same seal already
  wrapped; two seals in one event; an anchor that is a bare string; the sibling `interact` with the
  same seal; and an alias holding delimiters.
- `pinned_confirmations` records the address, the name, the body, and the seal.
- `reference_quirks` pins five behaviours, each with what the reference does and what this port does
  instead.

All seven calls **succeed** upstream. Three of them should not have.

## Reference behavior recorded as deliberate divergences

- **The pinned test approves nothing**, as above. **Refused here.**
- **An anchor may be anything.** `data?: any`, so a bare string is wrapped, anchored, and signed
  exactly as a seal would be — recorded. **A seal is a `Sad` here**, and `InceptionSeal` names the
  three fields a delegated inception's seal carries. More than one seal is still
  permitted, because the event format permits it.
- **The delegate reads its own prefix out of an operation's name.** The integration test does
  `op2.name.split('.')[1]` to learn the identifier it just created, then hand-assembles the seal
  from it. **`InceptionSeal::of` takes the delegate's artifact** and reads the identifier and the
  digest out of the event, so the three fields cannot disagree with each other or with what they
  claim to anchor — and an event that is not a delegated inception is refused, because nobody will
  ever approve one.
- **One alias is encoded on the read and raw on the write**, as above. **Closed.**
- **The address is the whole difference**, as above. **Reproduced.**

Rust tests consume the checked-in fixture and require neither Node nor network access. Four of them
also **drive this port** through the same inputs: the same address, the same seal, and the same
event fields the reference anchored.
