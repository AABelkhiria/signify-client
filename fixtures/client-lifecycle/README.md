# Signify client lifecycle reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-23
- Sources: `src/keri/app/clienting.ts`, `src/keri/app/coring.ts`, `src/ready.ts`,
  `test/app/clienting.test.ts`
- Binary fields: none. Identifiers, keys, and signatures are qualified Base64; request bodies are
  exact serialized text.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_lifecycle.mjs --write   # regenerate
node tools/reference-vectors/client_lifecycle.mjs --check   # verify determinism
```

## Determinism

Two things are pinned that make the whole walk reproducible. The **clock** is replaced by a
`Date` subclass returning a fixed instant, as Roadmap 5.5's fixture did, so a signed request's
`Signify-Timestamp` and the signature covering it are exact. The **agent's key** is a fixed seed,
so its response signatures are too. Everything else — the controller, its inception, its
delegation approval — derives from the passcode the pinned test publishes.

The one non-deterministic thing here is deliberate: `randomPasscode` and `randomNonce` cannot be
pinned, so they are recorded by **shape** over 64 samples — length, alphabet, code, and
distinctness.

## What the evidence is

Roadmap 6.4 ports what a client does before any endpoint family exists. As with Roadmap 6.3's
fixture, this one **drives the reference rather than re-expressing it**: `globalThis.fetch` is
replaced with a recorder that answers as a KERIA agent would — signing every response so
`SignifyClient.fetch` accepts it — and the real client is walked through `boot`, `state`,
`connect`, two signed requests, `saveOldPasscode`, `deletePasscode`, and one non-success status.
Every request it made is recorded with its method, URL, headers, and body.

`pinned_confirmations` closes the loop against the reference's *test suite* as well as its
implementation: the controller prefix and the exact boot body must both appear among the literals
`clienting.test.ts` asserts, and the generator fails if either does not.

`declarations` holds the constants and checks the lifecycle turns on — the default boot URL, the
passcode length check, the boot body's field order, the state path, the anchor and delegation
checks, the approval URL, the error-message template, both random helpers, and the whole of
`ready.ts` — read out of the reference's own syntax tree.

## Contents

- `lifecycle` pins eight steps with every request each produced. `connect` produces two: the state
  read and the unsigned delegation approval.
- `connected` pins what the client knows afterwards: the controller advanced to its
  delegation-approving interaction event, the agent's prefix, anchor, and verification key.
- `random_shapes` pins both helpers over 64 samples each.
- `reference_quirks` pins seven behaviours, each with what the reference does and what this port
  does instead.

## Reference behavior recorded as deliberate divergences

- **`boot` hardcodes `pidx: 1`** while the client's own field is zero, and nothing reads the value
  back. Reproduced as a constant, so the two cannot disagree.
- **The delegation approval is unauthenticated.** The `PUT` anchoring the agent bypasses the signed
  path and calls the global `fetch` directly, so it carries no HTTP signature; Roadmap 5.1 recorded
  the same defect from the transport side. Reproduced, and the method says so.
- **Both passcode calls are unauthenticated too.** `saveOldPasscode` writes a passcode to the agent
  over an unsigned request. Reproduced and named, so a caller cannot mistake either for a signed
  call.
- **A 404 is a thrown string and every other status falls through**, so a 500 would be parsed as if
  it were the agent state. Here a 404 is `AgentNotFound`, any other non-success status is `Status`,
  and neither is parsed.
- **`connect` assigns `controller.ridx` after construction without re-deriving any key**, so the
  field and the keys it names can disagree. Roadmap 4.5 fixed the index at construction, so here
  the controller is rebuilt with the returned index rather than mutated.
- **`src/ready.ts` is libsodium's WebAssembly initialization** — four lines awaiting
  `_sodium.ready`, imported from exactly one place, the export surface. Recorded `N/A`: the Rust
  cryptographic stack needs no asynchronous initialization, so there is nothing to port. This
  closes the `PORTING.md` §10 question that fell due here.
- **`fetch` throws `client need to call connect first`** when its authenticator is still null.
  Unrepresentable here: connecting consumes the unconnected client and returns a connected one, so
  there is no `fetch` to call before connecting.

Rust tests consume the checked-in fixture and require neither Node nor network access. They derive
one controller at the ephemeral cost, which takes a few seconds.
