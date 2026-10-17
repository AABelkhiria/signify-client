# Agent-configuration endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-24
- Sources: `src/keri/app/coring.ts`, `src/types/keria-api-schema.ts`, `test/app/coring.test.ts`
- Binary fields: none. The path is exact text; the answers are exact JSON.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_config.mjs --write   # regenerate
node tools/reference-vectors/client_config.mjs --check   # verify determinism
```

## Determinism

The clock and the agent's key are pinned, as the `client-lifecycle` fixture pinned them. Nothing
here derives an identifier key, so the generator is fast.

## What the evidence is

This ports `Config.get` — the smallest capability in the file and the last one before its OOBI
and operation-waiting code.

`Config` takes a whole `SignifyClient`, as `KeyEvents` and `KeyStates` do, so this fixture drives
the reference the way the `client-key-state` fixture did: `globalThis.fetch` is replaced with a
recorder that answers and signs as a KERIA agent would, and the real client is walked through boot,
connect, and the call.

**The request is not the interesting part.** The path is the constant `/config` — the only address
in this port that carries no caller input at all — so all five recorded answers produce byte-for-byte
the same `GET /config` with no body. What the vectors are about is the **response**: the reference
returns `res.json()` cast to `AgentConfig`, which is a compile-time claim about a run-time value,
and this port decodes it instead.

`declarations` holds the path and method declarations, the fetch call, the `res.json()` return, the
whole three-member class, the `AgentConfig` schema literal, and two 117-file scans, read from the
reference's own syntax tree. `pinned_confirmations` closes the loop: the one path
`coring.test.ts` asserts is produced by the reference's own class.

Every one of the five calls **succeeds** upstream — including the one whose answer is the wrong
shape. The reference validates nothing.

## Contents

- `calls` pins five: a configured agent, an empty list, an absent field, an answer carrying
  undeclared fields, and an answer whose `iurls` is a string rather than a list.
- `reference_quirks` pins four behaviours, each with what the reference does and what this port
  does instead.

## Reference behavior recorded as deliberate divergences

- **The answer is never validated.** `get` returns `res.json()` cast to `AgentConfig`, so an agent
  answering `{"iurls": "not-a-list"}` hands the caller a value they will read as configuration.
  **Decoded here**: such an answer is `ClientError::Api`, and the recorded one is proven refused.
- **Undeclared fields are kept.** `res.json()` returns whatever the agent sent, so `curls` and
  anything else survive into the caller's value. **Ignored here**, which is the shared API types'
  rule for a schema with no index signature.
- **An absent list is not an empty one.** The schema marks `iurls` optional, so an agent may omit
  it; the reference hands back `undefined` in one case and `[]` in the other and nothing in its own
  code tells them apart. Reproduced as `Option<Vec<String>>`, so an agent that was never configured
  stays distinguishable from one configured with nothing.
- **The path carries no input**, which makes this the only endpoint where the reference's unencoded
  interpolation cannot bite. Reproduced exactly; there is nothing to encode.

## A discovery that is not about this endpoint

While proving what the decoder refuses, the property tests established that **a JSON sequence
decodes as any `signify-types::api` record**, because serde reads a struct positionally from one:
`[["http://x"]]` yields exactly what `{"iurls":["http://x"]}` yields, and `[]` yields the default.
Only scalars are refused.

That is a leniency rather than a wrong belief — a positional answer is *understood*, not
misunderstood — and it applies to every record in that crate rather than to this endpoint. It is
recorded as a limitation for the upstream unit-vector audit rather than changed here, since
changing it would mean altering a verified type for a shape no KERIA sends. The named regression
`a_sequence_answer_decodes_positionally` pins the exact behaviour.

Rust tests consume the checked-in fixture and require neither Node nor network access.
