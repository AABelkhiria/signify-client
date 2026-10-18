# Challenge endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-25
- Sources: `src/keri/app/contacting.ts`, `src/keri/app/exchanging.ts`,
  `src/types/keria-api-schema.ts`, `test/app/contacting.test.ts`,
  `test-integration/challenge.test.ts`
- Binary fields: none. Paths and bodies are exact text; the answers are exact JSON.

Generate and verify from the repository root after installing the pinned references:

```bash
npm ci --prefix tools/reference-vectors
node tools/reference-vectors/client_challenges.mjs --write   # regenerate
node tools/reference-vectors/client_challenges.mjs --check   # verify determinism
```

## Determinism

The clock and the agent's key are pinned, as the `client-lifecycle` fixture pinned them. Nothing here
derives an identifier key, so the generator is fast.

## What the evidence is

This ports `Challenges.{generate,verify,responded}` from `src/keri/app/contacting.ts`. A
challenge is a list of BIP39 words: one party has the agent generate them and sends them out of
band, the other signs them into an exchange message, and the first asks the agent to verify the
signature exists and then records the answer — which is what puts an `authenticated` verdict into
that identifier's contact record.

`exchanging.ts` is a **source** here for one reason, and it is the first thing this fixture records.

## `respond` is not in this endpoint, and the fixture proves why

`Challenges.respond` is a five-line wrapper: it reads the habitat and calls
`exchanges.send(name, 'challenge', hab, '/challenge/response', {words}, {}, [recipient])`. That
reaches `Exchanges.{send, createExchangeMessage, sendFromEvents}` whole — the generic exchange
submission that POSTs `{tpc, exn, sigs, atc, rec}` to `/identifiers/{name}/exchanges`, which
belongs to **the exchange endpoint** rather than the challenges endpoint.

Reproducing it here would mean implementing the exchange endpoint alongside this one, so the
capability **moved** there rather than being duplicated. The `deferred_capability`
block holds `respond`'s whole body, the three methods it reaches, and `sendFromEvents`'s own path
and body expression — all read from the reference's syntax tree — and the generator refuses to write
a fixture if `respond` stops delegating. So the deferral is a checked fact, not a claim.

Two constants stay in the Rust module because they are facts about *challenges* rather than about
exchanges, and a caller answering one needs them: `CHALLENGE_TOPIC` and
`CHALLENGE_RESPONSE_ROUTE`. Both are asserted against the reference's own literals.

## Contents

- `calls` pins thirteen requests: three generations at both real strengths and the default, three
  strengths no mnemonic generator could satisfy, a verification, an empty word list, an escaping
  source, an acceptance, a hostile SAID, and two answers of the wrong shape.
- `declarations` pins all three path expressions, both bodies, the `= 128` default, the `return res`
  that makes `responded` the only method not to read its answer, and the `Challenge` schema entry.
  The `Challenges` class's member list is asserted, so the split between this endpoint and the
  exchange endpoint is machine-checked.
- `deferred_capability` pins why `respond` is elsewhere.
- `pinned_confirmations` pins the four unit-test assertions, the two addresses, the twelve-word list,
  and the five integration usages — including the empty challenge list that `responded` exists to
  fill.
- `reference_quirks` pins eight behaviours, each with what the reference does and what this port does
  instead.

## Reference behavior recorded as deliberate divergences

- **The strength is interpolated, not validated.** `strength: number` is stringified straight into
  the query, so `generate(1.5)` sends `?strength=1.5`, `NaN` sends `?strength=NaN`, and `-1` sends
  `?strength=-1` — none of which any BIP39 generator accepts. **Refused**: `ChallengeStrength` takes
  only the five entropy sizes BIP39 defines. keripy's own generator is the corroboration — it hands
  the value to `mnemonic.Mnemonic.generate(strength=…)`, which raises outside that set — recorded as
  corroboration rather than as a governing reference.
- **The strength default is observable.** `generate(strength = 128)` writes it into the query, so an
  omitted strength still names one. The strength is a **required argument** here and
  `ChallengeStrength::BITS_128` names the reference's value — the OOBI endpoint's `DEFAULT_ROLE`
  decision applied again.
- **The source is not encoded.** Both verification paths are `/challenges_verify/${source}`.
  **Refused twice over**: the validated `IdentifierPrefix`, and the builder would encode it
  exactly once regardless.
- **The two verification calls share one address.** `verify` and `responded` differ only in method
  and body — `POST` asks, `PUT` records. Reproduced, with the segment pinned as one constant so they
  cannot drift apart.
- **`responded` returns the raw response.** It is the only method in the family that does not call
  `res.json()`: it hands back the platform `Response` object, so a caller receives an unread body and
  a transport type. **Returns `()` here**, which is what `Operations::delete` and `Contacts::delete`
  do — a non-success status is already `ClientError::Status`, and transport types stay off the SDK
  boundary.
- **An empty word list is accepted.** `verify(source, [])` sends `{"words":[]}`, asking the agent to
  confirm that an identifier signed *nothing*. **Refused**, which is what the IPEX submission
  endpoint did for an empty recipient list on the same reasoning: a verification that trivially
  matches is worse than one that fails.
- **The answers are cast rather than decoded.** `generate` and `verify` return `res.json()` cast to
  `Challenge` and `ChallengeOperation`, so an answer carrying no words at all reaches the caller as a
  challenge. **Decoded here**, and both recorded wrong-shaped answers are proven refused.
- **The SAID reaches the body, not the path.** Unlike the source it cannot move a request. It is
  still the validated `Said`, because what it names is a specific exchange message and an
  unparseable one records an acceptance of nothing.

Rust tests consume the checked-in fixture and require neither Node nor network access.
