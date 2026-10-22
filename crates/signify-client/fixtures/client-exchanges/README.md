# Exchange endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-25
- Sources: `src/keri/app/exchanging.ts`, `src/keri/app/contacting.ts`,
  `src/keri/app/credentialing.ts`, `src/types/keria-api-schema.ts`,
  `test/app/exchanging.test.ts`, `test/app/contacting.test.ts`, `test/app/test-utils.ts`
- Binary fields: none. The paths and bodies are exact text; the messages are exact JSON.

Generate and verify from the repository root after installing the pinned references:

```bash
npm ci --prefix tools/reference-vectors
node tools/reference-vectors/client_exchanges.mjs --write   # regenerate
node tools/reference-vectors/client_exchanges.mjs --check   # verify determinism
```

## Determinism

Three things are pinned. The **clock**, because `send` passes no timestamp and `exchange(...)` then
reads the system clock — without this nothing the class sends is reproducible at all. The **agent's
key**, as the `client-lifecycle` fixture pinned it. And the **identifier**, which is the reference's
own `mockGetAID` read out of `test/app/test-utils.ts` by its own compiler.

Signing uses a real keeper at the reference's production Argon2 profile, so the generator takes
several seconds.

The record's sealed salt is replaced by what it **opens to**, because only the reference's own
controller can open the blob; a Rust test re-seals it under its own key. The `client-credentials`
fixture established that shape.

## What the evidence is

This fixture ports the `Exchanges` class — `createExchangeMessage`, `send`, `sendFromEvents`,
`get` — plus `Challenges.respond`, which `client-challenges` moved here on evidence because it is a
five-line wrapper over `send` and nothing else. Delivering these **closes `contacting.ts`** —
`Contacts`, the three challenge methods, and this one. It does **not** close `exchanging.ts`: the
pure `exchange(...)` was verified earlier and this fixture verifies the whole `Exchanges` class, but
the thirteen route constants, the eight resource variants, and the type guards over them belong to
`client-exchange-routes`.

The pure `exchange(...)` this class wraps is already byte-exact; what is new is the signing, the
request body, and the two addresses.

`declarations` holds all four methods read from the reference's own syntax tree — the keeper
lookup, the `exchange(...)` call, the signing, the loop, the `throw` after it, the path
expressions, the body literal, and every declared return type — beside the class's six members, the
thirteen exported route constants, both response schemas, and three 117-file scans.

The generator **refuses to write a fixture** if the class stops having exactly four methods, or if
the three submission return types ever agree.

`pinned_confirmations` closes the loop on **eleven** assertions: `exchanging.test.ts` asserts two
addresses and two methods, and `contacting.test.ts`'s `respond` case asserts an address, a method,
the topic, the message's route, its sender, its word list, and the length of its first signature.
All eleven are recomputed from the reference's own classes. The word list is read from the test's
own source rather than transcribed.

## Contents

- `calls` pins twelve: three `createExchangeMessage` results including one with an embed and one
  with the two arguments `send` never passes; five `send` calls covering one recipient, two, an
  alias that is not the signer, an empty list, and an answer of the other declared shape; the
  pinned `sendFromEvents` call; two reads; and the pinned `respond`.
- `mock_shortfall` records what the reference's own mock omits.
- `reference_quirks` pins seven behaviours, each with what the reference does and what this port
  does instead.

Eleven of the twelve calls **succeed** upstream. The twelfth is the empty recipient list, and it
fails only because the loop cannot run.

## The finding: `send` addresses only the first recipient

```js
for (const recipient of recipients) {
    const [exn, sigs, atc] = await this.createExchangeMessage(sender, route, payload, embeds, recipient);
    return await this.sendFromEvents(name, topic, exn, sigs, atc, recipients);
}
throw new Error('recipients list was empty');
```

The loop `return`s on its first pass. One message is built, addressed to `recipients[0]`, and
delivered to **all** of them — so every member after the first receives a message whose `rp` and
`a.i` name somebody else, and whose SAID and signature commit to that. The reference's own
`test-integration/multisig.test.ts` calls `send` with two recipients eighteen times.

The `throw` after the loop is therefore reachable only for an empty list, which is why
`sendFromEvents` — taking the same list — accepts one and its own unit test sends one.

The fixture drives it: `send_two_recipients` records the `rp` produced and the `rec` sent.

## Reference behavior recorded as deliberate divergences

- **`send` addresses only the first recipient**, as above. **Not reproduced by accident**: the
  addressee is a field of the draft and the delivery list is an argument of the submission, so a
  caller can still address one member and deliver to all — but has to say so.
- **The alias and the signer are two arguments.** `send(name, topic, sender, …)` posts under
  `/identifiers/{name}/exchanges` while signing with `sender`'s keeper, and nothing compares them;
  request signing covers `@path`, so the resource, the key, and the message's own `i` can all
  disagree. **One alias here**, and the record is looked up from it.
- **The timestamp is a clock reading.** `send` passes no datetime, so the message's `dt` — inside
  its SAID and every signature over it — depends on when it was built. **A required parameter**,
  which is the decision taken for `exchange(...)` applied again.
- **The submission answer has two declared types.** `sendFromEvents` says `Promise<Exn>`;
  `Ipex.submitGrant` says `Promise<ExchangeOperation>` for the same shape of POST to the same
  agent. Both are unchecked casts, so at most one is right. **Neither is imposed**: the answer is
  owned bytes with a decoder for each shape, and the question is left for a live KERIA run to
  settle.
- **The SAID is interpolated raw** into `/exchanges/${said}`. **Validated here**, so the recorded
  `../identifiers/aid1?x=1` has no representable input.
- **The pinned unit call is three empty values.** `sendFromEvents('aid1', '', serder, [''], '', [])`
  sends an empty topic, an empty string where a qualified signature belongs, and an empty delivery
  list. All three are unrepresentable here, so that request is reproduced in shape rather than byte
  for byte and each input is proven refused — the pattern used for `exchange(...)` and in
  `client-registries` and `client-oobis`.
- **The route table belongs to `client-exchange-routes`.** Thirteen exported constants and the
  resource variants and guards over them are that fixture's; a route is borrowed text here, as
  `ExchangeBuilder` left it.

Rust tests consume the checked-in fixture and require neither Node nor network access.
