# Group endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-26
- Sources: `src/keri/app/grouping.ts`, `src/types/keria-api-schema.ts`,
  `test/app/grouping.test.ts`, `test-integration/utils/test-util.ts`
- Binary fields: none. The paths and bodies are exact text; the answers are exact JSON.

Generate and verify from the repository root after installing the pinned references:

```bash
npm ci --prefix tools/reference-vectors
node tools/reference-vectors/client_groups.mjs --write   # regenerate
node tools/reference-vectors/client_groups.mjs --check   # verify determinism
```

## Determinism

The clock and the agent's key are pinned, as the `client-lifecycle` fixture pinned them. Nothing
here derives an identifier key, so the generator is fast.

## What the evidence is

This port covers the whole `Groups` class: `getRequest`, `sendRequest`, and `join` — the round of
messages a multisig group decides through.

`Groups` takes a whole `SignifyClient`, so this fixture drives the real client the way the
`client-exchanges` fixture did: `globalThis.fetch` is replaced with a recorder that answers and
signs as a KERIA agent would, and the real client is walked through boot, connect, and each call.

`declarations` holds all three methods read from the reference's own syntax tree — every path
expression, both body literals, all three signatures, and all three declared return types — beside
the class's five members, two schema shapes, and consumer scans over all 117 pinned files.

The generator **refuses to write a fixture** if the class stops having exactly three methods, if
`sendRequest` gains a consumer, or if `getRequest` loses every one.

## The finding: the only test of this class passes junk in every argument

The pinned `Groups` case asserts **three addresses and three methods and nothing else** — no body
is checked anywhere. And it reaches those addresses by passing:

| argument | value | why it cannot be |
|---|---|---|
| `getRequest`'s SAID | `ELI7pg979…Jose00` | 46 characters; a qualified digest is 44 |
| `join`'s rotation | `{ sad: {} }` | the event is empty |
| `join`'s signature | `'sig'` | not qualified material |
| `join`'s `gid` | the same 46-character value | not an identifier prefix |
| `join`'s `smids` / `rmids` | `['1','2','3']`, `['a','b','c']` | not prefixes |
| `sendRequest`'s `sigs` | `[]` | a proposal nobody signed |
| `sendRequest`'s `exn.i` | `'test'` | not an identifier prefix |

Every one is recorded verbatim and proven refused, and the case each is making is reproduced with a
value that can exist. That is the pattern exchange-message construction and the `client-registries`
and `client-oobis` fixtures used.

## Two of the three methods have no consumer

`getRequest` is called **twenty-one times** across `test-integration/multisig*.test.ts`.
`sendRequest` and `join` are called **nowhere** outside the pinned unit case. So the two writes are
ported from their declarations, and the fixture records that fact as a scan rather than a claim.

## Contents

- `calls` pins twelve: the three pinned calls; a signed proposal and a real join; an alias holding
  delimiters; a SAID holding them; the empty-string fallback the reference's own
  `waitAndMarkNotification` produces; a real read; a join naming no members; a join passed the
  rotation event instead of its `Serder`; and an answer of the wrong shape.
- `pinned_arguments` records each junk value with its length or shape.
- `reference_quirks` pins seven behaviours, each with what the reference does and what this port
  does instead.

Every one of the twelve calls **succeeds** upstream.

## Reference behavior recorded as deliberate divergences

- **The pinned case passes junk in every argument**, as above. Each is proven unrepresentable; the
  three addresses, which are what the test actually asserts, reproduce exactly.
- **A request may carry no signature.** `sendRequest` declares `sigs: string[]` and sends `[]`
  unchallenged, which asks the agent to relay to every group member a proposal nobody signed.
  **Refused here**: the message is a `SignedExchange`, which comes from a keeper.
- **None of the three dynamic values is encoded.** `getRequest` concatenates its SAID and both
  writes interpolate their alias, so the recorded `a/b?c=d` reaches the wire as two segments and a
  query, and `../identifiers/aid1?x=1` climbs out of its own. **Closed by typing and by the
  request builder.**
- **`join` reads a `Serder`, not an event.** It declares `rot: any` and writes `rot.sad`, so passing
  the rotation event its own JSDoc names sends **no `rot` field at all** — recorded both ways round,
  and nothing announces the loss. **An `IdentifierArtifact` here**, which carries the
  event and its signatures together.
- **The two writes disagree about their answers.** `sendRequest` declares `Promise<Exn>` and `join`
  declares `Promise<GroupOperation>`, for two writes under one resource — the disagreement the
  `client-exchanges` fixture recorded between `sendFromEvents` and `Ipex.submit*`, now inside a
  single class. **`join` is decoded as the operation it declares; `send_request` reuses
  `SentExchange`**, and the open question of which shape KERIA answers covers this path too.
- **A join may name no members.** Empty `smids` asks the agent to rotate a group into having no
  signers. **Refused here** — while an empty `rmids` is allowed, because `Identifiers.rotate`
  writes one for a single-signature identifier.
- **A request body carries no topic and no recipients**, where the sibling submission writes both.
  **Reproduced exactly**: they are different endpoints and this one's body is the shorter.

Rust tests consume the checked-in fixture and require neither Node nor network access.
