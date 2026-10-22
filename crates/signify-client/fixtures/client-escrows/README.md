# Escrows endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-25
- Sources: `src/keri/app/escrowing.ts`, `src/keri/app/exchanging.ts`,
  `src/types/keria-api-schema.ts`, `test/app/escrowing.test.ts`
- Scoped corroboration: `keripy` `1.3.6` `4ce4cc79` — `src/keri/core/routing.py`,
  `src/keri/core/eventing.py`, `src/keri/vdr/eventing.py`, `src/keri/app/oobiing.py`,
  `ref/Peer2PeerCredentials.md`
- Binary fields: none. The paths are exact text; the answers are exact JSON.

Generate and verify from the repository root after installing the pinned references:

```bash
npm ci --prefix tools/reference-vectors
node tools/reference-vectors/client_escrows.mjs --write   # regenerate
node tools/reference-vectors/client_escrows.mjs --check   # verify determinism
```

## Determinism

The clock and the agent's key are pinned, as the `client-lifecycle` fixture pinned them, and the
escrowed replies carry a fixed timestamp so their SAIDs are stable. Nothing here derives an
identifier key, so the generator is fast.

## What the evidence is

This fixture ports the whole of `escrowing.ts`: one class with one method, `Escrows.listReply`, and
one type alias, `Rpy`. An escrow is a message the agent received and could not yet accept, and this
is the only window the reference offers onto one.

`Escrows` takes a whole `SignifyClient`, as `Config` does, so this fixture drives the reference the
way `client-config` did: `globalThis.fetch` is replaced with a recorder that answers and signs as a
KERIA agent would, and the real client is walked through boot, connect, and each call.

The genuine escrowed replies are built by **the reference's own `reply()`**, so a record this port
decodes is one the reference itself produced rather than one this fixture invented.

`declarations` holds the whole method read from the reference's own syntax tree — the
`URLSearchParams` construction, the `route !== undefined` guard, the path expression, the method,
the fetch call, and the `res.json()` return — plus the class's three members, the module's two
exports, the `Rpy` alias with the two schema literals behind it, and five 117-file scans.

The generator **refuses to write a fixture** if `escrowing.ts` stops exporting exactly `Escrows`
and `Rpy`, or if the `Escrows` class stops having exactly one method, so the claim that this fixture
closes the file is a checked fact rather than a reading.

`pinned_confirmations` closes the loop: the one URL and the one method `escrowing.test.ts` asserts
are both recomputed from the reference's own class.

## Contents

- `calls` pins thirteen listings: the pinned route; no argument at all; an empty route; the two
  reply routes the reference actually produces; three routes that would inject, split, or climb if
  the query were interpolated; an empty listing; and four answers of shapes the reference accepts
  unchecked.
- `reference_quirks` pins six behaviours, each with what the reference does and what this port does
  instead.
- `keripy_corroboration` pins the escrow's own declaration and the seven reply routes keripy
  registers, read from source.

Every one of the thirteen calls **succeeds** upstream — including the four whose answers are not
escrowed replies at all.

## The finding: this file encodes its one caller value

`listReply` builds its query with `URLSearchParams` rather than by interpolation, so the route is
escaped. That is the **opposite** of what `client-oobis` found in `Oobis.get`, where none of four
dynamic values is encoded, and the same agreement `client-contacts` found in `Contacts.list`.

The pinned unit test states it from upstream's own side: the URL it asserts is
`/escrows/rpy?route=%2Fpresentation%2Frequest`, the **encoded** form. Three driven routes confirm
it — `a&b=c` cannot add a second parameter, `a b` becomes `a+b`, and `../../identifiers` cannot
climb.

## Reference behavior recorded as deliberate divergences

- **An unfiltered listing ends in a bare question mark.** `path` concatenates
  `'?' + params.toString()` unconditionally, so a listing with no route addresses `/escrows/rpy?`.
  **Not reproduced**, on the grounds `client-operations` gives for `/operations?`; a live KERIA run
  still owes it a confirmation.
- **The answer is never validated.** `listReply` returns `res.json()` cast to `Rpy[]`, so an object,
  a list of inception events, and a reply with no timestamp are all handed to the caller as escrowed
  replies — and `Rpy` types `t` as a bare `string`, so even a checked cast would not have caught the
  second. **Decoded here** into `Vec<ReplyRecord>`, whose `t` is the `ReplyIlk` marker; all three
  recorded answers are proven refused.
- **An undeclared field is kept.** `res.json()` returns whatever the agent sent. **Ignored here**,
  which is the rule for a schema with no index signature — while a reply's own attribute block `a`
  stays open and is captured, because the schema types it `unknown`.
- **The route is encoded**, which is a place the two implementations agree, recorded because the
  same position in the same phase went the other way in `Oobis.get`.
- **An empty route is a route.** The guard is `route !== undefined`, so `listReply('')` asks for
  `?route=` and `listReply()` asks for nothing. Reproduced: the argument is `Option<&str>`.
- **The escrow vocabulary is undetermined.** The pinned tree names exactly one escrow route,
  `/presentation/request`, and only inside this unit test; the two reply routes the reference does
  produce, `/end/role/add` and `/loc/scheme`, are never used to filter an escrow. So the route stays
  borrowed text rather than becoming an enum — the decision already taken for `ReplyBuilder`'s own
  route, for the same reason.

## The corroboration: the route the test filters on is not a reply route

signify-ts cannot answer what a reply escrow actually holds, because it never fills one. keripy
can, and `keripy_corroboration` records it from source: `Revery.escrowReply` is the escrow this
endpoint reads out of, and the three `registerReplyRoutes` methods declare every route a reply may
carry —

    /end/role/{action}   /introduce   /ksn/{aid}   /loc/scheme
    /tsn/credential/{aid}   /tsn/registry/{aid}   /watcher/{aid}/{action}

`/presentation/request` is **not** among them. It appears in keripy exactly once, in
`ref/Peer2PeerCredentials.md`, as the `r` of an **`exn`** — a peer-to-peer message, not a reply.
Both routes signify-ts produces *are* in the list, which is the cross-check that this is the right
list. The generator refuses to write a fixture if `/presentation/request` ever becomes a registered
reply route.

This governs nothing: keripy is consulted only for capabilities signify-ts cannot emit, and
this is not one, so signify-ts governs every byte this family sends and the port still writes
exactly the URL the pinned test asserts. It is recorded because it is the strongest available
reason not to turn the filter into an enum — the single literal on offer is not evidence about this
resource at all.

Rust tests consume the checked-in fixture and require neither Node nor network access.
