# Multisig rotation and interaction reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-26
- Sources: `test-integration/multisig.test.ts`, `test-integration/multisig-join.test.ts`,
  `test-integration/utils/multisig-utils.ts`, `src/keri/app/exchanging.ts`,
  `test/app/test-utils.ts`
- Binary fields: none. The paths and bodies are exact text; the answers are exact JSON.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_multisig_events.mjs --write   # regenerate
node tools/reference-vectors/client_multisig_events.mjs --check   # verify determinism
SHOW_ERRORS=1 node tools/reference-vectors/client_multisig_events.mjs   # trace a failing call
```

A failing call is evidence here, so the generator records it rather than raising — which means a
later step reading its result fails somewhere unhelpful. `SHOW_ERRORS=1` prints the original stack.

## There is no source file, and this time not even a helper

Multisig inception's unit lived in `test-integration/utils/multisig-utils.ts`, which could be
transpiled and called. Both rounds here are written **inline in a test body**: a hundred and fifty
statements in `multisig.test.ts` between `// MultiSig Interaction` and `// Multisig Rotation`. There
is nothing to import and nothing to call.

So the evidence has two halves.

The **syntax tree** supplies what cannot be driven. Every `exchanges().send` in the three multisig
files is read with the route it names (argument three) and the embed block it carries (argument
five), with an embed passed as a variable resolved to the keys of the nearest object literal
assigned to it. Every `waitAndMarkNotification` is read with the route it waits on. Those two lists
are what make the finding below machine-checked rather than transcribed.

The **recording agent** supplies the bytes. The reference's own `identifiers().interact`,
`identifiers().rotate`, `exchanges().send`, and `groups().join` are driven against a group its own
`startMultisigIncept` incepted, with `globalThis.fetch` replaced by a recorder that signs as a
KERIA agent would and the clock and agent key pinned as the `client-lifecycle` fixture pinned them.

The generator **refuses to write a fixture** if no rotation is announced on the interaction route
any more, if nobody waits on the rotation route, or if either route constant moves.

## The finding: a rotation announced on the interaction route

In `multisig.test.ts`, three `exchanges().send` calls carry a `rot` embed:

| sender | route it sends on | embed it carries |
|---|---|---|
| the initiator | `/multisig/rot` | `rot` |
| the second member | **`/multisig/ixn`** | `rot` |
| the third member | **`/multisig/ixn`** | `rot` |

Both peers are waiting on `/multisig/rot`. So the two join announcements are filed under a route
that names a different message, and a member that trusts the route reads a rotation as an
interaction — or, waiting on the rotation route, never sees the join at all. The pinned scenario
passes anyway, because the group only needs the *agent* to collect signatures; the exchange
messages are advisory there and nothing upstream ever compares a route with its embed.

**Refused here.** The exchange route classifier reads the embed the route names, so the exact body
the reference sent does not classify at all — which the Rust test asserts on those exact bytes.

## The finding: a joining member never reads the rotation it joins

`multisig.test.ts` has its joining members call `rotate` again with their own `states`/`rstates`
and sign whatever comes out. `multisig-join.test.ts` does the opposite — it rebuilds the proposed
`Serder` and signs *that*, through the join endpoint. The pinned tree contains both styles and
marks neither.

They agree only while the members' key states do, which is driven both ways:

| rebuilt from | digest | matches the proposal |
|---|---|---|
| the same states | `EC4JCX7E…` | yes |
| a rotation set of the same size whose digests differ | `EK6MaW8p…` | **no** |

The second row raises **no error**. The rebuilding member signs a rotation nobody proposed, and the
group silently never rotates — the multisig inception witness threshold defect in a second place.

**Checked here.** `accept_rotation` rebuilds as the reference does and then compares what it built
with the digest the proposal carries, refusing to sign a different event. A digest comparison
rather than a byte one, because a decoded record cannot reproduce the bytes it arrived as — but an
event's SAID is a digest over the event, so two events with one SAID are one event.

## The finding: `bt` changes JSON type with its value

`eventing.ts`'s `rotate` defaults `intive` to `true` and then writes:

```ts
bt: _toad && intive && _toad !== undefined && _toad <= MaxIntThold
        ? _toad                 // a bare number
        : _toad.toString(16),   // hexadecimal text
```

while `incept` defaults `intive` to `false` and always writes the text. So an identifier's inception
carries `"bt":"2"` and its rotation carries `"bt":3` — the same field, two JSON types, chosen by
value. The generated schema types it a string, so **a real rotation proposal did not decode here at
all** until these rounds; the KERIA API types' `RotationRecord` now reads either and keeps what
arrived as text.

This compounds the `client-multisig-inception` finding rather than repeating it: there,
`parseInt(icp.bt)` read hexadecimal text in base ten. Here the sibling event writes plain decimal.
What a `bt` means now depends on which event you found it in.

## A third route mismatch, recorded but not owned

The same machine check turns up `multisigRevoke`, which builds `{ iss: [rev, ''], anc: [...] }` —
putting a **revocation in the issuance slot** — and sends it on `/multisig/rev`. Revocation belongs
to the multisig credential and IPEX presentation rounds; it is recorded here because this is where
it was found, and left to them.

## Contents

- `calls` pins ten: the inception the rounds act on, the interaction round proposed and joined, the
  rotation round proposed and announced twice — once on each route — the join endpoint's own style,
  and two rebuilds, one agreeing and one not.
- `declarations` holds every `send` with its route and embed slot, every `waitAndMarkNotification`
  with its route, every group `rotate` call, every `smids`/`rmids` assignment expression, the two
  route constants read from `exchanging.ts`, and the scenario's own anchor.
- `key_states` and `group_record` pin what the agent answers each read with.
- `reference_quirks` pins five behaviours, each with what the reference does and what this port does
  instead.

All ten calls **succeed** upstream. Three of them should not have.

## Determinism, and a caution

The clock and the agent's key are pinned. The members' key states are **derived from the member's
own salt** rather than taken from `mockGetAID`, because a group rotation only works if they chain:
the group's prior next digests must commit to the key each member rotates to, and the pinned mock
invents both. That also means the group identifier here differs from the `client-multisig-inception`
fixture's.

The caution is worth recording. `SaltyIdentifierManager` given neither a `bran` nor an `sxlt`
falls back to `new SaltyCreator(undefined, ...)` — **a fresh random salt**, silently. An earlier
draft of this generator did exactly that and produced a different fixture on every run; passing the
member's own salt is what fixed it. Any later generator constructing a keeper by hand should pass
one.

`PUBLIC TEST MATERIAL`: the passcode and sealed salts are the pinned tests' own, recorded as what
they open to rather than as blobs only the reference's controller can open.

Rust tests consume the checked-in fixture and require neither Node nor network access.
