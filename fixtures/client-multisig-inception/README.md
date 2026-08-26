# Multisig inception reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-26
- Sources: `test-integration/utils/multisig-utils.ts`, `test-integration/utils/test-util.ts`,
  `test-integration/multisig-inception.test.ts`, `test/app/test-utils.ts`
- Binary fields: none. The paths and bodies are exact text; the answers are exact JSON.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_multisig_inception.mjs --write   # regenerate
node tools/reference-vectors/client_multisig_inception.mjs --check   # verify determinism
```

## There is no upstream source file

The reference writes this orchestration **only in its own integration helpers** —
`startMultisigIncept` and `acceptMultisigIncept` in `test-integration/utils/multisig-utils.ts`. There
is no exported API to port and no unit test to reproduce, which makes this a Rust-only module
(`PORTING.md` §4.5). The generator records that as a scan rather than a claim:
`startMultisigIncept` is called eight times across the pinned tree and `acceptMultisigIncept` nine,
every call site under `test-integration/`, and neither name appears under `src` at all.

## How the reference's own code is driven anyway

That file imports the package by name and is **not built into `dist`**, so it cannot simply be
required. The generator therefore **transpiles that one file in memory** with the reference's own
pinned TypeScript and evaluates it with a three-entry module shim: `signify-ts` resolves to the
built `dist`, `./test-util.ts` to a checked stub for the one helper it needs, and `assert` to node's.

Nothing is written into the submodule, and what produced these requests is the
reference's own code rather than a re-expression of it. This is the first fixture in the port to
reach a unit that upstream never exported; the technique is available to any later item in the same
position.

`globalThis.fetch` is replaced with a recorder that answers and signs as a KERIA agent would, the
clock and the agent's key are pinned as Roadmap 6.4's fixture pinned them, and the local member is
the reference's own `mockGetAID`.

## Determinism

The proposal's `dt` is inside its SAID and every signature over it, so the clock is pinned. The
sealed salt is recorded as **what it opens to** rather than as the blob itself — only the
reference's controller can open that blob — and the Rust test re-seals it under its own key, which
is the shape Roadmap 6.11 established. `PUBLIC TEST MATERIAL`: the passcode and salt are the pinned
tests' own.

## Contents

- `calls` pins six: the scenario's two proposals, one acceptance of the first, and three acceptances
  of proposals bent to make a latent defect observable.
- `key_states` pins the state each participant read is answered with, so the Rust side consumes them
  rather than transcribing them.
- `declarations` holds both helpers and their signatures read from the reference's own syntax tree,
  every `exchanges().send` call in the file with whether it is awaited, the scenario's group names,
  member names, route, and witnesses, and consumer scans over all 117 pinned files.
- `pinned_confirmations` records the five addresses the initiator visits, in order.
- `reference_quirks` pins five behaviours, each with what the reference does and what this port does
  instead.

Five of the six calls **succeed** upstream. The sixth fails, and that failure is the finding.

## The finding: a hexadecimal field read in base ten

`acceptMultisigIncept` rebuilds the accepted inception with `toad: parseInt(icp.bt)`. The protocol
writes `bt` in **hexadecimal** — by the reference's own builder, which formats it with
`toad.toString(16)` — so below ten the two agree and at ten or above they do not.

| proposed `bt` | means | what `parseInt` makes of it | result |
|---|---|---|---|
| `"2"` | 2 | 2 | the two members converge |
| `"a"` | 10 | `NaN` | `Invalid num = NaN, too large to encode.` |
| `"10"` | 16 | 10 | **a different group, silently** |

The last row is driven end to end. The proposer derives
`EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk`; the joining member rebuilds the event with `bt: "a"`
and derives `EGr5G-KvvPNtYFqyspUvLY_ID1GZBjidQFAN1Gs5-GDr`; **no error is raised on either side**.
The two members have not joined the same group, both are waiting for a signature the other will
never send, and nothing tells them.

Here the joining member takes the proposal's own decoded witness configuration, so there is no
string to read in the wrong base at all.

## Reference behavior recorded as deliberate divergences

- **The initiator addresses its proposal to itself.** `startMultisigIncept` passes `participants` as
  the recipient list and the scenario puts the local member first, so through the loop Roadmap 7.7
  recorded, the message's `rp` is its own `i` and it is delivered back to its own sender. The
  *accepting* helper already filters itself out, which is the asymmetry. **Both halves filter here**,
  and the addressee is a separate argument from the delivery list.
- **The joining member discards the rotation set it read.** `acceptMultisigIncept` computes
  `rmids` from the proposal, derives the group's next keys from it, and then relays
  `{ gid, smids, rmids: smids }` — so a third member joining from that message is told the signing
  set where the rotation set belongs. **The set that was read is the set that is relayed here.**
- **The joining member does not await the message it sends.** Its `exchanges().send(...)` is a
  floating promise, proven from the syntax tree: of the nine `send` calls in the file, that one
  alone is unawaited. The helper returns its operation whether or not the message ever left.
  **Awaited here** — a member that could not tell its peers has not joined.
- **The witness threshold is read in the wrong base**, as above.
- **There is no source file**, as above.

## What this port does that the reference does not

One thing, recorded here so the request counts can be compared honestly: **this port reads the
member record twice.** Roadmap 7.7's `send` resolves its own sender from the alias rather than
taking a record the caller is already holding — which is what keeps a message's `i` field and the
key that signed it one identifier — where the reference passes the hab it already has. So a proposal
makes six requests here and five upstream, and the reference's five are these six with that read
removed. Nothing else differs in what is read or in what order.

Rust tests consume the checked-in fixture and require neither Node nor network access. The
cross-language test also **drives this port through the same inputs** and asserts the thing the
whole workflow rests on: both implementations derive the same group identifier, from the same
inception event, byte for byte.
