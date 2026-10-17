# IPEX presentation workflow reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-09-16 (first generated 2026-08-27; the sixth divergence was added on regeneration)
- Sources: `test-integration/credentials.test.ts`, `test-integration/multisig-holder.test.ts`,
  `test-integration/utils/multisig-utils.ts`, `test-integration/utils/test-util.ts`,
  `src/keri/app/credentialing.ts`, `test/app/test-utils.ts`, `src/keri/app/exchanging.ts`,
  `test-integration/multisig.test.ts`
- Binary fields: none. The paths and bodies are exact text; the answers are exact JSON.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_ipex_presentation.mjs --write   # regenerate
node tools/reference-vectors/client_ipex_presentation.mjs --check   # verify determinism
SHOW_ERRORS=1 node tools/reference-vectors/client_ipex_presentation.mjs   # trace a failing call
```

## What the evidence is

This port covers the conversation that discloses a credential — apply, offer, agree, grant,
admit — and the two rounds where a group runs a grant or an admit as a multisig. The IPEX artifact
builders build the five messages and the `client-ipex` submitters send them; this fixture is the
part between.

There is no source file. The single-signature conversation is written inline in
`credentials.test.ts`, so each step is driven through the reference's own `Ipex` method with the
same arguments in the same order. The group rounds live in `multisig-utils.ts` and are
**transpiled in memory** as the `client-multisig-inception` fixture's are.

Sixteen rounds are driven and all sixteen succeed.

## The finding: a group's round agrees only because one process held one clock

An IPEX message's SAID is a digest over the message, and the message carries its own `dt`. So two
members of a group build the same grant only if they stamp it identically. Both helpers take the
stamp as a parameter:

```ts
export async function admitMultisig(client, aid, otherMembersAIDs, multisigAID,
                                    recipientAID, timestamp, isInitiator = false)
```

and `multisig-holder.test.ts` supplies it from a module-level constant:

```ts
const TIME = createTimestamp();
```

so both of its members read one value from one process. Its own check —

```ts
assert.equal(admitResult1.admitSaid, admitResult2.admitSaid);
```

— therefore passes, and is the only thing anywhere that would notice if it did not.

Driven both ways, one second apart:

| round | same stamp | own clocks | error |
|---|---|---|---|
| grant | same grant | **different grant** | none |
| admit | same admit | **different admit** | none |

Two members in two processes sign two different messages, the group reaches its threshold on
neither, and nothing says so.

**Here** `accept_admittance` takes no timestamp at all. The stamp, the recipient, the text, and the
grant being acknowledged are read out of the proposal, and the SAID this member derives is compared
with the one it was shown. `accept_disclosure` does the same.

## The finding: a notification need not name a message

```ts
return notes[notes.length - 1]?.a.d ?? '';
```

Two things follow. A notification carrying no `a.d` yields the **empty string**, which
`admitMultisig` passes straight into `grantSaid` — driven here, producing an admit posted with an
empty `p`, acknowledging nothing, with no error. The inline step in `credentials.test.ts` guards the
same value with `assert(grantNotification.a.d)` first; the helper beside it does not, and neither
does the third copy in `multisig-holder.test.ts`.

And the waiter marks **every** matching notification read while returning only the last one's SAID.
A holder group admitting from a multisig issuer receives one grant per issuer member; it answers one
and silently marks the rest read. The parameter that would have said how many to expect is still in
the tree, commented out:

```ts
    isInitiator: boolean = false
    // numGrantMsgs: number
```

**Here** `Presentation::read` refuses a notification that names no message, and
`Presentation::waiting` returns every unread notification on the route so the caller answers each.

## Two smaller findings

**A joining member never reads the proposal** — the same shape the `client-multisig-credentials`
fixture pinned for the transaction rounds, now in all three group IPEX helpers: each waits on
`/multisig/exn` and discards the SAID, and across six driven group rounds not one fetches a group
request.

**A grant assembles its attachments three different ways in one tree**: all three
(`credentials.test.ts` presentation), the anchor's only (`credentials.test.ts` issuance), and none
at all (`grantMultisig` and `multisig-holder.test.ts`). Passing none reaches the branch that signs
`args.anc.raw` with the **sender's** keeper — correct only when the sender is the issuer, and
reached in the tree where it is not. The credentials endpoint refused that branch;
`presentation::disclosure_of` assembles the three attachments from a credential in hand, and
re-serializes each of the three events to check its bytes still reproduce the SAID that names it.

## A third, found live: the announcement names only the group

`MultisigExnExchange` declares the `/multisig/exn` attribute block as `{ gid }` and nothing else, and
the recorded announcement carries exactly `["i", "gid"]`. Both group helpers take the peers as an
argument, so a joining member is told who to answer by its caller. Where the reference's own tests
derive the members themselves — `multisigIssue` and `multisigRevoke` — they ask the agent's members
endpoint for `signing[].aid`; the group record's `keys` are the members' *signing keys* and never
stand in for their identifiers. This port once read them as if they did, and a joining member
answered every grant with `LocalMemberNotAParticipant` against a live agent (2026-09-16). Now the
IPEX rounds announce `smids` and `rmids` as the six event rounds do, a proposal that names nobody is
answered by `identifiers().members`, and the classifier reads both shapes.

## The chain, which is what makes any of this checkable

| step | embeds | answers |
|---|---|---|
| apply | nothing | nothing — this opens the conversation |
| offer | `acdc` | the apply |
| agree | nothing | the offer |
| grant | `acdc`, `iss`, `anc` | the agree, or nothing when an issuer grants unprompted |
| admit | nothing | the grant |

Every link is pinned by SAID in `pinned_confirmations.chain`, and the Rust tests walk it.

## Contents

- `calls` pins sixteen: the issuance and its two grants, two admits, the five-step presentation, the
  group's inception, three disclosure rounds, and three admittance rounds.
- `declarations` holds all three group helpers' text, the waiter's own return statement, every
  `waitAndMarkNotification` with whether its SAID is bound, every `ipex()` call with the arguments
  it names, `Ipex.grant`'s default-attachment branches, and scans over all pinned files.
- `held_credential` is the credential as a holder reads it back, with the three attachments it
  arrived with — the input to `disclosure_of`.
- `reference_quirks` pins six behaviours, each with what the reference does and what this port
  does instead.

## Determinism

The clock and the agent's key are pinned, and the two stamps the group rounds use are fixed
constants rather than readings — which is the point of the finding rather than a workaround. The
helpers narrate to `console.log`, which the generator captures so its own output is only the
fixture. `PUBLIC TEST MATERIAL`: the passcode and sealed salts are the pinned tests' own, recorded
as what they open to.

Rust tests consume the checked-in fixture and require neither Node nor network access.
