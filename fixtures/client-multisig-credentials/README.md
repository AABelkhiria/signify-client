# Multisig registry, issuance, and revocation reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-26
- Sources: `test-integration/utils/multisig-utils.ts`, `test-integration/multisig.test.ts`,
  `test-integration/multisig-vlei-issuance.test.ts`, `src/keri/app/credentialing.ts`,
  `test/app/test-utils.ts`
- Binary fields: none. The paths and bodies are exact text; the answers are exact JSON.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_multisig_credentials.mjs --write   # regenerate
node tools/reference-vectors/client_multisig_credentials.mjs --check   # verify determinism
SHOW_ERRORS=1 node tools/reference-vectors/client_multisig_credentials.mjs   # trace a failing call
```

## What the evidence is

Roadmap 8.7 ports the three rounds a group runs over a credential registry: creating one, issuing a
credential from it, and revoking that credential. Two of the units — `createRegistryMultisig` and
`issueCredentialMultisig` — live in the reference's integration utilities and are **transpiled in
memory** as Roadmap 8.3's are. The third, `multisigRevoke`, is written inline in a test body and is
driven through the reference's own `revoke` and `send` in the same order with the same arguments.

Eight rounds are driven and all eight succeed. Three of them should not have.

## The finding: a joining member never reads the proposal

Both helpers begin:

```ts
if (!isInitiator) await waitAndMarkNotification(client, '/multisig/vcp');
```

The call's result — the SAID of the proposal — is **never bound**. There is no `getRequest`, no
embed read, and no comparison anywhere in either helper. A joining member waits for a bell and then
builds from its own arguments.

Machine-checked two ways: the syntax tree records both waits with `binds: null`, and neither helper
contains a `getRequest`; and across all eight driven rounds **not one fetches a group request**.

What that costs:

| round | same arguments | different arguments | error |
|---|---|---|---|
| registry | same registry | **different registry** | none |
| issuance | same credential | **different credential** | none |

A registry identifier is a digest over an inception whose **nonce** is inside it; a credential SAID
is a digest over every field of the credential. So one changed nonce or one changed attribute and
the members create different things, each waiting for signatures on an event the others never
built.

**Here** the nonce is read out of the proposed inception and used, and the credential SAID this
member derives is compared with the one it was shown. A mismatch is a typed error.

## The finding: a revocation travels in the issuance slot

`multisigRevoke` builds

```ts
const embeds = { iss: [rev, ''], anc: [anc, atc] };
```

and sends it on `/multisig/rev`. The recorded announcement confirms it: route `/multisig/rev`, slots
`["iss","anc"]`, and the event in that `iss` slot has ilk `rev`. So a reader narrowing through the
reference's own `assertMultisigRev` — which declares `e: { rev, d? }` — finds **no `rev` at all**.
Roadmap 8.4's route-and-embed scan turned this up and left it here.

The exact body the reference sent is proven not to classify in this port, and the revocation
travels in `rev`, which is what the route names and what Roadmap 4.1's schema declares.

## Two smaller findings

**The issuance result drops the signatures it computed.** `IssueCredentialResult` declares
`{ acdc, anc, iss, op }` and no `sigs`, so `issueCredentialMultisig` fetches the group identifier a
second time, rebuilds its keeper, and signs the same anchor bytes again just to build the
attachment. Driven: the issuance round reads `/identifiers/multisig` **twice** where the registry
round, whose endpoint does return its signatures, reads it once. `RevokeCredentialResult` has the
same gap. Roadmap 6.11's `IssuanceArtifacts.anchor` is an `IdentifierArtifact` — the event *with*
its signatures — so nothing is signed twice here.

**One round is filed under a different topic**, and the pinned tree is not consistent with itself:
of its four `/multisig/vcp` sends, three use `registry` and one uses `multisig`. The ported helper
sends the majority form, which is what this port reproduces; the disagreement is recorded rather
than resolved, since nothing in the pinned tree settles which is intended.

## Slots, which these rounds are the exception to

Every other multisig route is named for the slot it embeds. These are not:

| route | discriminating slot | also carries |
|---|---|---|
| `/multisig/vcp` | `vcp` | `anc` |
| `/multisig/iss` | **`acdc`** | `iss`, `anc` |
| `/multisig/rev` | `rev` | `anc` |

An issuance is named for its transaction event and discriminated by its credential, because Roadmap
4.1's union is told apart by field names and an issuance carries three messages. Only the anchor is
signed: the attachment names all three paths but attaches a signature to `anc` alone, because that
signature is what authorizes the rest.

## Contents

- `calls` pins eight: the group's inception; the registry proposed, joined, and joined with a
  different nonce; the issuance proposed, joined, and joined with different attributes; and the
  revocation round.
- `declarations` holds all three helpers' text, every `waitAndMarkNotification` with whether its
  SAID is bound, every `getRequest`, every `exchanges().send` with its route, topic and embed slots,
  both credential result interfaces, and consumer scans over all 117 pinned files.
- `reference_quirks` pins six behaviours, each with what the reference does and what this port does
  instead.

## Determinism

The clock and the agent's key are pinned; the nonce is the one the vLEI scenario itself pins, so the
registry identifier is reproducible. The helpers narrate to `console.log`, which the generator
captures so its own output is only the fixture. `PUBLIC TEST MATERIAL`: the passcode and sealed
salts are the pinned tests' own, recorded as what they open to.

Rust tests consume the checked-in fixture and require neither Node nor network access.
