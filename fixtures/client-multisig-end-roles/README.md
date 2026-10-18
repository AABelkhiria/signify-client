# Multisig agent end-role reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-09-17
- Sources: `test-integration/utils/multisig-utils.ts`, `test-integration/endroles-by-aid.test.ts`,
  `test-integration/utils/test-util.ts`, `test/app/test-utils.ts`
- Binary fields: none. Paths and bodies are exact text; the answers are exact JSON.

Generate and verify from the repository root after installing the pinned references:

```bash
npm ci --prefix tools/reference-vectors
node tools/reference-vectors/client_multisig_end_roles.mjs --write   # regenerate
node tools/reference-vectors/client_multisig_end_roles.mjs --check   # verify determinism
SHOW_ERRORS=1 node tools/reference-vectors/client_multisig_end_roles.mjs   # trace a failing call
```

## What the evidence is

This port covers the round that authorizes a group's agents. A group identifier has no agent
endpoint until its members authorize one, so until this round completes nothing addressed to the
group reaches any member's agent but the sender's — which is why the group IPEX rounds could not be
driven between two agents before it.

There is no source file. The unit is `addEndRoleMultisig` in `test-integration/utils/multisig-utils.ts`,
called by three integration scenarios, so the helper module is **transpiled in memory** by the
reference's own pinned TypeScript and evaluated with a module shim, as the
`client-multisig-inception` generator does. Nothing is written into the submodule. Six calls are
driven: the group's inception, the proposing half, the joining half, the joining half a second
later, a proposal against a stale group state, and a proposal where one member authorizes no agent.

## The finding: the members agree only on a shared stamp

A reply's SAID covers its `dt`, so members sign the same reply only if they stamp it identically.
The joining half waits for as many `/multisig/rpy` notifications as there are signing members,
**discards them**, and builds from its own `timestamp` argument; the scenarios agree only because one
process hands every member one `stamp`. Driven a second apart, the two members sign different
replies, the group reaches its threshold on none, and neither call fails. `accept_end_role` here
takes no timestamp: the stamp, the role, and the endpoint are read out of the proposal, and the reply
this member derives is compared with the one it was shown before anything is signed.

## Three smaller findings

**Every member's agent is authorized**, one reply and one announcement each, read as
`Object.keys(signing.ends.agent)[0]`. This is the behaviour worth keeping: authorizing only the
proposer's agent would leave every other member unreachable through the group.

**A member with no agent throws part way through the loop**, after the members before it were
already authorized and announced, leaving the round half done. `member_agents` reads every member's
agent before anything is submitted and refuses with `MemberHasNoAgent`.

**The seal is the group state the caller passed in**, not the state the agent holds, so a caller
still holding the group from before a rotation seals every reply to a superseded establishment event.
Driven with a stale record, the announcement's attachment names the stale digest. Here the seal is
read from the group's record as the agent reports it.

## Contents

- `declarations` holds the helper's text, its one notification wait, its zero proposal reads, its one
  send, and the lines that read the agent and the seal.
- `provenance` names the reference files each declaration and request was read from.
- `key_states`, `identifier_record`, and `group_record` are the member's key state, its identifier
  record, and the group's record the driven calls answer with.
- `members` and `members_without_an_agent` are the listings the driven calls answer with.
- `calls` pins six, each with its requests and the notifications its joining half waited for.
- `pinned_confirmations` names the group, the stamp, both agents, and the routes.
- `reference_quirks` pins five behaviours, each with what the reference does and what this port does
  instead.

## Determinism

The clock and the agent's key are pinned, and the local member is the reference's own `mockGetAID`.
`PUBLIC TEST MATERIAL`: the passcode and sealed salt are the pinned tests' own.

Rust tests consume the checked-in fixture and require neither Node nor network access. The driven
half runs this port's own client at the ephemeral derivation cost against a scripted agent answering
with these records, and requires its replies and their attachments to equal the reference's byte for
byte.
