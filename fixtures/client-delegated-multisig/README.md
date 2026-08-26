# Delegated multisig reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-26
- Sources: `test-integration/utils/multisig-utils.ts`,
  `test-integration/delegation-multisig.test.ts`, `test-integration/utils/test-util.ts`,
  `test-integration/multisig.test.ts`, `test/app/test-utils.ts`
- Binary fields: none. The paths and bodies are exact text; the answers are exact JSON.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_delegated_multisig.mjs --write   # regenerate
node tools/reference-vectors/client_delegated_multisig.mjs --check   # verify determinism
SHOW_ERRORS=1 node tools/reference-vectors/client_delegated_multisig.mjs   # trace a failing call
```

## What the evidence is

Roadmap 8.6 ports the case where **both sides of a delegation are groups**: a delegatee group whose
inception names a delegator, and a delegator group that approves it by each of its members anchoring
the same seal and telling the others. It composes the three items before it — 8.3's group inception,
8.4's interaction announcement, and 8.5's approval address — and it is the first place in the port
where a **delegated inception** is driven at all.

The unit is `delegateMultisig`, which lives in the reference's integration utilities, so
`multisig-utils.ts` is **transpiled in memory** by the reference's own pinned TypeScript and
evaluated with a three-entry module shim, exactly as Roadmap 8.3's generator does. Nothing is
written into the submodule.

One shim entry is new. `delegateMultisig` calls `assert`, and `import assert from 'assert'`
transpiles to `assert_1.default`, which node's CommonJS module does not have — so the shim supplies
the real module with a `default`. It must be the real one, because **what that assertion does is
the finding**.

## The finding: one index, and a check in the wrong place

The joining half reads

```ts
anchor = (ixn.a as Array<{ i: string; s: string; d: string }>)[0];
```

— the **first seal and no other** — where Roadmap 8.4's plain interaction round reads `ixn.a` whole.
Both readings of one field live in the same tree. Driven:

| | seals anchored | event |
|---|---|---|
| initiator | 2 | `EK6…` |
| joining member | **1** | a different digest |

No error on either side. The second delegation is never approved, the two members sign different
events, and the group never reaches its threshold.

And the one check the reference performs anywhere in the multisig tree —

```ts
const expectedAnchor = Array.isArray(delResult.serder.sad.a) ? delResult.serder.sad.a[0] : ...;
assert.equal(JSON.stringify(expectedAnchor), JSON.stringify(anchor));
```

— compares the **first seal of what it built** against the **whole anchor it was given**, and fires
*after* `approve` has already been awaited. So a two-seal approval:

1. reaches the delegator's log — recorded, `POST /identifiers/delegators/delegation`;
2. then throws `AssertionError`;
3. and the peers are never told — no `/exchanges` request is made.

The caller gets an exception instead of the operation it needs to wait on, and the anchor is already
irreversible. The one check is placed after the irreversible step and compares the wrong shape.

**Here** the seals are checked before anything is written, all of them are anchored, and the joining
half compares the event it built with the digest the proposal carries — before announcing.

## The delegated inception

The same helper incepts both groups, and the only difference in the request is `delpre`, which
becomes the event's `di` and changes its ilk from `icp` to `dip`. Roadmap 8.3's fixture drove only
undelegated groups; this one drives both, and shows that Roadmap 8.1's inception embed — which
accepts either ilk — classifies a delegated group proposal like any other.

## Contents

- `calls` pins seven: the delegator group's inception; the delegatee group's, with a `delpre`; the
  initiator's approval and the joining member's; the two-seal approval that fails its own assertion
  after posting; a two-seal announcement built from the reference's own primitives, since the helper
  cannot send one; and a join of that announcement, which drops the second seal.
- `declarations` holds the helper's whole text and signature, every read of an embedded
  interaction's seal list with whether it takes one or all, every `smids`/`rmids`/`recp` expression,
  its one assertion, both inception argument objects, and consumer scans over all 117 pinned files.
- `reference_quirks` pins six behaviours, each with what the reference does and what this port does
  instead.

## Reference behavior recorded as deliberate divergences

- **The joining member takes only the first seal**, as above. **Every seal is read here.**
- **The check fires after the approval is already posted**, as above. **Checked before writing.**
- **`rmids: smids` a third time.** Roadmap 8.3 recorded it in the accepting half of an inception and
  8.4 found it again at one of two rotation call sites; here it is unconditional, with no rotation
  set consulted at all. **The two sets are separate arguments here.**
- **The member list is hand-assembled** from the local member plus whatever the caller passed, in
  the caller's order, rather than read from the group's own key states. The delivery list *does*
  exclude the sender here, which is what 8.3's proposing half fails to do. **Read from the record
  here**, with 8.3's `delivery_list` deciding who is told.
- **The reference checks its own work exactly once**, and it is this helper, and it is in a test
  tree so no consumer of the library gets it. **Moved into the port**, on every round.
- **A delegated group inception is a `dip`**, which is reproduced.

The scenario also reads a group's own prefix out of `opDelegatee1.name.split('.')[1]` — twice — which
Roadmap 8.5 recorded for a single-signature delegate and this item finds again for groups.

## Determinism

The clock and the agent's key are pinned. The helper narrates to `console.log`, which this generator
captures so its own output is only the fixture. `PUBLIC TEST MATERIAL`: the passcode and sealed
salts are the pinned tests' own, recorded as what they open to rather than as blobs only the
reference's controller can open.

Rust tests consume the checked-in fixture and require neither Node nor network access.
