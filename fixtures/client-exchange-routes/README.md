# Exchange route table, resource variants, and guards — reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-26
- Sources: `src/keri/app/exchanging.ts`, `src/types/keria-api-schema.ts`,
  `test-integration/multisig.test.ts`
- Binary fields: none. The declarations are exact source text; the verdicts are exact values.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_exchange_routes.mjs --write   # regenerate
node tools/reference-vectors/client_exchange_routes.mjs --check   # verify determinism
```

## Determinism

Nothing here derives a key, builds a client, or reads a clock. Every value is either source text or
the return of a pure function on a literal, so the generator is instant.

## What the evidence is

Roadmap 8.1 ports the half of `exchanging.ts` that Roadmap 7.7 left: thirteen route constants,
thirteen `*Exchange` resource variants, eight `*Group` variants, thirteen `is*` type guards, and
thirteen `assert*` assertions — forty-seven exported symbols, plus the private `assertRoute`.

**The unit under test is a type system**, which no other item in this port has been, so the evidence
has two halves.

The **executed** half. Each of the twenty-six functions was called on a message of its own route, on
a message of another route, on a message whose declared payload is simply absent, and on six shapes
that are not messages at all. Verdicts and exact error text are recorded.

The **declared** half. What each variant says its `e` and `a` blocks contain, read from the
reference's own syntax tree — because there is nothing to execute — and compared with the generated
schema and with what `test-integration/multisig.test.ts` actually sends.

The generator **refuses to write a fixture** if `exchanging.ts` stops exporting exactly thirteen
route constants, if a guard gains a consumer, or if the set of used assertions changes.

## The finding: the narrowing is a claim, not a check

Every one of the twenty-six functions is a single route comparison:

```ts
export function isMultisigIcp(msg: ExnMessage): msg is ExnMessage {
    return msg.exn.r === MULTISIG_ICP_ROUTE;
}
```

The variant it narrows to declares an `e` block and an `a` block, and **neither is looked at**. So
`assertMultisigIcp` accepts a message on `/multisig/icp` carrying no `icp` at all, hands it back
typed as though it did, and the caller's `exn.e.icp` is `undefined` while the compiler insists it is
an inception. That is recorded, executed, for all eight multisig routes: `guard_on_empty_payload` is
`true` and `assertion_on_empty_payload` returns the message.

Here the route selects a shape and the shape is decoded, so a route and a payload that disagree are
a typed refusal.

## Contents

- `route_table` pins all thirteen: the constant, the variant, the group variant, the guard, the
  assertion, each one's full source text, and a consumer scan for each.
- `variant_shapes` pins the `e` and `a` block each variant declares.
- `observed_attributes` pins the attribute labels every `send` call site in the pinned tree passes,
  per route — thirty-eight call sites.
- `executed` pins the twenty-six functions' verdicts across four inputs each.
- `hostile` pins six shapes that are not messages.
- `shape_findings` and `reference_quirks` pin ten behaviours, each with what the reference does and
  what this port does instead.

## Nineteen of twenty-six exports are dead

**None of the thirteen `is*` guards has a caller anywhere in the pinned tree**, and six of the
thirteen `assert*` assertions have none either. The seven that are used account for nineteen call
sites, all in `test-integration/multisig*.test.ts`.

Not ported as functions: a guard is `matches!` on the classified enum and an assertion is `?`, so
neither can drift from the other the way two hand-written functions can. This is the reasoning that
recorded `Unqualified` and `CredentialTypes` as having no Rust equivalent, applied to a capability
the enum simply subsumes.

## Reference behavior recorded as deliberate divergences

- **A guard narrows without checking**, as above. **Decoded here.**
- **The guards have no consumers.** Not ported as functions.
- **A guard and its assertion fail differently on a malformed message.** `assertRoute` reads
  `msg.exn?.r` and every guard reads `msg.exn.r`, so a value with no `exn` gives the assertion a
  clean `Error` and the guard a `TypeError` — two functions one question mark apart, and a caller
  has to catch both. **Unrepresentable here**: a classified message comes from a typed resource,
  which has no shape without its `exn`.
- **The failure message repeats the route.** `Expected ${label} but got route: ${msg.exn?.r}`
  interpolates an agent-supplied value; a message whose route *is* the label text produces
  `Expected Multisig ICP message but got route: Multisig ICP message`. **The refusal here names the
  slot expected and the slot found**, both bounded.
- **The route table is not closed.** Thirteen constants, and the reference's own
  `Challenges.respond` sends a fourteenth, `/challenge/response`, which every guard returns false
  for and every assertion throws on. **An unnamed route classifies here** rather than failing.
- **Only multisig routes have a group variant.** Eight `*Group` types, none for IPEX — so
  `assertIpexGrant` on a group request returns an unnarrowed value. **One classifier over both
  containers here**, so the asymmetry disappears.
- **The hand-written revocation variant hides its anchor.** `MultisigRevExchange` declares
  `e: { rev, d? }` where the generated schema's `MultisigRevokeEmbeds` declares `{ rev, anc }`, so a
  caller narrowing through `assertMultisigRev` cannot reach the anchoring key event — while the
  registry and issuance variants, whose schema counterparts carry the same field, both expose it.
  **Roadmap 4.1 modelled the schema and this port keeps the anchor.**
- **A grant and an issuance declare the same embed.** `IpexGrantExchange.e` and
  `MultisigIssExchange.e` are structurally identical, so one shape serves two routes on opposite
  sides of the table. **Reused rather than duplicated**, which is why eight schema embed shapes
  cover nine of the thirteen routes.
- **The schema models no IPEX embed.** Its `ExnEmbeds` union has exactly eight members, all
  multisig; an offer's `{ acdc }` is not among them. **Modelled here** rather than added to Roadmap
  4.1's enum, because widening a verified untagged enum would change how existing documents decode.
- **The schema names no group attribute.** `gid`, `smids`, and `rmids` appear **zero** times in it,
  so the `a` block shapes exist only in the hand-written variants — which is why they are checked
  against what the integration tests send. **One `GroupAttributes` value here**, with the route
  deciding which optional fields are required.

Rust tests consume the checked-in fixture and require neither Node nor network access.
