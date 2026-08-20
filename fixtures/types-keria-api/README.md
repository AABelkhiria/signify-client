# KERIA API type reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-20
- Sources: `src/types/keria-api-schema.ts`, `src/keri/core/keyState.ts`,
  `scripts/generate-types.js`, `test/app/test-utils.ts`, `test/app/registry.test.ts`
- Binary fields: none. Every value is JSON.

Generate and verify from the repository root — no build step is needed, because nothing is
executed:

```bash
node tools/reference-vectors/types_keria_api.mjs --write   # regenerate
node tools/reference-vectors/types_keria_api.mjs --check   # verify determinism
```

## Why this fixture is different

Every other generator here calls a function and records what it returns.
`src/types/keria-api-schema.ts` declares *types*, which do not exist at run time and cannot be
called. The reference for this module is therefore the TypeScript compiler itself, used two ways.

**The declaration is read, not transcribed.** `schemas` holds all 150 schemas exactly as the pinned
file writes them — every field, whether it is optional, and the type it is written as — extracted
from the syntax tree. `enums` holds the six enum declarations, `key_state_exports` the 78 aliases
`keyState.ts` defines, and `key_state_functions` its two exported guards. A Rust test asserts its
own model against this, so a schema drifting out from under the port becomes a failing test rather
than a silent incompatibility.

**Documents are type-checked.** Each entry in `documents` is a JSON document checked against a named
schema by the pinned compiler, twice:

- `literal_accepted` — written as an object literal, which is what a TypeScript author writes. This
  also applies the excess-property check.
- `structural_accepted` — assigned through an inferred variable, which suppresses the
  excess-property check but widens literal types.

Each document also records `rust_type` and `rust_expected`: what this port decodes it as and whether
decoding succeeds. `divergences` lists, computed rather than transcribed, every document the two
decide differently.

## Provenance of the OpenAPI document

There isn't one. Upstream generates `keria-api-schema.ts` with
`node scripts/generate-types.js`, which fetches `http://localhost:3902/spec.yaml` — a **live KERIA
agent**. That document is checked in nowhere in the pinned repository, carries no revision, and
cannot be fetched from the pinned checkout. The generated TypeScript is therefore the pinned
artifact and the only reproducible source, which is why these Rust records are curated against it
rather than regenerated from the schema it came from. `docs/adr/0012-keria-api-record-types.md`
records the decision; it closes the `PORTING.md` §10 "KERIA OpenAPI source revision/generator"
question with the finding that no such revision exists to pin.

## What the two verdicts show

Neither column is "the reference accepts this response". TypeScript performs **no runtime
validation at all**: every KERIA response reaches application code through an unchecked
`await res.json()` cast. The declared type is a claim about what the caller asked for. The columns
measure how a TypeScript author's own code would be checked, which is the only executable statement
the reference makes about these shapes.

Two systemic effects fall out of that and explain most of the divergence table:

- **A TypeScript enum is nominal.** A decoded JSON document can never satisfy a schema whose field
  is typed as one, because the string `"iss"` is not assignable to `IssEventT`, `"low"` is not
  assignable to `Tier`, and `"agent"` is not assignable to `OOBIRole`. That makes `IssEvent`,
  `SaltyState` (and so every salty `HabState`), `RegistryState`, `CredentialState`, `Credential`,
  `Registry`, and `OOBI` unsatisfiable by any response — the very types upstream casts responses to.
  Rust accepts these documents; the divergence is against a compile-time artifact the reference's
  own run time ignores.
- **A literal type widens through a variable.** `done: false` inferred from an object becomes
  `boolean`, which no operation arm accepts, so `operation_pending` is `literal_accepted` but not
  `structural_accepted`. The `Operation` union is usable only for a directly written literal.

## Documents recorded as safe Rust divergences

- **An unknown field.** `key_state_unknown_field` is refused by the excess-property check and
  accepted structurally and at run time. Rust accepts and ignores it, so a newer agent adding a
  field does not break an older client. Where the schema declares an index signature —
  `acdc_attributes_open_block`, `hab_extern_open_block`, `contact_open_block`, and the notification
  payload — the unknown fields are captured and survive a round trip instead.
- **An ilk outside the union.** `key_event_receipt_ilk` is an interaction relabelled `rct`. The
  schema types every message's `t` as a bare string, so the reference accepts it as a `KeyEvent`;
  Rust chooses the record from that field, so it refuses.
- **Two key managers at once.** `hab_two_key_managers` names both `randy` and `extern`. TypeScript's
  excess-property check permits a property belonging to *any* arm of a union, so the reference
  accepts a record whose key manager is undecided; Rust returns
  `ApiError::AmbiguousKeyManagerState`.
- **A fractional sequence number.** `anchor_fractional_sequence_number` carries `sn: 1.5`, which the
  schema's `number` admits; Rust decodes an anchor's sequence number as an unsigned integer.
- **A role outside the nine declared.** `oobi_unknown_role` is refused by the reference's `OOBIRole`
  enum while `end_role_unknown_role`, the same text in the field the schema types as a bare string,
  is accepted — the schema is inconsistent about this. Rust reads both, keeping an unnamed role as
  `Role::Other`, because KERI's role registry is extensible.
- **An absent nullable field.** `member_ends_missing_a_role` omits `juror` and
  `agent_resource_result_upstream_mock` omits `sxlt`; the schema requires both, with a `null`
  default. Rust treats an absent value and an explicit `null` alike, as one rule rather than a
  per-field judgement, so it accepts both.

## Documents recorded as the reference refusing its own test mocks

- `agent_resource_result_upstream_mock` is `mockConnect` from `test/app/test-utils.ts` verbatim. The
  schema requires `sxlt`; the mock omits it, and the compiler refuses it as an
  `AgentResourceResult`. Rust accepts it, because `sxlt` is nullable — see the rule above.
- `hab_upstream_mock_without_inception_stamp` is `mockGetAID` verbatim. The schema requires
  `icp_dt`, which is **not** nullable; the mock omits it. Both refuse it.
- `operation_done_without_result` is the `{ name, done: true }` body `test/app/coring.test.ts`
  returns from its mocked fetch. It matches no arm of the `Operation` union, because a finished
  operation carries a response or an error. Both refuse it.

These are recorded because they are the only KERIA-shaped documents in the pinned repository, and
their looseness is the reason this port follows the schema rather than the mocks. A live-deployment
check belongs to Roadmap 9.2.

Rust tests consume the checked-in fixture and require neither Node nor network access.
