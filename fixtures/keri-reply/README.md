# KERI reply-message reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-19
- Sources: `src/keri/core/eventing.ts`, `test/app/aiding.test.ts`
- Binary fields: `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message bytes;
  `raw` is the same bytes as text and the two are cross-checked on load.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/keri_reply.mjs --write   # regenerate
node tools/reference-vectors/keri_reply.mjs --check   # verify determinism
```

## Why this fixture is small

`exported_builders` records every function the pinned `eventing.ts` actually exports:

```
ample, incept, interact, messagize, reply, rotate
```

Roadmap 3.5 ported four of those and `messagize` belongs to Roadmap 3.7, which leaves **`reply`
alone** in Roadmap 3.6. The reference has no receipt, query, or key-state builder to port. The
`ilks` list confirms the other half of that finding: the ilk table declares `rct` and `vrc`, which
nothing in the pinned source ever constructs, and does not declare `qry` at all. Both lists are
asserted by the Rust test, so the `N/A` decisions in `PORTING.md` §5.3 rest on recorded evidence
rather than on a reading of the source.

## Contents

`cases` records six replies with their exact bytes, route, timestamp, attributes, SAID, and version
string:

- `end_role_add` and `loc_scheme` are the two routes the pinned `test/app/aiding.test.ts`
  exercises, using the stamp `2021-06-27T21:26:21.233257+00:00` that test asserts.
- `empty_route_and_attributes` covers both of the reference's defaults.
- `nested_attributes` covers a nested attribute block.
- `non_ascii_route` covers a route whose byte length exceeds its character count, which is what the
  version string has to count.
- `one_microsecond_later` differs from another case only in the last digit of the timestamp, and
  has a different identifier — the stamp is committed to.

## Reference behavior recorded as safe Rust divergences

- **The timestamp defaults to the system clock.** With no stamp the reference calls
  `new Date().toISOString()` and rewrites the trailing `Z` as `000+00:00`, so the message — and
  therefore its SAID — depends on when it was built. The fixture records the *shape* with every
  digit masked to `9`, so it stays reproducible while still pinning the format and length. Rust
  requires the timestamp as a validated parameter: a protocol crate never reads the clock, which is
  what keeps event construction deterministic and testable.
- **Any string is accepted as a timestamp.** The stamp is interpolated without validation, so the
  fixture records replies whose `dt` is `not-a-timestamp` and the empty string — values every
  recipient must then accept, because the SAID commits to them. Rust parses the field into a
  validated `Timestamp` first.
- **Attributes need not be a map.** The `data` argument is typed `any` and written through
  unchanged, so the fixture records replies asserting a bare string, an array, and a number where
  the protocol expects an attribute block. Rust takes a field map, the only shape the protocol
  defines.
- **Null attributes become an empty map.** The guard is `data == undefined`, whose loose equality
  also matches `null`, so `null` silently becomes `{}` instead of being written as `null`. Rust
  defaults to an empty map and cannot express a null attribute block.
- **The post-derivation check is unreachable.** `reply` re-verifies the SAID it just derived with
  both the `prefixed` and `versioned` flags set; `saidify` has already written that exact
  identifier and version string, so the throw is dead code. Rust derives once, and the property
  tests assert the invariant the check was reaching for.

Rust tests consume the checked-in fixture and require neither Node nor network access.
