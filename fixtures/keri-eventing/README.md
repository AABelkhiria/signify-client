# KERI core key-event reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-19
- Sources: `src/keri/core/eventing.ts`, `test/core/eventing.test.ts`
- Binary fields: `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact event bytes;
  `raw` is the same bytes as text and the two are cross-checked on load.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/keri_eventing.mjs --write   # regenerate
node tools/reference-vectors/keri_eventing.mjs --check   # verify determinism
```

All keys are derived from the two seeds the pinned unit test uses, plus a deterministic family
obtained by varying the last seed byte, so every case is reproducible without stored secrets.

## Contents

`cases` records twenty complete events with their exact bytes, identifier, SAID, sequence number,
and version string:

- `pinned_non_transferable_inception`, `pinned_transferable_inception`,
  `pinned_self_addressing_inception_text`, and `pinned_self_addressing_inception_integer` are the
  four inception events the pinned unit test asserts byte for byte. The last two differ only in
  the reference's `intive` flag, which changes `kt`, `nt`, and `bt` from strings to JSON numbers
  and therefore changes the identifier.
- `multisig_inception`, `weighted_inception`, and `multi_clause_weighted_inception` cover more than
  one key with numeric, single-clause weighted, and multi-clause weighted thresholds. A single
  clause is written as one flat array; several clauses nest.
- `witnessed_inception_default_toad` and `witnessed_inception_integer_toad` cover the witness list
  with a derived and an explicit threshold.
- `configured_and_anchored_inception` covers configuration traits and anchored seals.
- `abandoned_inception` commits to no next keys, so the identifier can never rotate.
- `delegated_inception` is a `dip` event; its delegator field is written last, after the anchors.
- `rotation`, `delegated_rotation`, `rotation_text_encoding`, `rotation_high_sequence_number`,
  `rotation_with_witness_changes`, and `rotation_with_anchors` cover `rot` and `drt`.
- `interaction` and `interaction_with_anchors` cover `ixn`.

`ample_table` and `ample_explicit` pin the witness fault-tolerance helper for fourteen witness
counts under both majorities, plus four explicit fault counts. Six and nine are the only counts
below ten where the two majorities differ, which is why the reference evaluates both fault
estimates.

`rejected_cases` pins the reference's error class and message for nineteen malformed inputs:
unmeetable signing thresholds, duplicate and inconsistent witness lists, witness thresholds that do
not fit their set, non-transferable identifiers committing to a future, a delegated identifier with
a basic prefix, sequence number zero for a rotation or interaction, and an impossible fault count.

## Reference defects recorded as safe Rust divergences

Each is reproduced in the fixture from the pinned checkout, so the incompatibility is documented
and detectable rather than assumed.

- **Multi-key inception is unreachable.** With more than one key and no explicit code the prefix
  branch falls through to `new Prefixer({code: undefined}, sad)`, whose second `super()` call
  receives the still-empty identifier field and throws `Empty Material`. Multisig inception cannot
  be built through the documented path at all. Rust defaults to the self-addressing derivation
  whenever a basic prefix cannot represent the event, producing exactly the event the reference
  builds when given `code: E` — the fixture asserts that equivalence directly.
- **The next-threshold field takes its encoding from the current threshold.** `incept` tests
  `tholder.num` — the *current* threshold — before writing `ntholder.num`. A weighted current
  threshold therefore forces the next one to text even under integer encoding. This is
  **reproduced exactly**, because it changes the bytes the identifier commits to; diverging would
  make Rust and the reference derive different AIDs from the same inputs.
- **The mirror case drops the field entirely.** With a numeric current threshold, a weighted next
  threshold, and integer encoding, the same condition writes `ntholder.num`, which is `undefined`
  for a weighted threshold; `JSON.stringify` then omits the key. The reference emits an event with
  **no `nt` field at all**, and its SAID commits to that malformed shape. The fixture records the
  exact bytes. Rust refuses with `UnrepresentableNextThreshold` rather than producing a
  structurally invalid event.
- **The next threshold is validated against the current key count.** `incept` compares
  `ntholder.size` against `keys.length` instead of `ndigs.length` — the error message even
  interpolates `ndigs`. This both rejects a valid commitment (one key rotating to a 2-of-2 next
  set) and accepts an unsatisfiable one (a 2-of-nothing next threshold). The fixture records both.
  Rust validates against the digest count.
- **An inferred basic prefix skips its own checks.** When the derivation is inferred from a single
  key the reference *parses* that key rather than deriving from the event, so the non-transferable
  emptiness checks never run. The fixture records two events the reference happily builds: a
  non-transferable identifier that commits to next keys, and one that anchors data — identifiers
  that can never rotate yet promise a future. Rust always derives, so the same checks apply however
  the derivation was chosen.
- **Rotation cannot abandon an identifier.** `rotate` defaults the next threshold to at least one
  and rejects an explicit zero, so no rotation it builds can ever be the last one, even though
  `incept` has no such restriction. Rust allows an empty next-key commitment in a rotation.
- **Rotation ignores its configuration argument.** `RotateArgs` accepts `cnfg` and never writes it;
  the fixture records the resulting field list. Rust's rotation builder exposes no configuration
  setter.
- **Rotation omits an absent identifier or prior digest.** Both are optional, and an absent one is
  simply not written, producing an event with no `i` or no `p` whose SAID commits to that shape.
  The fixture records both. Rust requires them as constructor arguments.

Rust tests consume the checked-in fixture and require neither Node nor network access.
