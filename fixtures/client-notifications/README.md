# Notification endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Secondary reference: `https://github.com/WebOfTrust/keripy.git` at
  `4ce4cc79e06653f77342be1bf604086b89b1f090`, **corroboration only**, for what fills a
  notification's identifier
- Generated: 2026-08-25
- Sources: `src/keri/app/notifying.ts`, `src/keri/app/coring.ts`,
  `src/types/keria-api-schema.ts`, `test/app/notifying.test.ts`,
  `test-integration/utils/test-util.ts`; keripy `src/keri/app/notifying.py`,
  `src/keri/core/coring.py`
- Binary fields: none. Paths, headers, and bodies are exact text; the answers are exact JSON.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_notifications.mjs --write   # regenerate
node tools/reference-vectors/client_notifications.mjs --check   # verify determinism
```

## Determinism

The clock and the agent's key are pinned, as the `client-lifecycle` fixture pinned them, and every
sample nonce is built from a fixed counting pattern rather than drawn. Nothing here derives an
identifier key, so the generator is fast.

## What the evidence is

This port covers `Notifications.{list,mark,delete}` — three methods, one of which is the second
windowed listing in the port (the identifiers listing being the first) and the only one that reads a
`Content-Range` back.

The pinned `notifying.test.ts` case asserts all three paths, all three methods, and the `Range`
header exactly; the generator drives the reference's own class through them, with the recorder able
to set a `Content-Range` so the listing's read-back half is exercised too.

## A notification's identifier is not a SAID

Both single-notification methods name their parameter `said` and their JSDoc says "SAID of the
notification". It is not one, and `notification_identifier` establishes that from source rather than
asserting it:

- keripy's `notice()` builds the record with `i=""`, and its `Dicter` fills an empty identifier with
  `randomNonce()` — recorded with the line and a count of the sites that do it.
- The two references **disagree** about that nonce's code. signify-ts's own `randomNonce` qualifies
  thirty-two bytes under the Ed25519 **seed** code `A`; keripy's qualifies sixteen under the 128-bit
  **salt** code `0A`.
- Neither is a digest code. Samples of all three — both nonces and a real Blake3 SAID — are in the
  fixture, and a Rust test proves that neither nonce parses as a SAID while the digest does.

KERIA is built on keripy, so what a real agent writes is the `0A` form. The argument is therefore
**not** typed as `Said`, which would refuse every identifier a real agent produces. It stays
borrowed text encoded exactly once — the shape the operations endpoint gave an operation name —
which is enough to close the path injection recorded below. The pinned unit test's own literal,
`notificationSAID`, is neither a SAID nor a nonce, which is a third reason not to type it.

## Contents

- `calls` pins twelve requests: six listings covering both real windows, the default, an absent
  `Content-Range`, a fraction, and a reversed pair; three marks including a real nonce and one that
  reshapes the path; two deletes; and a page of the wrong shape. Each records the payload it was
  answered with as well as the wrapper the reference built around it.
- `declarations` pins all three path expressions, the `Range` header construction, the
  `Content-Range` read-back, the flattened return, the `res.text()` that makes `mark` the only method
  to read its answer, and the `undefined` a delete sends. The `Notifications` class's member list is
  asserted.
- `notification_identifier` pins the chain above, across both references.
- `pinned_confirmations` pins the three unit-test assertions, the two addresses, and the three
  integration usages — every one of which passes a runtime `note.i`, which is why the identifier's
  shape had to be established from source.
- `reference_quirks` pins nine behaviours, each with what the reference does and what this port does
  instead.

## Reference behavior recorded as deliberate divergences

- **The identifier is not a SAID**, as above.
- **The window defaults are observable.** `list(start = 0, end = 24)` writes both into the `Range`
  header, so an omitted window still names one. The window is a **required** `ItemRange` here and
  `ItemRange::DEFAULT` names the reference's page — the response decoder had already defined it as
  exactly that.
- **A window bound is not an integer.** Both are `number` and reach the header through template
  interpolation, so `list(1.5, 2.5)` sends `notes=1.5-2.5` and `list(40, 20)` sends a window whose
  end precedes its start. **Refused**: `ItemRange` takes two `u64` and validates the ordering, so
  neither is representable.
- **An absent `Content-Range` becomes three zeroes.** `parseRangeHeaders(null, 'notes')` returns
  `{0,0,0}`, so a page of real notifications reports as an empty window. Reproduced as the response
  decoder decided and the identifier listing applied: the window is an `Option`, so unreported and
  empty stay distinct.
- **The identifier is not encoded.** Both single-notification paths are `'/notifications/' + said`,
  and the `http-request-response` fixture recorded `mark("a?b=c")` turning the path into a query.
  Closed by the builder, which encodes every component exactly once.
- **`mark` returns its body as text.** It is the only method here that reads its answer, and
  `res.text()` replaces any byte that is not valid UTF-8 with U+FFFD rather than failing. The text is
  returned, because the reference genuinely offers it, but decoded **strictly** — the decision
  the credentials endpoint made for a CESR answer read the same way.
- **A delete carries no body**, where `list` and `mark` pass `null`. Reproduced.
- **The page is never typed.** `list` returns `Promise<any>` and its `notes` field is `res.json()`
  with no cast at all — not even the compile-time claim the other families make. **Decoded** into
  `signify_types::api::Notification`, and the recorded wrong-shaped page is proven refused.
- **The window is returned flattened.** The three numbers are spread beside the page, so a caller
  cannot tell them apart. `NotificationListing` keeps them separate, as the identifier listing does.

Rust tests consume the checked-in fixture and require neither Node nor network access.
