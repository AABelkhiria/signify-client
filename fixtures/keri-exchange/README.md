# KERI exchange-message reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-19
- Sources: `src/keri/app/exchanging.ts` (the pure `exchange(...)` function),
  `test/app/exchanging.test.ts`
- Binary fields: `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message bytes;
  `raw` is the same bytes as text and the two are cross-checked on load. `attachments` is the
  transposed CESR stream as text, which is ASCII by construction.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/keri_exchange.mjs --write   # regenerate
node tools/reference-vectors/keri_exchange.mjs --check   # verify determinism
```

## Why the pinned unit test is not the parity evidence

`test/app/exchanging.test.ts` asserts two exchange messages, and its inputs are the text `test` as
the sender, the empty string as the recipient, and `2023-08-30T17:22:54.183Z` as the timestamp.
None of the three is a value the protocol defines: the reference simply interpolates whatever it
is given. The Rust builder takes `IdentifierPrefix` values and a validated `Timestamp`, so it
cannot express any of them, and the identifiers that test asserts are unreachable from valid input.

Both of its vectors are therefore recorded verbatim under `upstream_unit_test`, together with the
identifiers the test asserts, and the Rust test proves that each of the three inputs is refused on
its own. Byte parity is proven instead by `cases`, which drives the same reference function with
real prefixes and the reference's own default timestamp format — the 32-character
`…183000+00:00` shape its `nowUTC` path emits. The transposed attachment group is identical in
both, differing only in the embed label, which the Rust test asserts directly.

## Contents

`cases` records eleven messages with their exact bytes, inputs, identifiers, version string, and
transposed attachment stream:

- `no_embeds` is the minimal message: no payload, no modifiers, no embeds.
- `ipex_apply_payload` carries the attribute shape `Ipex.apply` builds.
- `prior_and_modifiers` chains to the identifier of `no_embeds` and carries a nonempty `q` block,
  including an integer modifier.
- `basic_prefix_sender` sends from an Ed25519 basic prefix rather than a self-addressing one.
- `embed_without_attachment` carries an embed that transposes nothing.
- `embed_with_signature_group` transposes a complete controller signature group (`-AAB…`) for one
  of two embeds — the shape `SignedMessage::attachments` produces.
- `embed_with_bare_signature` transposes a bare indexed signature, which is what the pinned unit
  test does.
- `two_attachments` transposes two groups, and its four-character label exercises a different
  Base64-text lead size in the path.
- `empty_attachment` covers the reference's `atc == undefined` guard: an empty attachment is not
  absent, so the path is written with no material after it.
- `non_ascii_payload` makes the message's byte length exceed its character count, which is what the
  version string has to count.
- `wide_quadlet_count` needs both Base64 digits of the pathed-material count.

Each case also records `reparse`: the reference re-read the exact bytes, re-serialized them
identically, and agreed on the size and identifier. Because the Rust test asserts its own output is
byte-identical to `raw` first, that records the reverse direction — the reference accepting what
Rust produces.

`count_boundary` pins the pathed-material counter's own limit, which both implementations enforce:
4095 quadlets including the three the attachment path occupies. The accepted case's 16 KiB stream
is elided — its prefix, length, and SHA-256 are recorded, and its body is a single repeated
character, so the Rust test reconstructs and checks it without the fixture carrying it. One quadlet
more and the reference throws `Invalid count=4096 for code=-L.`; Rust returns
`AttachmentTooLarge`.

## Reference behavior recorded as safe Rust divergences

- **The timestamp defaults to the system clock.** As in the reply fixture, the shape is recorded
  with every digit masked to `9` so the fixture stays reproducible. Rust requires a validated
  `Timestamp`.
- **The sender and the recipient are unvalidated text.** Neither is parsed, so the fixture records
  a message sent from `test` to `not-a-prefix`. Rust takes `IdentifierPrefix` values.
- **The payload overrides the recipient.** The attribute block is built as
  `{...{i: recipient}, ...payload}`, so a payload field named `i` silently readdresses the
  attributes while the top-level `rp` still names the original recipient. The fixture records such
  a message; Rust returns `PayloadOverridesRecipient`.
- **An embed labelled `d` destroys itself.** The embeds block's own identifier field is written
  after the embeds, so the embedded message is overwritten by the block SAID and disappears. The
  fixture records the resulting `"e":{"d":"E…"}`; Rust reserves the label.
- **An embed labelled `v` throws.** A `v` at the top of the embeds block makes the SAID machinery
  treat the block as a versioned message; the recorded error is
  `Invalid version string = [object Object]`. Rust reserves the label too, with a typed error.
- **A separator in a label changes the path.** The label is written into the attachment path
  unescaped, so `a-b` yields `-e-a-b`, which parses back as three components naming a different
  field entirely; the reference's own `-` check never runs on it. Rust validates the label as a
  path component at construction.
- **An empty label is accepted.** It produces the path `-e-`, an identity step naming no field.
- **Numeric labels are hoisted.** JavaScript enumerates array-index-like keys first, so an embeds
  block inserted as `2, 1, a` is written `1, 2, a`; a numeric label is also an ordinal rather than
  a field in an attachment path. Rust refuses numeric labels, consistent with ADR `0008`'s decision
  to preserve insertion order.
- **A misaligned attachment truncates its count.** The count is `Math.floor(length / 4)`, so a
  three-byte attachment produces a nineteen-character group whose counter covers twelve — the tail
  falls outside the group a parser reads and corrupts whatever follows it. Rust returns
  `NonIntegralAttachment`.
- **A non-CESR attachment is embedded verbatim.** The attachment is concatenated without
  inspection, so the fixture records `{"a"` injected into the CESR stream a recipient parses. Rust
  returns `InvalidAttachmentText` with the offending offset.
- **The payload and the modifiers need not be maps.** Both arguments are `Dict<any>` and written
  through unchanged; spreading the string `hello` into the attribute block even produces one field
  per character. Rust takes field maps.

Rust tests consume the checked-in fixture and require neither Node nor network access.
