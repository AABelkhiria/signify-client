# KERI CESR attachment reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-19
- Sources: `src/keri/core/eventing.ts`, `src/keri/core/utils.ts`, `test/core/eventing.test.ts`
- Binary fields: `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message bytes;
  `raw` is the same bytes as text and the two are cross-checked on load. Each case also records the
  `event` and `attachments` halves separately, and the Rust test asserts they reassemble.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/keri_attachment.mjs --write   # regenerate
node tools/reference-vectors/keri_attachment.mjs --check   # verify determinism
```

## Contents

`cases` records seven complete messages — a serialized event followed by its CESR attachment
stream:

- `pinned_controller_signature` and `pinned_seal_event` are the two the pinned
  `test/core/eventing.test.ts` asserts verbatim, using the seed, event, and signature that test
  uses.
- `pipelined` prefixes the stream with an attached-material quadlet count (`-VAX`).
- `two_signatures` shows the controller counter tracking the signature count.
- `seal_last` uses the transferable last-establishment group (`-HAB`), which names only the
  identifier.
- `seal_event_at_sequence_one` seals against a non-zero position.
- `seal_event_pipelined` combines a seal with pipelining.

`seal_sources` records the two standalone serializers from `utils.ts`: `serializeACDCAttachment`,
a seal-source **triple** (`-IAB`, identifier + sequence + digest, unframed), and
`serializeIssExnAttachment`, a seal-source **couple** (`-GAB`, sequence + digest, pipelined). The
reference bakes the framing choice into the two function names; Rust makes it an argument, so the
other two combinations are expressible too.

## Reference defects recorded as safe Rust divergences

- **The witness and receipt paths cannot be reached at all.** Both guard with
  `!(verfer.code in NonTransDex)`. The `in` operator tests an object's *property keys* — which are
  names like `Ed25519N` — not its values, which are the codes `B`, `1AAA`, `1AAC`, `1AAI`. The
  fixture records `"B" in NonTransDex` as `false`, so the guard is true for every code and any
  signature carrying a verifier is rejected as "transferable" whether it is or not. A `Signer`
  always attaches one. The fixture records all three attempts throwing, **including the one with a
  genuinely non-transferable key**. Both paths also write `ControllerIdxSigs` rather than the
  witness or receipt-couple counter, so anything that did get through would be misparsed by a peer
  as controller signatures. Witness-signature and non-transferable-receipt-couple groups are
  therefore recorded `BLOCKED` in `PORTING.md` rather than implemented: with no reachable reference
  behavior there is nothing to verify a Rust encoding against, and inventing one would ship an
  unverifiable wire format.
- **Seal sequence numbers are read as decimal.** The seal's `s` field is parsed with `parseInt`,
  but KERI sequence numbers are hexadecimal. The fixture records the consequences: hex `a` — ten —
  becomes `NaN` and encodes **identically to zero**, and hex `10` — sixteen — encodes as ten. A
  seal built this way silently references the wrong event, which is exactly the binding a
  signature depends on. Rust's seal takes a typed sequence number, so no text parsing happens.
- **An unknown seal tag is silently dropped.** The tag is compared against two string literals and
  anything else falls through, so a misspelled tag produces a message with no seal rather than an
  error. The fixture records the resulting attachments starting at `-AAB` with no `-FAB` group.
  Rust's seal is an enum, so an unknown variant cannot be expressed.

Rust tests consume the checked-in fixture and require neither Node nor network access.
