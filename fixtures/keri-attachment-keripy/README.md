# KERI witness and receipt attachment reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-08-19
- Sources: `src/keri/core/eventing.py` (`messagize`), `src/keri/core/coring.py` (`NonTransDex`)
- Binary fields: `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message bytes;
  `raw` is the same bytes as text and the two are cross-checked on load. Each case also records the
  `event` and `attachments` halves separately, and the Rust test asserts they reassemble.

## Why keripy and not signify-ts

The primary reference cannot emit witness indexed-signature groups or non-transferable receipt
couples at all: its guards translate Python's value-membership `code not in NonTransDex` into a
JavaScript `in`, which tests property *keys*, so every signature carrying a verifier is rejected —
and both paths also write the controller counter, so anything that got through would be misparsed.
`fixtures/keri-attachment/README.md` records all three attempts throwing. keripy — the canonical
KERI implementation, which KERIA itself is built on — implements both paths correctly: its codex
`__iter__` yields the code values (`B`, `1AAA`, `1AAC`, `1AAI`), so the guard is reachable, the
witness group is introduced by `-B` (`WitnessIdxSigs`) and the receipt group by `-C`
(`NonTransReceiptCouples`), and a transferable key is rejected with a `ValueError`. ADR 0009
records the decision to verify these two group kinds against keripy.

## Generation

The generator needs a Python 3.12+ environment with the pinned `reference/keripy` checkout
installed. From the repository root:

```bash
uv venv --python 3.12 .venv-keripy
uv pip install --python .venv-keripy/bin/python ./reference/keripy
.venv-keripy/bin/python tools/reference-vectors/keri_attachment_keripy.py --write   # regenerate
.venv-keripy/bin/python tools/reference-vectors/keri_attachment_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## Contents

Deterministic inputs: the event and controller signature are the exact pinned pair from
`fixtures/keri-attachment/v1.json`, reused verbatim so both fixtures describe the same message;
the two witness signers use the seed byte sequences `0..31` and `32..63` (recorded as
`witness_seeds_hex`), non-transferable Ed25519 (`B` prefixes). Ed25519 signing is deterministic,
so `--check` needs no seeds beyond these.

`cases` records nine complete messages:

- `witness_only` and `two_witnesses` show the witness counter (`-BAB`, `-BAC`) tracking the count.
- `controller_and_witness` shows a controller group followed by a witness group.
- `witness_pipelined` and `receipt_pipelined` prefix the stream with an attached-material quadlet
  count (`-VAX`, `-VAi`).
- `receipt_couple` and `two_receipt_couples` show the receipt counter (`-CAB`, `-CAC`) and the
  verfer+signature couples.
- `controller_witness_receipt` pins the group order when all three kinds are present:
  controller, then witness, then receipt couples.
- `seal_event_controller_and_witness` pins a sealed controller group followed by a witness group.

`rejected_cases` records keripy refusing a transferable key in either path (`ValueError`,
"Attempt to use tranferable prefix=…" — the upstream misspelling is verbatim) and an unsigned
message.

`reference_facts` records `"B" in NonTransDex` evaluating `true` in Python — the same expression
whose JavaScript translation is pinned `false` in `fixtures/keri-attachment/v1.json` — plus the
codex values and the two counter codes.

Rust tests consume the checked-in fixture and require neither Python nor network access.
