# Passcode rotation verdicts (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`)
- Input: `fixtures/client-passcode-rotation/v1.json` (`kel`), recorded from signify-ts
  `91a04a5edd804425f42be75ffbf034f8d14e5cb2` by `tools/reference-vectors/client_passcode_rotation.mjs`
- Generated: 2026-09-16
- Sources: `src/keri/core/eventing.py` — `Kevery.processEvent`, `Kever.update`, `Kever.rotate`
- Binary fields: none. Events are raw JSON text, signatures qualified Base64, both copied from the
  input fixture; keripy's error messages are recorded verbatim.

## Why keripy

signify-ts's `Controller.rotate` never passes a sequence number, so its passcode rotation always
claims `s = "1"` with the controller's current event as prior. Its only test mocks the agent. A
connected client's log already holds the delegation-approval interaction at sequence one, and
whether the rotation is valid there is decided by KERI event validation, which signify-ts does not
implement and KERIA delegates to keripy. keripy is a secondary reference for exactly this kind of
question, and this port's rotation follows its verdicts.

## Generation

Needs Node for the input fixture and a Python 3.12+ environment with the pinned keripy installed.
From the repository root:

```bash
npm ci --prefix tools/reference-vectors
node tools/reference-vectors/client_passcode_rotation.mjs --write
uv sync --locked --project tools/reference-vectors
uv run --locked --project tools/reference-vectors python tools/reference-vectors/client_passcode_rotation_keripy.py --write   # regenerate
uv run --locked --project tools/reference-vectors python tools/reference-vectors/client_passcode_rotation_keripy.py --check   # verify determinism
```

Set `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own. The Rust tests read the checked-in JSON and need neither runtime.

## Contents

Each verdict replays the recorded inception and interaction into a fresh keripy `Kevery`, then
processes one candidate rotation:

| Candidate | Sequence | Prior | keripy |
|---|---|---|---|
| `reference_rotation` | 1 | the interaction | refused: `Invalid recovery attempt: Mismatch recovery event prior dig` |
| `corrected_rotation` | 2 | the interaction | accepted; the log moves to the rotation |
| `inception_prior_rotation` | 2 | the inception | refused: `Mismatch event dig … with state dig` |

The corrected rotation is what this port builds; `passcode_rotation_keripy_vectors.rs` requires the
port's event bytes and both signatures to equal it. The generator refuses to write if keripy's
verdict on any candidate changes.

KERIA calls this validation through `SignifyHab.processEvent`, which re-raises any failure as
`ConfigurationError("Improper Habitat event type=rot …")`; `AgentResourceEnd.on_put` leaves it
unhandled, so the reference's rotation reaches a client as `500`.
