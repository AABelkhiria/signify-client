# Passcode rotation reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Secondary reference: `https://github.com/WebOfTrust/keripy.git`
  at `4ce4cc79e06653f77342be1bf604086b89b1f090`
- Generated: 2026-09-16 (first generated 2026-08-27; `kel` and the sixth divergence added on regeneration)
- Sources: `src/keri/app/clienting.ts`, `src/keri/app/controller.ts`,
  `test/app/clienting.test.ts`, `src/keri/core/eventing.ts`, and keripy's `src/keri/app/keeping.py`
- Binary fields: none. Sealed boxes draw a fresh ephemeral key per call, so no ciphertext can be
  compared byte for byte; this fixture records **what each sealed value opens to and under which
  passcode**, which is the property the finding is about.

Generate and verify from the repository root after installing the pinned references:

```bash
npm ci --prefix tools/reference-vectors
node tools/reference-vectors/client_passcode_rotation.mjs --write   # regenerate
node tools/reference-vectors/client_passcode_rotation.mjs --check   # verify determinism
```

## What the evidence is

This port covers `SignifyClient.rotate` — the client half of moving to a new passcode. The artifact
half is `Controller.rotate`, recorded in `crates/signify-keys/fixtures/keri-controller/`. This fixture adds the request
that carries it and the comparison that decided what the port should do.

## The finding: the payload is sealed to the passcode being left behind

```ts
const nbran = MtrDex.Salt_128 + 'A' + bran.substring(0, 21);   // the NEW salt
const nsalter = new Salter({ qb64: nbran, tier: this.tier });  // the NEW salter
const nsigner = this.salter.signer(undefined, false);          // ...the OLD salter
const encrypter = new Encrypter({}, b(nsigner.verfer.qb64));
const decrypter = new Decrypter({}, nsigner.qb64b);
```

Two of the three `n`-prefixed locals are the new passcode's. The third is not, and it feeds both
ciphers — the decrypter, correctly, since the stored material *is* under the old passcode, and the
encrypter, which therefore never rotates. The controller salt the payload records is the old salt
too: `encrypter.encrypt(b(this.bran))`, and `this.bran` never moves.

Driven with one salty and one randy identifier:

| sealed value | opens under the old passcode | opens under the new one |
|---|---|---|
| the controller salt | yes — and it *is* the old salt | **no** |
| the salty identifier's salt | yes | **no** |
| the randy identifier's private key | yes | **no** |

Two consequences. A client that rotated and reconnected with its new passcode could not open its
own identifiers. And whoever holds the old passcode still can — rotating did not revoke it.

## What keripy does

`Manager.updateAeid` builds its encrypter from the **new** key, checks the new seed belongs to it,
and only then opens each secret with the old decrypter and seals it with the new encrypter:

```python
self.encrypter = core.Encrypter(verkey=aeid)          # from the NEW key
...
salter = self.decrypter.decrypt(qb64=data.salt)       # open with OLD
data.salt = self.encrypter.encrypt(prim=salter).qb64  # re-seal with NEW
```

Its docstring: *"aeid may be different not empty which reencrypts."* So this is not a design
choice signify-ts made differently — it is a defect against the protocol's own reference
implementation, in the direction that does not work.

**This port follows keripy.** Maintainer decision of 2026-08-27. The wire contract is unchanged:
only the ciphertext differs, and the agent stores it opaquely.

## Two smaller findings

**A second rotation commits to the original passcode again.** `rotate` moves the signers, keys, and
digests and leaves `bran`, `salter`, `ridx`, and `serder` behind, so the controller's salt and its
keys disagree from the first rotation onward and every later rotation derives its "old" key from
the original passcode. Driven: both rotations name the same old key. Here the salt moves with the
keys, so the second rotation reveals the key the first pre-committed to — which the KERI chain
requires, and which the sealing fix depends on.

**The rotation travels unsigned.** `rotate` calls the global `fetch` directly rather than the
client's signed pipeline, so the request carrying every re-sealed secret has no HTTP signature — the
same bypass the `client-lifecycle` fixture recorded for the delegation approval and both passcode
calls. Reproduced, because a signed request is not what KERIA expects here.

## Nothing upstream exercises any of it

The one call in the pinned tree is:

```ts
resp = await client.rotate('abcdefghijk0123456789', []);
```

An **empty** identifier list. The loop, both its branches, the key-state check, and every re-seal
are skipped, and the payload's `keys` map comes back empty — which this fixture drives and records.
Four assertions cover the rotation event and nothing else.

## Contents

- `declarations` holds both methods' text, the three `n`-prefixed declarations side by side, every
  `Encrypter`/`Decrypter` construction with the argument it is given, the pinned test's one call,
  and keripy's contrasting lines read from its own checkout.
- `request` pins the exact `PUT`: its path, that the reference sends it unsigned (this port signs
  it with the key the rotation introduces), its four body fields in order, and the per-identifier
  shapes.
- `sealing` records what each of the three sealed values opens to, under each passcode.
- `kel` holds the connected client's log as raw events with their signatures — the inception and
  the delegation-approval interaction the connection sent — and three rotations over it: the
  recorded request's (`s = 1`, prior the interaction), and two rebuilt by the reference's own
  `rotate` with the same keys and signers, at `s = 2` over the interaction and at `s = 2` over the
  inception. The generator first rebuilds the recorded rotation at `s = 1` and refuses to write
  unless it reproduces the recorded bytes and signatures, so the rebuilt ones are the reference's
  own construction. `fixtures/client-passcode-rotation-keripy/` records keripy's verdict on each.
- `reference_quirks` pins six behaviours, each with what the reference does and what this port
  does instead. The sixth, `the_rotation_always_claims_sequence_one`, is why a live KERIA answers
  the reference's rotation with `500`.

## Determinism

The clock and the agent's key are pinned. `PUBLIC TEST MATERIAL`: both passcodes are the pinned
tests' own.

Rust tests consume the checked-in fixture and require neither Node nor network access. The driven
half of the test runs this port's own client at the ephemeral derivation cost, so its controller
prefix and identifier keys are its own rather than the fixture's — a cost is part of a key's
identity, and the fixture's were derived at the reference's production cost.
