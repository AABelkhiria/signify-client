# KERIA integration observations

- Source: a live KERIA deployment, driven by `crates/signify-keria-systest`
- Binary fields: none.

Record from the repository root, against a running deployment:

```bash
SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest --features live \
    -- --ignored --test-threads=1
```

## What this is

A live run's product is a **fixture, not a green tick**. Each scenario in
`crates/signify-keria-systest` records what it asked and what the deployment answered into this
directory, and hermetic tests in the default suite then assert against the recording. That is the
same generator/fixture split the rest of the crates use, pointed at a deployment instead of at
Node: it turns "it passed on the machine that ran it" into something diffable.

| File | What it holds | Asserted by |
|---|---|---|
| `environment.json` | The deployment's identity to the six-element standard — a BLAKE3-256 digest of the served OpenAPI document, its version, the three witnesses checked against the prefixes the configuration claims, and the schema server's absence | `deployment_vectors.rs` (5) |
| `observations/content_range.json` | Five `Content-Range` values across both listing endpoints, on empty, partial, complete, and past-the-end pages | `content_range_vectors.rs` (4) |
| `observations/sequence_base.json` | Three spellings of one sequence number, which resolved, and the asking client's whole transcript | `sequence_base_vectors.rs` (4) |
| `observations/live_query_answer.json` | The one complete query answer the deployment resolved, written out of the transcript by the scenario itself so the two cannot drift | `key_state_reference_vectors.rs` |
| `observations/exchange_answer.json` | One exchange posted to each of the two submission paths, with both decoders run over both answers | `exchange_answer_vectors.rs` (3) |
| `observations/salty_lifecycle.json` | The whole of `salty.test.ts` driven against a live agent: three creations from the upstream case's own pinned passcodes, the listing ladder, a rotation, an interaction, the key state, the log, the rename, and the full transcript | `salty_lifecycle_vectors.rs` (6) |
| `observations/client_setup.json` | Both client-setup files driven whole: the pinned passcode's controller prefix, a witnessed identifier's agent and witness OOBIs, the agent's six introduction URLs, and two clients cross-resolving each other's OOBIs — with all three transcripts | `client_setup_vectors.rs` (6) |
| `observations/endpoint_smoke.json` | End-role authorisation end to end: zero agent roles before the grant, the exact triple after it, a self-controlled mailbox, and the OOBI the agent derives from the location scheme | `endpoint_smoke_vectors.rs` (5) |
| `observations/randy_lifecycle.json` | A fresh-entropy identifier's inception, interaction, and rotation, with the key commitment — BLAKE3-256 over the revealed key equals the committed digest — recomputable from the recorded events | `randy_lifecycle_vectors.rs` (5) |
| `observations/witness_behavior.json` | Four receipted establishment events: incept with one witness, rotate, cut, add back — the witness ladder, and `bt` changing JSON type with its value inside one log | `witness_behavior_vectors.rs` (4) |
| `observations/singlesig_rot.json`, `observations/singlesig_ixn.json` | The twin local/remote divergences: an event advances the owner's key state, the observer stays one behind until the hexadecimal `keyStates().query` refresh; the interaction reproduces upstream's `[{}]` anchor exactly | `singlesig_events_vectors.rs` (2) |
| `observations/delegation.json` | A delegated inception proven pending until the delegator anchors its seal, the approval at the delegation address, the query that completes it, and the `/agent/`-truncated OOBI that still resolves | `delegation_vectors.rs` (5) |
| `observations/singlesig_dip.json`, `observations/singlesig_drt.json` | The delegated lifecycle: unwitnessed and witnessed delegated inceptions, a delegated rotation, both refresh modes, the anchor query's idempotence — and the echoed-seal metadata that widened `QueryMetadata` | `delegated_lifecycle_vectors.rs` (2) |
| `observations/challenge.json` | The challenge round: BIP39 word counts at both strengths, the signed response as an exchange message, the verification answering with the very message sent, and the contact's authenticated challenge | `challenge_vectors.rs` (3) |
| `observations/endroles_by_aid.json` | A two-member multisig inception, the group end-role round over `/multisig/rpy`, and a third party's five `/endroles/{aid}` reads — the group's roles naming exactly both agents | `endroles_by_aid_vectors.rs` (5) |
| `observations/multisig_inception.json` | Two groups incepted by two members — witnessed at threshold two and witnessless at zero — with the members listings, including the witnessless one upstream dare not assert against `keria#189` | `multisig_inception_vectors.rs` (4) |
| `observations/passcode_rotation.json` | Two passcode rotations, each signed with the key it introduces and accepted (`204`), with the new passcode alone finding no agent, the replaced passcode refused at connect, and a reconnect by the persisted controller prefix after each rotation | `passcode_rotation_vectors.rs` (3) |
| `observations/multisig_join.json` | A third member entering a group in KERI's two steps: committed into rotation authority, then seated by a rotation he joins by rebuilding it and comparing SAIDs before `groups().join` | `multisig_join_vectors.rs` (3) |

Three findings are worth reading the files for. Asked for a page past the end of a collection, KERIA
answers **`aids 100-0/4`** — a start greater than its end, which RFC 9110 forbids — so a parser that
had enforced the rule would refuse a response deployments genuinely send. A KERIA agent reads a
query's sequence number in **hexadecimal**: against an eleven-event log, `a` resolved and returned
event ten while `10` and `16` ran to the deadline. And both exchange submission paths answer with an
**operation**, so `sendFromEvents`'s declared `Promise<Exn>` is wrong — the reference contradicts
itself about its own two endpoints, and only a deployment could say which half was right.

The deployment also serves **six** introduction URLs where the upstream `validate config` case
deep-equals exactly three for this preset, so the reference's own assertion would refuse the
deployment its suite targets; and a witnessed record spells `windexes` in JSON **numbers** where
the reference's generated schema declares strings — the defect that widened
`HabCommon.witness_indexes` to `WitnessIndex`.

## The schema source

The credential and IPEX scenarios need a schema source. Any host that serves `/oobi/{said}` will
do — KERIA resolves a schema by fetching that path, and nothing about the rest of the server
matters. `SIGNIFY_KERIA_SCHEMA_URL` names it; the preset's default is the vLEI container the
reference's own compose file uses:

```bash
docker run -p 7723:7723 gleif/vlei:1.0.3 vLEI-server -s /vLEI/schema -c /vLEI/credentials -o /vLEI/oobis
```

A deployment may serve them from elsewhere. The Veridian credential server does, on port 3001, by
static-serving its `src/schemas/` directory under `/oobi` — so
`SIGNIFY_KERIA_SCHEMA_URL=http://localhost:3001` is enough, with no other change.

**Which schemas a source serves decides which scenarios can run.** The SAID of an ACDC schema is a
digest of the schema itself, so two sources serving the same SAID serve byte-identical schemas:

| scenario | schemas | vLEI server | Veridian server |
|---|---|---|---|
| Credential/IPEX flows | QVI, LE | yes | yes |
| Multisig holder flow | QVI | yes | yes |
| Multisig vLEI issuance | + ECR | yes | **no** |
| Single-signature vLEI issuance | + ECR, ECR_AUTH, OOR, OOR_AUTH | yes | **no** |

## Determinism

Rust tests consume only the checked-in files and require neither a deployment nor network access.
A recording run replaces a file whole, so a changed answer shows up as a diff.
