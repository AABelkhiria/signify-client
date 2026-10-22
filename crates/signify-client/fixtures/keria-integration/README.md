# KERIA integration matrix

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-28
- Sources: the whole of `test-integration/` — 22 scenario files, 6 support files, 35 cases,
  7,070 lines
- Binary fields: none.

Generate and verify from the repository root:

```bash
node tools/reference-vectors/upstream_integration_audit.mjs --write   # regenerate the inventory
node tools/reference-vectors/upstream_integration_audit.mjs --check   # verify determinism
```

## What this is

The integration matrix must answer every upstream integration scenario with Rust evidence or a
documented reason, and close four open questions that only a live deployment can settle. This
directory holds the matrix. `crates/signify-client/tests/keria_integration_audit.rs` — 13 tests,
hermetic — is what keeps it honest.

`v1.json` is the **inventory**, generated from the reference's own syntax tree.
`ledger.json` is the **answer**, authored, because mapping a scenario to evidence is a judgement.

## Why the case is the wrong unit here

`fixtures/upstream-unit-audit/` audited the unit suite one row per `it`/`test` case, and that
worked: its 139 cases were each a few lines long.

It would not work here. Four of these files are **a single case each**:

| file | lines | cases | assertions | API calls |
|---|---:|---:|---:|---:|
| `multisig.test.ts` | 1,343 | 1 | **13** | **134** |
| `multisig-vlei-issuance.test.ts` | 1,336 | 1 | 70 | 60 |
| `credentials.test.ts` | 743 | 1 | 68 | 54 |
| `multisig-holder.test.ts` | 592 | 1 | **5** | 53 |

Counting cases would report "35 of 35 answered" while hundreds of behaviours went unexamined — an
audit that passes while certifying almost nothing. So the inventory records a finer unit: **every
`client.<family>().<method>()` call site**, 502 of them across 14 endpoint families. The largest
scenario in the suite performs ten operations for every assertion it makes.

Only four of the twenty-two files label their internal steps with `step()`; the rest narrate with
`console.log` or not at all. That is why steps cannot key the matrix either.

## What the audit found before a single scenario ran

**The scenario table was missing a row.** `challenge.test.ts` was claimed by none of the nineteen
rows the table carried — it omitted a whole capability. The row was added, and the audit test now
refuses to let any upstream scenario go unclaimed.

**One row is blocked on this port, not on infrastructure.** *External module behavior* cannot be
exercised at all: `ConnectedClient::keepers()` lends the factory immutably,
`KeeperFactory::with_module` consumes `self`, and `signify-client` never names
`ExternalKeeperModule`. Recorded as `api_missing`, owned by the API consistency review.

**The `KERIA OpenAPI` record is wrong about the spec.** It states the served document "carries no
version". The live deployment serves `info.version: 1.0.1` — at line 2237 of 2240, where a reader
checking the head of the file would miss it.

## The suite's defects, as data

Twenty-one defects across seven kinds, each with a file and a line, so every "this port does better"
claim cites a generated location rather than a memory:

| kind | count | example |
|---|---:|---|
| `local_reimplementation` | 7 | `createTimestamp`, exported by `utils/`, redefined three times |
| `no_operation_teardown` | 5 | the file never calls `assertOperations` |
| `swallowing_catch` | 3 | `catch {}` treating any failure as "not created yet" |
| `bare_sleep` | 2 | `multisig.test.ts`:709, a five-second `setTimeout` as a race patch |
| `commented_assertion` | 2 | `multisig-inception.test.ts`, a step with its asserts commented out |
| `module_scope_timestamp` | 1 | `multisig-holder.test.ts`:34, a stale `TIME` used as a `datetime` |
| `wall_clock_identifier` | 1 | `multisig-join.test.ts`:408, names seeded from `Date.now()` |

The runner is recorded too: `fileParallelism: false` with `bail: 1` — the first failure aborts
everything, and nothing is designed to run in parallel against one agent. A recording run must do
the same.

## The three tables in the ledger

- **`scenarios`** — 20 rows, one per scenario-table row, each naming its upstream files, its
  recomputed counts, the infrastructure it needs, and its status.
- **`open_questions`** — the four open questions owed to the live matrix plus the residual on a
  fifth, each with the exact experiment that would settle it.
- **`obligations`** — 31 "a live run should/owes/owns" claims collected out of status prose and
  per-capability records by the maintainer decision of 2026-08-28, each naming the record it came
  from.

Four obligations are `out_of_scope` with an argument, because not everything a live run touches is
an integration question: TLS (KERIA listens on plain HTTP, so a live run exercises none of it),
`TokioClock` (a paused-time test proves the delegation better than real elapsed time), credential
bounds (a resource-limit question, → the fuzz and security review), and clock skew (a loopback run
measures ≈0, so the row may only make a narrowed claim).

## `observations/` — what a deployment actually answered

A live run's product is a **fixture, not a green tick**. Each scenario in
`crates/signify-keria-systest` records what it asked and what the deployment answered into this
directory, and hermetic tests in the default suite then assert against the recording. That is the
same generator/fixture split the rest of the port uses, pointed at a deployment instead of at Node:
it turns "it passed on the machine that ran it" into something diffable.

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
| `observations/passcode_rotation.json` | Not an upstream scenario: two passcode rotations, each signed with the key it introduces and accepted (`204`), with the new passcode alone finding no agent, the replaced passcode refused at connect, and a reconnect by the persisted controller prefix after each rotation | `passcode_rotation_vectors.rs` (3) |
| `observations/multisig_join.json` | A third member entering a group in KERI's two steps: committed into rotation authority, then seated by a rotation he joins by rebuilding it and comparing SAIDs before `groups().join` | `multisig_join_vectors.rs` (3) |

Three findings are worth reading the files for. Asked for a page past the end of a collection, KERIA
answers **`aids 100-0/4`** — a start greater than its end, which RFC 9110 forbids — so a parser that
had enforced the rule would refuse a response deployments genuinely send. And a KERIA agent reads a
query's sequence number in **hexadecimal**: against an eleven-event log, `a` resolved and returned
event ten while `10` and `16` ran to the deadline. And both exchange submission paths answer with an
**operation**, so `sendFromEvents`'s declared `Promise<Exn>` is wrong — the reference contradicts
itself about its own two endpoints, and only a deployment could say which half was right.

## Status

Four scenario rows are `observed`: **Salty identifier lifecycle** (wave 3, sixteen of eighteen
pinned qb64 values reproduced exactly, the two divergent ones pinned from both sides), **Client
setup, single/multiple clients** and **Single-signature inception** (wave 4, the pinned
controller prefix reproduced, witnessed inceptions receipted by the running triple, and both
cross-resolutions answering with the other's prefix), **Endpoint smoke coverage** (wave 5,
the end-role triples and the self-controlled mailbox's derived OOBI), **Randy identifier
lifecycle** (wave 6, the key commitment recomputed from the recorded events), **Witness
behavior** (wave 7, four receipted establishments walking a witness in, out, and back in), and
the twins **Single-signature rotation** and **Single-signature interaction** (wave 8, the
local/remote key-state divergence closed by the hexadecimal refresh), **Delegation** (wave 9,
a delegated inception proven pending until its seal is anchored), **Single-signature
delegated inception/rotation** (wave 10, both refresh modes and the delegated rotation, plus the
echoed-seal defect that widened `QueryMetadata`), **Challenge and response** (wave 11, the
round tied across two clients by SAID), and **End roles by AID** (wave 12, the first live drive
of the port's multisig machinery, read back by a third party). **Multisig inception/join** is
`partly_observed` — wave 13 recorded the inception file whole and wave 14 the join spine, a third
member rebuilding the rotation he was shown and comparing SAIDs before joining; only the
four-client replacement case remains. The other seven remain `unobserved`.
"How much of the matrix remains" stays a number a test prints rather than a judgement. Nothing here
claims evidence that does not exist — the audit requires every path a row names to be on disk,
and forbids a row from naming evidence while claiming to be unanswered.

Wave 4 also found two things worth reading `client_setup.json` for: the deployment serves **six**
introduction URLs where the upstream `validate config` case deep-equals exactly three for this
preset, so the reference's own assertion would refuse the deployment its suite targets; and a
witnessed record spells `windexes` in JSON **numbers** where the reference's generated schema
declares strings — the defect that widened `HabCommon.witness_indexes` to `WitnessIndex`.

Of the five open questions, three are now `observed` and `settled`: the `Content-Range` discipline, the
sequence-number base, and the exchange answer's two declared types. A question that is answered must carry the reason `settled`, and one that
is not must not — the audit checks the two agree, because an answered row that kept the reason it
was pending for reads as though the observation never happened.

Seventeen of the twenty-two scenarios are runnable against a KERIA today; five need a schema source.

## The schema source

Any host that serves `/oobi/{said}` will do — KERIA resolves a schema by fetching that path, and
nothing about the rest of the server matters. `SIGNIFY_KERIA_SCHEMA_URL` names it; the preset's
default is the vLEI container the reference's own compose file uses:

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

The two issuance rows therefore keep `vlei_unavailable` against a Veridian source and would need
those four schemas added to it. The other two are blocked only on a recording run.

## Determinism

The inventory is a pure function of the pinned checkout: no clock, no randomness, no network. It
fails rather than guesses if two cases share a key. Rust tests consume both checked-in files and
require neither Node nor network access.
