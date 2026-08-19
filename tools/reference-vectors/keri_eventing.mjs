// Generates and checks core key-event vectors from the compiled pinned signify-ts checkout.
import { readFileSync, writeFileSync } from "node:fs";

import { b, Ilks } from "../../reference/signify-ts/dist/keri/core/core.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { ample, incept, interact, rotate } from "../../reference/signify-ts/dist/keri/core/eventing.js";
import { Diger } from "../../reference/signify-ts/dist/keri/core/diger.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

// The two seeds the pinned `test/core/eventing.test.ts` uses, plus a deterministic family derived
// from the first so that multi-key and witness cases stay reproducible.
const SEED_0 = new Uint8Array([
  159, 123, 168, 167, 168, 67, 57, 150, 38, 250, 177, 153, 235, 170, 32, 196, 27, 71, 17, 196, 174, 83, 65, 82, 201,
  189, 4, 157, 133, 41, 126, 147,
]);
const SEED_1 = new Uint8Array([
  131, 66, 126, 4, 148, 227, 206, 85, 81, 121, 17, 102, 12, 147, 93, 30, 191, 172, 81, 181, 214, 89, 94, 162, 69, 250,
  1, 53, 152, 89, 221, 232,
]);

function seedAt(index) {
  const seed = new Uint8Array(SEED_0);
  seed[31] = index;
  return seed;
}

function key(seed, transferable = true) {
  return new Signer({ raw: seed, transferable }).verfer.qb64;
}

function nextDigest(seed) {
  return new Diger({}, new Signer({ raw: seed }).verfer.qb64b).qb64;
}

const KEY_TRANSFERABLE = key(SEED_0);
const KEY_NON_TRANSFERABLE = key(SEED_0, false);
const KEY_SECOND = key(SEED_1);
const NEXT_DIGEST = nextDigest(SEED_1);
const KEYS_3 = [0, 1, 2].map((index) => key(seedAt(index)));
const DIGESTS_2 = [10, 11].map((index) => nextDigest(seedAt(index)));
const WITNESSES_3 = [20, 21, 22].map((index) => key(seedAt(index), false));

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function rejectedCase(name, operation, rustErrorCategory) {
  try {
    operation();
  } catch (error) {
    return {
      name,
      reference_error_category: error?.constructor?.name ?? "Unknown",
      reference_error_message: String(error?.message ?? error),
      rust_error_category: rustErrorCategory,
    };
  }
  throw new Error(`reference unexpectedly accepted rejected case ${name}`);
}

// Records one built event: its exact bytes, its identifiers, and the inputs that produced it.
function eventCase(name, serder, inputs) {
  const raw = serder.raw;
  return {
    name,
    inputs,
    event_kind: serder.sad.t,
    identifier: serder.sad.i,
    said: serder.sad.d,
    sequence_number: serder.sad.s,
    version_string: serder.sad.v,
    raw,
    raw_hex: hex(b(raw)),
    raw_byte_size: b(raw).length,
  };
}

// 1. The four inception events the pinned unit test asserts, byte for byte.
const cases = [
  eventCase("pinned_non_transferable_inception", incept({ keys: [KEY_NON_TRANSFERABLE] }), {
    builder: "incept",
    keys: [KEY_NON_TRANSFERABLE],
  }),
  eventCase("pinned_transferable_inception", incept({ keys: [KEY_TRANSFERABLE] }), {
    builder: "incept",
    keys: [KEY_TRANSFERABLE],
  }),
  eventCase(
    "pinned_self_addressing_inception_text",
    incept({ keys: [KEY_TRANSFERABLE], ndigs: [NEXT_DIGEST], code: MtrDex.Blake3_256 }),
    {
      builder: "incept",
      keys: [KEY_TRANSFERABLE],
      ndigs: [NEXT_DIGEST],
      code: MtrDex.Blake3_256,
      intive: false,
    },
  ),
  eventCase(
    "pinned_self_addressing_inception_integer",
    incept({ keys: [KEY_TRANSFERABLE], ndigs: [NEXT_DIGEST], code: MtrDex.Blake3_256, intive: true }),
    {
      builder: "incept",
      keys: [KEY_TRANSFERABLE],
      ndigs: [NEXT_DIGEST],
      code: MtrDex.Blake3_256,
      intive: true,
    },
  ),
  // 2. Multi-key, weighted, witnessed, configured, and delegated inception.
  eventCase(
    "multisig_inception",
    incept({ keys: KEYS_3, isith: 2, ndigs: DIGESTS_2, nsith: 1, code: MtrDex.Blake3_256 }),
    { builder: "incept", keys: KEYS_3, isith: 2, ndigs: DIGESTS_2, nsith: 1, code: MtrDex.Blake3_256 },
  ),
  eventCase(
    "weighted_inception",
    incept({
      keys: KEYS_3,
      isith: ["1/2", "1/2", "1/2"],
      ndigs: DIGESTS_2,
      nsith: 1,
      code: MtrDex.Blake3_256,
    }),
    {
      builder: "incept",
      keys: KEYS_3,
      isith: ["1/2", "1/2", "1/2"],
      ndigs: DIGESTS_2,
      nsith: 1,
      code: MtrDex.Blake3_256,
    },
  ),
  eventCase(
    "multi_clause_weighted_inception",
    incept({
      keys: KEYS_3,
      isith: [["1/2", "1/2"], ["1"]],
      ndigs: DIGESTS_2,
      nsith: 1,
      code: MtrDex.Blake3_256,
    }),
    {
      builder: "incept",
      keys: KEYS_3,
      isith: [["1/2", "1/2"], ["1"]],
      ndigs: DIGESTS_2,
      nsith: 1,
      code: MtrDex.Blake3_256,
    },
  ),
  eventCase(
    "witnessed_inception_default_toad",
    incept({ keys: [KEY_TRANSFERABLE], ndigs: [NEXT_DIGEST], wits: WITNESSES_3, code: MtrDex.Blake3_256 }),
    {
      builder: "incept",
      keys: [KEY_TRANSFERABLE],
      ndigs: [NEXT_DIGEST],
      wits: WITNESSES_3,
      code: MtrDex.Blake3_256,
    },
  ),
  eventCase(
    "witnessed_inception_integer_toad",
    incept({
      keys: [KEY_TRANSFERABLE],
      ndigs: [NEXT_DIGEST],
      wits: WITNESSES_3,
      toad: 2,
      code: MtrDex.Blake3_256,
      intive: true,
    }),
    {
      builder: "incept",
      keys: [KEY_TRANSFERABLE],
      ndigs: [NEXT_DIGEST],
      wits: WITNESSES_3,
      toad: 2,
      code: MtrDex.Blake3_256,
      intive: true,
    },
  ),
  eventCase(
    "configured_and_anchored_inception",
    incept({
      keys: [KEY_TRANSFERABLE],
      ndigs: [NEXT_DIGEST],
      cnfg: ["EO", "DND"],
      data: [{ i: KEY_TRANSFERABLE, s: "0" }],
      code: MtrDex.Blake3_256,
    }),
    {
      builder: "incept",
      keys: [KEY_TRANSFERABLE],
      ndigs: [NEXT_DIGEST],
      cnfg: ["EO", "DND"],
      data: [{ i: KEY_TRANSFERABLE, s: "0" }],
      code: MtrDex.Blake3_256,
    },
  ),
  eventCase(
    "abandoned_inception",
    incept({ keys: [KEY_TRANSFERABLE], ndigs: [], code: MtrDex.Blake3_256 }),
    { builder: "incept", keys: [KEY_TRANSFERABLE], ndigs: [], code: MtrDex.Blake3_256 },
  ),
];

// 3. Delegated inception, and the rotations and interactions that follow an identifier.
const delegator = cases[2].identifier;
cases.push(
  eventCase("delegated_inception", incept({ keys: [KEY_TRANSFERABLE], ndigs: [NEXT_DIGEST], delpre: delegator }), {
    builder: "incept",
    keys: [KEY_TRANSFERABLE],
    ndigs: [NEXT_DIGEST],
    delpre: delegator,
  }),
);

const root = incept({ keys: [KEY_TRANSFERABLE], ndigs: [NEXT_DIGEST], code: MtrDex.Blake3_256 });
const rotationArgs = {
  pre: root.sad.i,
  dig: root.sad.d,
  keys: [KEY_SECOND],
  ndigs: [NEXT_DIGEST],
  sn: 1,
  isith: 1,
  nsith: 1,
};
// Each rotation records the arguments it was called with, tagged for the Rust reader.
function rotationCase(name, overrides) {
  const args = { ...clone(rotationArgs), ...clone(overrides) };
  return eventCase(name, rotate(clone(args)), { builder: "rotate", ...args });
}

cases.push(
  rotationCase("rotation", {}),
  rotationCase("delegated_rotation", { ilk: Ilks.drt }),
  rotationCase("rotation_text_encoding", { intive: false }),
  rotationCase("rotation_high_sequence_number", { sn: 255 }),
  rotationCase("rotation_with_witness_changes", {
    wits: [WITNESSES_3[0], WITNESSES_3[1]],
    cuts: [WITNESSES_3[0]],
    adds: [WITNESSES_3[2]],
  }),
  rotationCase("rotation_with_anchors", { data: [{ i: root.sad.i, s: "1", d: root.sad.d }] }),
);

const interactionInputs = {
  builder: "interact",
  pre: root.sad.i,
  dig: root.sad.d,
  sn: 1,
  data: [],
};
cases.push(
  eventCase(
    "interaction",
    interact({ pre: root.sad.i, dig: root.sad.d, sn: 1, data: [], version: undefined, kind: undefined }),
    interactionInputs,
  ),
  eventCase(
    "interaction_with_anchors",
    interact({
      pre: root.sad.i,
      dig: root.sad.d,
      sn: 2,
      data: [{ i: root.sad.i, s: "0", d: root.sad.d }],
      version: undefined,
      kind: undefined,
    }),
    { ...interactionInputs, sn: 2, data: [{ i: root.sad.i, s: "0", d: root.sad.d }] },
  ),
);

// 4. The witness fault-tolerance table.
const ampleTable = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 17, 100].map((witnesses) => ({
  witnesses,
  weak: ample(witnesses),
  strong: ample(witnesses, undefined, false),
}));
const ampleExplicit = [
  { witnesses: 4, faults: 1, weak: ample(4, 1), strong: ample(4, 1, false) },
  { witnesses: 3, faults: 0, weak: ample(3, 0), strong: ample(3, 0, false) },
  { witnesses: 0, faults: 5, weak: ample(0, 5), strong: ample(0, 5, false) },
  { witnesses: 1, faults: 0, weak: ample(1, 0), strong: ample(1, 0, false) },
];

// 5. Reference rejections.
const rejected = [
  rejectedCase("signing_threshold_zero", () => incept({ keys: [KEY_TRANSFERABLE], isith: 0 }), "SigningThresholdIsZero"),
  rejectedCase(
    "signing_threshold_exceeds_keys",
    () => incept({ keys: [KEY_TRANSFERABLE], isith: 2 }),
    "SigningThresholdExceedsKeys",
  ),
  rejectedCase(
    "duplicate_witnesses",
    () => incept({ keys: [KEY_TRANSFERABLE], wits: [WITNESSES_3[0], WITNESSES_3[0]] }),
    "DuplicateWitness",
  ),
  rejectedCase(
    "witness_threshold_zero_with_witnesses",
    () => incept({ keys: [KEY_TRANSFERABLE], wits: [WITNESSES_3[0]], toad: 0 }),
    "InvalidWitnessThreshold",
  ),
  rejectedCase(
    "witness_threshold_exceeds_witnesses",
    () => incept({ keys: [KEY_TRANSFERABLE], wits: [WITNESSES_3[0]], toad: 2 }),
    "InvalidWitnessThreshold",
  ),
  rejectedCase(
    "witness_threshold_without_witnesses",
    () => incept({ keys: [KEY_TRANSFERABLE], toad: 1 }),
    "InvalidWitnessThreshold",
  ),
  rejectedCase(
    "non_transferable_prefix_with_next_keys",
    () => incept({ keys: [KEY_NON_TRANSFERABLE], code: MtrDex.Ed25519N, ndigs: [NEXT_DIGEST] }),
    "Prefix",
  ),
  rejectedCase(
    "non_transferable_prefix_with_witnesses",
    () => incept({ keys: [KEY_NON_TRANSFERABLE], code: MtrDex.Ed25519N, wits: [WITNESSES_3[0]] }),
    "Prefix",
  ),
  rejectedCase(
    "non_transferable_prefix_with_anchors",
    () => incept({ keys: [KEY_NON_TRANSFERABLE], code: MtrDex.Ed25519N, data: [{ i: "ABCDE" }] }),
    "Prefix",
  ),
  rejectedCase(
    "delegated_inception_with_basic_prefix",
    () => incept({ keys: [KEY_TRANSFERABLE], ndigs: [NEXT_DIGEST], delpre: delegator, code: MtrDex.Ed25519 }),
    "DelegatedPrefixMustBeDigestive",
  ),
  rejectedCase(
    "rotation_sequence_number_zero",
    () => rotate({ ...clone(rotationArgs), sn: 0 }),
    "SequenceNumberTooSmall",
  ),
  rejectedCase(
    "rotation_non_rotation_ilk",
    () => rotate({ ...clone(rotationArgs), ilk: Ilks.icp }),
    "UnrepresentableInRust",
  ),
  rejectedCase(
    "rotation_duplicate_cuts",
    () => rotate({ ...clone(rotationArgs), cuts: [WITNESSES_3[0], WITNESSES_3[0]] }),
    "DuplicateWitness",
  ),
  rejectedCase(
    "rotation_duplicate_adds",
    () => rotate({ ...clone(rotationArgs), adds: [WITNESSES_3[0], WITNESSES_3[0]] }),
    "DuplicateWitness",
  ),
  rejectedCase(
    "rotation_witness_added_twice",
    () => rotate({ ...clone(rotationArgs), wits: [WITNESSES_3[0]], adds: [WITNESSES_3[0]] }),
    "ConflictingWitnessLists",
  ),
  rejectedCase(
    "rotation_witness_cut_and_added",
    () => rotate({ ...clone(rotationArgs), cuts: [WITNESSES_3[0]], adds: [WITNESSES_3[0]] }),
    "ConflictingWitnessLists",
  ),
  rejectedCase(
    "rotation_cut_not_a_witness",
    () => rotate({ ...clone(rotationArgs), wits: [WITNESSES_3[0]], cuts: [WITNESSES_3[1]] }),
    "WitnessCutNotPresent",
  ),
  rejectedCase(
    "interaction_sequence_number_zero",
    () => interact({ pre: root.sad.i, dig: root.sad.d, sn: 0, data: [], version: undefined, kind: undefined }),
    "SequenceNumberTooSmall",
  ),
  rejectedCase("ample_impossible_fault_count", () => ample(4, 2), "FaultToleranceTooHigh"),
];

// 6. Reference defects that Rust deliberately does not reproduce.
const quirks = {
  multi_key_inception_needs_an_explicit_code: {
    ...rejectedCase("multi_key_inception_without_code", () => incept({ keys: KEYS_3, ndigs: DIGESTS_2 }), "Accepted"),
    note: "with more than one key and no explicit code the prefix branch falls through to `new Prefixer({code: undefined}, sad)`, whose second super() call receives the still-empty identifier field; multisig inception is therefore unreachable through the documented path",
    rust_decision:
      "Rust defaults the derivation to Blake3_256 whenever a basic prefix cannot represent the event, so the same inputs produce the event the reference would build with code: E",
    rust_equivalent_case: "multisig_inception",
  },
  next_threshold_encoding_follows_the_current_threshold: {
    weighted_current_numeric_next_integer_encoding: (() => {
      const serder = incept({
        keys: KEYS_3,
        isith: ["1/2", "1/2", "1/2"],
        ndigs: DIGESTS_2,
        nsith: 1,
        code: MtrDex.Blake3_256,
        intive: true,
      });
      return { raw: serder.raw, kt: serder.sad.kt, nt: serder.sad.nt, nt_type: typeof serder.sad.nt };
    })(),
    note: "the next-threshold field tests `tholder.num` -- the *current* threshold -- before writing `ntholder.num`, so a weighted current threshold silently forces the next one to text even under integer encoding",
    rust_decision: "reproduced exactly: this changes the bytes the identifier commits to",
  },
  numeric_current_weighted_next_drops_the_field: (() => {
    const serder = incept({
      keys: KEYS_3,
      isith: 2,
      ndigs: DIGESTS_2,
      nsith: ["1/2", "1/2"],
      code: MtrDex.Blake3_256,
      intive: true,
    });
    return {
      raw: serder.raw,
      contains_next_threshold: serder.raw.includes('"nt"'),
      note: "the same condition then writes ntholder.num, which is undefined for a weighted threshold, and JSON.stringify drops the key entirely -- the event has no `nt` field at all and its SAID commits to that malformed shape",
      rust_error_category: "UnrepresentableNextThreshold",
    };
  })(),
  next_threshold_validated_against_the_current_key_count: {
    ...rejectedCase(
      "valid_next_threshold_rejected",
      () => incept({ keys: [KEY_TRANSFERABLE], ndigs: DIGESTS_2, nsith: 2, code: MtrDex.Blake3_256 }),
      "Accepted",
    ),
    note: "incept compares the next threshold's size against keys.length instead of ndigs.length -- the error message even interpolates ndigs -- so a single-key identifier cannot commit to a 2-of-2 rotation",
    rust_decision: "Rust validates the next threshold against the next-key digest count",
    unsatisfiable_accepted: (() => {
      const serder = incept({ keys: KEYS_3, isith: 2, ndigs: [], nsith: 2, code: MtrDex.Blake3_256 });
      return { raw: serder.raw, nt: serder.sad.nt, n: serder.sad.n };
    })(),
    unsatisfiable_note:
      "the same comparison accepts a 2-of-nothing next threshold, an event committing to a rotation no key set can ever satisfy; Rust rejects it as NextThresholdExceedsDigests",
  },
  auto_selected_basic_prefix_skips_its_own_checks: {
    non_transferable_with_next_keys: incept({ keys: [KEY_NON_TRANSFERABLE], ndigs: [NEXT_DIGEST] }).raw,
    non_transferable_with_anchors: incept({ keys: [KEY_NON_TRANSFERABLE], data: [{ i: "x" }] }).raw,
    note: "when the derivation is inferred from a single key the reference *parses* that key instead of deriving from the event, so the non-transferable emptiness checks never run; the result is an identifier that can never rotate yet commits to next keys",
    rust_decision: "Rust always derives, so the same checks apply however the derivation was chosen",
    rust_error_category: "Prefix",
  },
  rotation_cannot_abandon_an_identifier: {
    default_next_threshold: rejectedCase(
      "rotation_without_next_keys",
      () => rotate({ pre: root.sad.i, dig: root.sad.d, keys: [KEY_SECOND], sn: 1 }),
      "Accepted",
    ),
    explicit_zero: rejectedCase(
      "rotation_with_zero_next_threshold",
      () => rotate({ pre: root.sad.i, dig: root.sad.d, keys: [KEY_SECOND], sn: 1, nsith: 0 }),
      "Accepted",
    ),
    note: "rotate defaults the next threshold to at least one and rejects an explicit zero, so no rotation it builds can ever be the last one; inception has no such restriction",
    rust_decision: "Rust allows an empty next-key commitment in a rotation, as inception already does",
  },
  rotation_ignores_the_configuration_argument: {
    fields: Object.keys(rotate({ ...clone(rotationArgs), cnfg: ["EO"] }).sad).join(","),
    note: "RotateArgs accepts cnfg and never writes it; a caller who sets configuration traits on a rotation silently gets none",
    rust_decision: "the rotation builder exposes no configuration setter",
  },
  rotation_omits_absent_identifier_and_prior: {
    missing_identifier: rotate({ dig: root.sad.d, keys: [KEY_SECOND], ndigs: [NEXT_DIGEST], sn: 1 }).raw,
    missing_prior: rotate({ pre: root.sad.i, keys: [KEY_SECOND], ndigs: [NEXT_DIGEST], sn: 1 }).raw,
    note: "both fields are optional and an absent one is simply not written, producing an event with no `i` or no `p` whose SAID commits to that shape",
    rust_decision: "both are required constructor arguments",
  },
};

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-19",
  sources: ["src/keri/core/eventing.ts", "test/core/eventing.test.ts"],
  keys: {
    transferable: KEY_TRANSFERABLE,
    non_transferable: KEY_NON_TRANSFERABLE,
    second: KEY_SECOND,
    next_digest: NEXT_DIGEST,
    multisig: KEYS_3,
    next_digests: DIGESTS_2,
    witnesses: WITNESSES_3,
  },
  cases,
  ample_table: ampleTable,
  ample_explicit: ampleExplicit,
  rejected_cases: rejected,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/keri-eventing/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("keri-eventing fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
