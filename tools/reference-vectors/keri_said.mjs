// Generates and checks self-addressing-identifier vectors from the compiled pinned signify-ts
// checkout.
import { readFileSync, writeFileSync } from "node:fs";

import { b } from "../../reference/signify-ts/dist/keri/core/core.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Saider } from "../../reference/signify-ts/dist/keri/core/saider.js";
import { dumps } from "../../reference/signify-ts/dist/keri/core/serder.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
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

// Records the full derivation of one SAD: the placeholder-bearing intermediate that is actually
// hashed, the resulting identifier, and the completed data.
function saidCase(name, sad, label = "d") {
  const input = JSON.parse(JSON.stringify(sad));
  const [saider, completed] = Saider.saidify({ ...sad }, MtrDex.Blake3_256, "JSON", label);
  // `derive` returns the same placeholder-bearing data `_derive` hashed, so re-serializing it
  // reproduces the exact preimage.
  const [, dummied] = saider.derive({ ...input }, MtrDex.Blake3_256, undefined, label);
  const preimage = dumps(dummied, "JSON");
  return {
    name,
    label,
    input_sad_json: JSON.stringify(input),
    placeholder: dummied[label],
    placeholder_width: dummied[label].length,
    preimage,
    preimage_hex: hex(b(preimage)),
    preimage_byte_size: b(preimage).length,
    said: saider.qb64,
    said_code: saider.code,
    completed_sad_json: JSON.stringify(completed),
    completed_version_string: completed.v ?? null,
  };
}

// 1. The exact `rep` message from the pinned unit test.
const repMessage = {
  v: "KERI10JSON000000_",
  t: "rep",
  d: "",
  dt: "2020-08-22T17:50:12.988921+00:00",
  r: "logs/processor",
  a: {
    d: "EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg",
    i: "EB0_D51cTh_q6uOQ-byFiv5oNXZ-cxdqCqBAa4JmBLtb",
    name: "John Jones",
    role: "Founder",
  },
};

// 2. A version-less block, the shape ACDC nests inside a credential.
const versionLess = {
  d: "",
  i: "EB0_D51cTh_q6uOQ-byFiv5oNXZ-cxdqCqBAa4JmBLtb",
  name: "John Jones",
};

// 3. A non-default identifier label.
const customLabel = { id: "", name: "John Jones", role: "Founder" };

const cases = [
  saidCase("pinned_rep_message", repMessage),
  saidCase("version_less_block", versionLess),
  saidCase("custom_label", customLabel, "id"),
];

// 4. Verification behavior against the completed message.
const [repSaider, repCompleted] = Saider.saidify({ ...repMessage });
const verification = {
  completed_default: repSaider.verify({ ...repCompleted }),
  completed_prefixed: repSaider.verify({ ...repCompleted }, true),
  completed_prefixed_versioned: repSaider.verify({ ...repCompleted }, true, true),
  tampered_content_default: repSaider.verify({ ...repCompleted, r: "logs/tampered" }),
  restamped_version_prefixed_versioned: repSaider.verify(
    { ...repCompleted, v: "KERI10JSON000000_" },
    true,
    true,
  ),
};

// 5. Reference rejections.
const rejected = [
  rejectedCase(
    "saidify_missing_label",
    () => Saider.saidify({ v: "KERI10JSON000000_", t: "rep" }),
    "MissingLabelField",
  ),
  rejectedCase(
    "unsupported_digest_code",
    () => Saider.saidify({ ...repMessage }, MtrDex.SHA3_256),
    "UnrepresentableInRust",
  ),
];

// 6. Reference quirks that Rust deliberately does not reproduce.
const [, appendedSad] = repSaider.derive(
  { v: "KERI10JSON000000_", t: "rep" },
  MtrDex.Blake3_256,
  undefined,
  "d",
);
const quirks = {
  default_verify_ignores_the_identifier_field: {
    empty_identifier_accepted: repSaider.verify({ ...repMessage }),
    unrelated_identifier_accepted: repSaider.verify({
      ...repMessage,
      d: "EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg",
    }),
    unrelated_identifier_rejected_when_prefixed: repSaider.verify(
      { ...repMessage, d: "EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg" },
      true,
    ),
    note: "derivation replaces the identifier field with a placeholder before hashing, so the field's actual content is never checked unless the caller passes prefixed=true; a caller who writes verify(sad) has not verified what the message claims about itself",
    rust_decision:
      "SaidVerification::strict is the default and requires the identifier field to match; the reference behavior is available only as the explicitly named digest_only policy",
    rust_error_category: "LabelFieldMismatch",
  },
  derive_appends_a_missing_label: {
    input_sad_json: JSON.stringify({ v: "KERI10JSON000000_", t: "rep" }),
    reference_result_json: JSON.stringify(appendedSad),
    note: "the public derive() inserts the absent label at the end of the field order and sizes the version string around it, silently changing the bytes being committed to; only saidify() checks first",
    rust_error_category: "MissingLabelField",
  },
  constructor_super_called_twice: rejectedCase(
    "constructor_with_existing_identifier",
    () => new Saider({}, { ...repCompleted }),
    "UnreachableInRust",
  ),
};
quirks.constructor_super_called_twice.note =
  "when the identifier field is already populated and no code is passed, the constructor calls super() twice, so the natural 'parse a received message and check its SAID' path throws; callers must construct from qb64 and call verify() instead";

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-18",
  sources: ["src/keri/core/saider.ts", "test/core/saider.test.ts"],
  dummy_character: "#",
  default_label: "d",
  cases,
  verification,
  rejected_cases: rejected,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/keri-said/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("keri-said fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
