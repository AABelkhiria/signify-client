// Generates and checks CESR attachment vectors from the compiled pinned signify-ts checkout.
import { readFileSync, writeFileSync } from "node:fs";

import { b, d } from "../../reference/signify-ts/dist/keri/core/core.js";
import { MtrDex, NonTransDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { incept, interact, messagize } from "../../reference/signify-ts/dist/keri/core/eventing.js";
import {
  serializeACDCAttachment,
  serializeIssExnAttachment,
} from "../../reference/signify-ts/dist/keri/core/utils.js";
import { Diger } from "../../reference/signify-ts/dist/keri/core/diger.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

// The two seeds the pinned `test/core/eventing.test.ts` uses.
const SEED_0 = new Uint8Array([
  159, 123, 168, 167, 168, 67, 57, 150, 38, 250, 177, 153, 235, 170, 32, 196, 27, 71, 17, 196, 174, 83, 65, 82, 201,
  189, 4, 157, 133, 41, 126, 147,
]);
const SEED_1 = new Uint8Array([
  131, 66, 126, 4, 148, 227, 206, 85, 81, 121, 17, 102, 12, 147, 93, 30, 191, 172, 81, 181, 214, 89, 94, 162, 69, 250,
  1, 53, 152, 89, 221, 232,
]);

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

const signer = new Signer({ raw: SEED_0 });
const nextDigest = new Diger({}, new Signer({ raw: SEED_1 }).verfer.qb64b).qb64;

// The exact inception event the pinned unit test signs, and its signature.
const icp = incept({
  keys: [signer.verfer.qb64],
  ndigs: [nextDigest],
  code: MtrDex.Blake3_256,
  intive: true,
});
const siger = signer.sign(b(icp.raw), 0);
const secondSiger = new Signer({ raw: SEED_1 }).sign(b(icp.raw), 1);

// An interaction at a non-zero sequence number, so a seal can reference a real position.
const ixn = interact({
  pre: icp.sad.i,
  dig: icp.sad.d,
  sn: 1,
  data: [],
  version: undefined,
  kind: undefined,
});

function messageCase(name, serder, sigers, seal, pipelined) {
  const bytes = messagize(serder, sigers, seal, undefined, undefined, pipelined);
  const text = d(bytes);
  const event = serder.raw;
  return {
    name,
    event,
    attachments: text.slice(event.length),
    signature_count: sigers.length,
    seal_kind: seal ? seal[0] : null,
    pipelined: Boolean(pipelined),
    raw: text,
    raw_hex: hex(bytes),
    raw_byte_size: bytes.length,
  };
}

const cases = [
  // The two the pinned `test/core/eventing.test.ts` asserts verbatim.
  messageCase("pinned_controller_signature", icp, [siger], undefined, false),
  messageCase(
    "pinned_seal_event",
    icp,
    [siger],
    ["SealEvent", { i: icp.sad.i, s: icp.sad.s, d: icp.sad.d }],
    false,
  ),
  messageCase("pipelined", icp, [siger], undefined, true),
  messageCase("two_signatures", icp, [siger, secondSiger], undefined, false),
  messageCase("seal_last", icp, [siger], ["SealLast", { i: icp.sad.i }], false),
  messageCase(
    "seal_event_at_sequence_one",
    ixn,
    [siger],
    ["SealEvent", { i: ixn.sad.i, s: ixn.sad.s, d: ixn.sad.d }],
    false,
  ),
  messageCase(
    "seal_event_pipelined",
    icp,
    [siger],
    ["SealEvent", { i: icp.sad.i, s: icp.sad.s, d: icp.sad.d }],
    true,
  ),
];

// The two standalone seal-source serializers, which anchor a credential or an exchange to the
// event that authorised it.
const sealSources = {
  triple: {
    identifier: ixn.sad.i,
    sequence_number: ixn.sad.s,
    said: ixn.sad.d,
    framing: "plain",
    raw: d(serializeACDCAttachment(ixn)),
    raw_hex: hex(serializeACDCAttachment(ixn)),
    reference_function: "serializeACDCAttachment",
  },
  couple: {
    sequence_number: ixn.sad.s,
    said: ixn.sad.d,
    framing: "pipelined",
    raw: d(serializeIssExnAttachment(ixn)),
    raw_hex: hex(serializeIssExnAttachment(ixn)),
    reference_function: "serializeIssExnAttachment",
  },
};

const rejected = [
  rejectedCase("no_signatures", () => messagize(icp), "MissingSignatures"),
];

// Reference defects that Rust deliberately does not reproduce.
const cigar = signer.sign(b(icp.raw));
const nonTransferableCigar = new Signer({ raw: SEED_0, transferable: false }).sign(b(icp.raw));

const quirks = {
  receipt_paths_are_unreachable: {
    non_transferable_codex_keys: Object.keys(NonTransDex),
    non_transferable_codex_values: Object.values(NonTransDex),
    code_is_a_value_not_a_key: "B" in NonTransDex,
    witness_with_non_transferable_key: rejectedCase(
      "witness_signature_with_non_transferable_key",
      () => messagize(icp, undefined, undefined, [nonTransferableCigar]),
      "Blocked",
    ),
    receipt_with_non_transferable_key: rejectedCase(
      "receipt_couple_with_non_transferable_key",
      () => messagize(icp, undefined, undefined, undefined, [nonTransferableCigar]),
      "Blocked",
    ),
    receipt_with_transferable_key: rejectedCase(
      "receipt_couple_with_transferable_key",
      () => messagize(icp, undefined, undefined, undefined, [cigar]),
      "Blocked",
    ),
    note: "both guards read `!(verfer.code in NonTransDex)`, and `in` tests an object's property keys -- Ed25519N, ECDSA_256k1N, ... -- not its values B, 1AAA, ..., so the guard is true for every code; any signature carrying a verifier is rejected as transferable whether it is or not, and a Signer always attaches one",
    second_defect:
      "both paths also write CtrDex.ControllerIdxSigs rather than the witness or receipt-couple counter, so anything that did get through would be misparsed by a peer as controller signatures",
    rust_decision:
      "recorded BLOCKED rather than implemented: with no reachable reference behavior there is nothing to verify a Rust encoding against",
  },
  seal_sequence_numbers_are_parsed_as_decimal: (() => {
    const at_ten = messagize(icp, [siger], ["SealEvent", { i: icp.sad.i, s: "a", d: icp.sad.d }]);
    const at_sixteen = messagize(icp, [siger], ["SealEvent", { i: icp.sad.i, s: "10", d: icp.sad.d }]);
    const at_zero = messagize(icp, [siger], ["SealEvent", { i: icp.sad.i, s: "0", d: icp.sad.d }]);
    return {
      sequence_a_attachments: d(at_ten).slice(icp.raw.length),
      sequence_10_attachments: d(at_sixteen).slice(icp.raw.length),
      sequence_0_attachments: d(at_zero).slice(icp.raw.length),
      hex_a_equals_zero: d(at_ten) === d(at_zero),
      note: "the sequence number is read with parseInt, which is decimal: hex 'a' becomes NaN and is encoded as zero, and hex '10' -- sixteen -- is encoded as ten, so a seal silently references the wrong event",
      rust_decision: "the seal takes a typed SequenceNumber, so no text parsing happens at all",
    };
  })(),
  an_unknown_seal_tag_is_ignored: {
    attachments: d(messagize(icp, [siger], ["SealBogus", { i: icp.sad.i }])).slice(icp.raw.length),
    note: "the seal tag is compared against two literals and anything else falls through silently, so a misspelled tag produces a message with no seal rather than an error",
    rust_decision: "the seal is an enum, so an unknown variant cannot be expressed",
  },
};

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-19",
  sources: ["src/keri/core/eventing.ts", "src/keri/core/utils.ts", "test/core/eventing.test.ts"],
  signatures: {
    controller: siger.qb64,
    second: secondSiger.qb64,
  },
  cases,
  seal_sources: sealSources,
  rejected_cases: rejected,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/keri-attachment/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("keri-attachment fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
