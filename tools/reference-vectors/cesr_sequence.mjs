// Generates fixed-width sequence vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { decodeBase64Url } from "../../reference/signify-ts/dist/keri/core/base64.js";
import {
  MtrDex,
  NumDex,
} from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Seqner } from "../../reference/signify-ts/dist/keri/core/seqner.js";

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function sequenceCase(name, inputKind, input, construct) {
  const sequence = construct();
  const reparsed = new Seqner({ qb64: sequence.qb64 });
  return {
    name,
    input_kind: inputKind,
    input,
    value_hex: sequence.snh,
    code: sequence.code,
    raw_hex: hex(sequence.raw),
    qb64: sequence.qb64,
    qb64_bytes_hex: hex(sequence.qb64b),
    qb2_hex: hex(decodeBase64Url(sequence.qb64)),
    qb64_round_trip: reparsed.qb64,
  };
}

function exactRawCase(name, valueHex, rawHex) {
  const raw = Uint8Array.from(Buffer.from(rawHex, "hex"));
  const sequence = new Seqner({ raw, code: MtrDex.Salt_128 });
  return {
    name,
    value_hex: valueHex,
    code: sequence.code,
    raw_hex: hex(sequence.raw),
    observed_reference_snh: sequence.snh,
    qb64: sequence.qb64,
    qb2_hex: hex(decodeBase64Url(sequence.qb64)),
  };
}

function errorCase(name, operation, rustErrorCategory) {
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

function quirkCase(inputKind, input, construct, rustErrorCategory) {
  const sequence = construct();
  return {
    input_kind: inputKind,
    input,
    observed_snh: sequence.snh,
    raw_hex: hex(sequence.raw),
    qb64: sequence.qb64,
    rust_error_category: rustErrorCategory,
  };
}

const zero = new Seqner({});
const excessRaw = Uint8Array.from([
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255,
]);
const truncated = new Seqner({ raw: excessRaw, code: MtrDex.Salt_128 });

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-04",
  sources: [
    "src/keri/core/seqner.ts",
    "src/keri/core/matter.ts",
    "src/keri/core/utils.ts",
    "test/core/seqner.test.ts",
  ],
  binary_derivation:
    "qb2_hex is decodeBase64Url(reference-produced qb64) because Matter._bexfil is unimplemented; qb64_round_trip is accepted by the pinned Seqner constructor",
  cases: [
    sequenceCase("default_zero", "default", "", () => new Seqner({})),
    sequenceCase("number_one", "number", "1", () => new Seqner({ sn: 1 })),
    sequenceCase(
      "number_fifteen",
      "number",
      "15",
      () => new Seqner({ sn: 15 }),
    ),
    sequenceCase(
      "number_sixteen",
      "number",
      "16",
      () => new Seqner({ sn: 16 }),
    ),
    sequenceCase("hex_f", "hex", "f", () => new Seqner({ snh: "f" })),
    sequenceCase(
      "safe_integer_max",
      "number",
      "9007199254740991",
      () => new Seqner({ sn: Number.MAX_SAFE_INTEGER }),
    ),
  ],
  exact_raw_cases: [
    exactRawCase("raw_zero", "0", "00000000000000000000000000000000"),
    exactRawCase(
      "raw_above_javascript_safe_range",
      "20000000000001",
      "00000000000000000020000000000001",
    ),
    exactRawCase(
      "raw_u128_max",
      "ffffffffffffffffffffffffffffffff",
      "ffffffffffffffffffffffffffffffff",
    ),
  ],
  reference_quirks: {
    negative_number: quirkCase(
      "number",
      "-1",
      () => new Seqner({ sn: -1 }),
      "Unrepresentable",
    ),
    fractional_number: quirkCase(
      "number",
      "1.5",
      () => new Seqner({ sn: 1.5 }),
      "Unrepresentable",
    ),
    partial_hex: quirkCase(
      "hex",
      "fzz",
      () => new Seqner({ snh: "fzz" }),
      "InvalidHexCharacter",
    ),
    prefixed_hex: quirkCase(
      "hex",
      "0x10",
      () => new Seqner({ snh: "0x10" }),
      "InvalidHexCharacter",
    ),
    positive_infinity: quirkCase(
      "number",
      "Infinity",
      () => new Seqner({ sn: Number.POSITIVE_INFINITY }),
      "Unrepresentable",
    ),
    excess_raw_truncation: {
      input_raw_hex: hex(excessRaw),
      retained_raw_hex: hex(truncated.raw),
      qb64: truncated.qb64,
      rust_error_category: "TrailingMaterial",
    },
  },
  rejected_cases: [
    errorCase(
      "wrong_code",
      () => new Seqner({ raw: new Uint8Array(2), code: NumDex.Short }),
      "InvalidSequenceCode",
    ),
    errorCase(
      "short_raw",
      () => new Seqner({ raw: new Uint8Array(15), code: MtrDex.Salt_128 }),
      "Truncated",
    ),
    errorCase(
      "empty_raw",
      () => new Seqner({ raw: new Uint8Array(0), code: MtrDex.Salt_128 }),
      "Truncated",
    ),
    errorCase(
      "qb2_constructor",
      () => new Seqner({ qb2: decodeBase64Url(zero.qb64) }),
      "ReferenceUnsupported",
    ),
  ],
};

const outputUrl = new URL(
  "../../fixtures/cesr-sequence/v1.json",
  import.meta.url,
);
mkdirSync(fileURLToPath(new URL(".", outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
