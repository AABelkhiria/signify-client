// Generates exact CESR-number vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { decodeBase64Url } from "../../reference/signify-ts/dist/keri/core/base64.js";
import {
  Matter,
  NumDex,
} from "../../reference/signify-ts/dist/keri/core/matter.js";
import { CesrNumber } from "../../reference/signify-ts/dist/keri/core/number.js";

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function numberCase(name, inputKind, input, construct) {
  const number = construct();
  return {
    name,
    input_kind: inputKind,
    input,
    value_hex: number.numh,
    positive: number.positive,
    code: number.code,
    raw_hex: hex(number.raw),
    qb64: number.qb64,
    qb2_hex: hex(decodeBase64Url(number.qb64)),
  };
}

function materialCase(name, valueHex, code, rawHex) {
  const raw = Uint8Array.from(Buffer.from(rawHex, "hex"));
  const material = new Matter({ raw, code });
  return {
    name,
    value_hex: valueHex,
    code: material.code,
    raw_hex: hex(material.raw),
    qb64: material.qb64,
    qb2_hex: hex(decodeBase64Url(material.qb64)),
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

const one = new CesrNumber({}, 1);
const cases = [
  numberCase("default_zero", "default", "", () => new CesrNumber({})),
  numberCase("hex_zero", "hex", "0", () => new CesrNumber({}, "0")),
  numberCase("number_zero", "number", "0", () => new CesrNumber({}, 0)),
  numberCase("number_one", "number", "1", () => new CesrNumber({}, 1)),
  numberCase("number_fifteen", "number", "15", () => new CesrNumber({}, 15)),
  numberCase("hex_f", "hex", "f", () => new CesrNumber({}, "f")),
  numberCase("hex_15", "hex", "15", () => new CesrNumber({}, "15")),
  numberCase("short_max", "number", "65535", () => new CesrNumber({}, 65535)),
  numberCase("long_min", "number", "65536", () => new CesrNumber({}, 65536)),
  numberCase("long_max", "number", "4294967295", () =>
    new CesrNumber({}, 4294967295),
  ),
  numberCase("big_min", "number", "4294967296", () =>
    new CesrNumber({}, 4294967296),
  ),
  numberCase("javascript_safe_max", "number", "9007199254740991", () =>
    new CesrNumber({}, Number.MAX_SAFE_INTEGER),
  ),
  numberCase("huge_power_65", "number_expression", "2 ** 65", () =>
    new CesrNumber({}, 2 ** 65),
  ),
];

const exactMaterialCases = [
  materialCase("short_zero", "0", NumDex.Short, "0000"),
  materialCase("short_max", "ffff", NumDex.Short, "ffff"),
  materialCase("long_min", "10000", NumDex.Long, "00010000"),
  materialCase("long_max", "ffffffff", NumDex.Long, "ffffffff"),
  materialCase("big_min", "100000000", NumDex.Big, "0000000100000000"),
  materialCase("big_max", "ffffffffffffffff", NumDex.Big, "ffffffffffffffff"),
  materialCase(
    "huge_min",
    "10000000000000000",
    NumDex.Huge,
    "00000000000000010000000000000000",
  ),
  materialCase(
    "huge_max",
    "ffffffffffffffffffffffffffffffff",
    NumDex.Huge,
    "ffffffffffffffffffffffffffffffff",
  ),
];

const negative = new CesrNumber({}, -1);
const fractional = new CesrNumber({}, 1.5);
const partialHex = new CesrNumber({}, "fzz");
const prefixedHex = new CesrNumber({}, "0x10");
const roundedBigBoundary = new CesrNumber({}, 2 ** 64);
const roundedHugeThreshold = new CesrNumber({}, 2 ** 128);

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-04",
  sources: [
    "src/keri/core/number.ts",
    "src/keri/core/matter.ts",
    "src/keri/core/utils.ts",
    "test/core/number.test.ts",
  ],
  binary_derivation:
    "qb2_hex is decodeBase64Url(reference-produced qb64); CesrNumber encoded-input construction rejects before Matter parsing",
  cases,
  exact_material_cases: exactMaterialCases,
  reference_quirks: {
    negative_number: {
      input: "-1",
      value_hex: negative.numh,
      code: negative.code,
      qb64: negative.qb64,
      rust_error_category: "Unrepresentable",
    },
    fractional_number: {
      input: "1.5",
      value_hex: fractional.numh,
      code: fractional.code,
      qb64: fractional.qb64,
      rust_error_category: "Unrepresentable",
    },
    partial_hex: {
      input: "fzz",
      value_hex: partialHex.numh,
      qb64: partialHex.qb64,
      rust_error_category: "InvalidHexCharacter",
    },
    prefixed_hex: {
      input: "0x10",
      value_hex: prefixedHex.numh,
      qb64: prefixedHex.qb64,
      rust_error_category: "InvalidHexCharacter",
    },
    rounded_big_boundary: {
      input_expression: "2 ** 64",
      exact_value_hex: "10000000000000000",
      decoded_value_hex: roundedBigBoundary.numh,
      code: roundedBigBoundary.code,
      raw_hex: hex(roundedBigBoundary.raw),
      qb64: roundedBigBoundary.qb64,
      rust_code: NumDex.Huge,
    },
    rounded_huge_threshold: {
      input_expression: "2 ** 128",
      decoded_value_hex: roundedHugeThreshold.numh,
      code: roundedHugeThreshold.code,
      raw_hex: hex(roundedHugeThreshold.raw),
      qb64: roundedHugeThreshold.qb64,
      rust_error_category: "InputTooLarge",
    },
  },
  rejected_cases: [
    errorCase(
      "invalid_hex",
      () => new CesrNumber({}, "zz"),
      "InvalidHexCharacter",
    ),
    errorCase(
      "positive_infinity",
      () => new CesrNumber({}, Number.POSITIVE_INFINITY),
      "Unrepresentable",
    ),
    errorCase(
      "qb64_constructor",
      () => new CesrNumber({ qb64: one.qb64 }),
      "ReferenceUnsupported",
    ),
    errorCase(
      "qb64_bytes_constructor",
      () => new CesrNumber({ qb64b: one.qb64b }),
      "ReferenceUnsupported",
    ),
    errorCase(
      "qb2_constructor",
      () => new CesrNumber({ qb2: decodeBase64Url(one.qb64) }),
      "ReferenceUnsupported",
    ),
    errorCase(
      "raw_constructor",
      () => new CesrNumber({ raw: one.raw, code: one.code }),
      "ReferenceUnsupported",
    ),
  ],
};

const outputUrl = new URL(
  "../../fixtures/cesr-number/v1.json",
  import.meta.url,
);
mkdirSync(fileURLToPath(new URL(".", outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
